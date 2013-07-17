// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build freebsd

package gocapsicum

import (
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// ProcAttr holds the attributes that will be applied to a new process
// started by StartProcess.
type ProcAttr struct {
	// If Dir is non-empty, the child changes into the directory before
	// creating the process.
	Dir string
	// If Env is non-nil, it gives the environment variables for the
	// new process in the form returned by Environ.
	// If it is nil, the result of Environ will be used.
	Env []string
	// Files specifies the open files inherited by the new process.  The
	// first three entries correspond to standard input, standard output, and
	// standard error.  An implementation may support additional entries,
	// depending on the underlying operating system.  A nil entry corresponds
	// to that file being closed when the process starts.
	Files []*os.File
	files []uintptr // File descriptors.

	Chroot     string              // Chroot.
	Credential *syscall.Credential // Credential.
	Ptrace     bool                // Enable tracing.
	Setsid     bool                // Create session.
	Setpgid    bool                // Set process group ID to new pid (SYSV setpgrp)
	Setctty    bool                // Set controlling terminal to fd 0
	Noctty     bool                // Detach fd 0 from controlling terminal
	Capability bool
}

type Process struct {
	Pid        int
	isdone     uint32              // process has been successfully waited on, non zero if true
	Chroot     string              // Chroot.
	Credential *syscall.Credential // Credential.
	Ptrace     bool                // Enable tracing.
	Setsid     bool                // Create session.
	Setpgid    bool                // Set process group ID to new pid (SYSV setpgrp)
	Setctty    bool                // Set controlling terminal to fd 0
	Noctty     bool                // Detach fd 0 from controlling terminal
}

func newProcess(pid int) *Process {
	p := &Process{Pid: pid}
	runtime.SetFinalizer(p, (*Process).Release)
	return p
}

func (p *Process) Release() error {
	// NOOP for unix.
	p.Pid = -1
	// no need for a finalizer anymore
	runtime.SetFinalizer(p, nil)
	return nil
}

func (p *Process) Wait() (ps *ProcessState, err error) {
	if p.Pid == -1 {
		return nil, syscall.EINVAL
	}
	var status syscall.WaitStatus
	var rusage syscall.Rusage
	pid1, e := syscall.Wait4(p.Pid, &status, 0, &rusage)
	if e != nil {
		return nil, os.NewSyscallError("wait", e)
	}
	if pid1 != 0 {
		p.setDone()
	}
	ps = &ProcessState{
		pid:    pid1,
		status: status,
		rusage: &rusage,
	}
	return ps, nil
}

func (p *Process) setDone() {
	atomic.StoreUint32(&p.isdone, 1)
}

// ProcessState stores information about a process, as reported by Wait.
type ProcessState struct {
	pid    int                // The process's id.
	status syscall.WaitStatus // System-dependent status info.
	rusage *syscall.Rusage
}

// Pid returns the process id of the exited process.
func (p *ProcessState) Pid() int {
	return p.pid
}

func (p *ProcessState) Exited() bool {
	return p.status.Exited()
}

func (p *ProcessState) Success() bool {
	return p.status.ExitStatus() == 0
}

func (p *ProcessState) Sys() syscall.WaitStatus {
	return p.status
}

func (p *ProcessState) SysUsage() *syscall.Rusage {
	return p.rusage
}

// Convert i to decimal string.
func itod(i int) string {
	if i == 0 {
		return "0"
	}

	u := uint64(i)
	if i < 0 {
		u = -u
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; u > 0; u /= 10 {
		bp--
		b[bp] = byte(u%10) + '0'
	}

	if i < 0 {
		bp--
		b[bp] = '-'
	}

	return string(b[bp:])
}

func (p *ProcessState) String() string {
	if p == nil {
		return "<nil>"
	}
	status := p.Sys()
	res := ""
	switch {
	case status.Exited():
		res = "exit status " + itod(status.ExitStatus())
	case status.Signaled():
		res = "signal: " + status.Signal().String()
	case status.Stopped():
		res = "stop signal: " + status.StopSignal().String()
		if status.StopSignal() == syscall.SIGTRAP && status.TrapCause() != 0 {
			res += " (trap " + itod(status.TrapCause()) + ")"
		}
	case status.Continued():
		res = "continued"
	}
	if status.CoreDump() {
		res += " (core dumped)"
	}
	return res
}

var hasCapabilities bool

func init() {
	b1, err1 := syscall.SysctlUint32("kern.features.security_capabilities")
	b2, err2 := syscall.SysctlUint32("kern.features.security_capability_mode")
	if b1 != 0 && b2 != 0 && err1 == nil && err2 == nil {
		hasCapabilities = true
	}
}

// Fork, dup fd onto 0..len(fd), and exec(argv0, argvv, envv) in child.
// If a dup or exec fails, write the errno error to pipe.
// (Pipe is close-on-exec so if exec succeeds, it will be closed.)
// In the child, this function must not acquire any locks, because
// they might have been locked at the time of the fork.  This means
// no rescheduling, no malloc calls, and no new stack segments.
// The calls to RawSyscall are okay because they are assembly
// functions that do not grow the stack.
func forkAndExecInChild(argv0 *byte, argv, envv []*byte, chroot, dir *byte, attr *ProcAttr, pipe int) (pid int, err syscall.Errno) {
	// Declare all variables at top in case any
	// declarations require heap allocation (e.g., err1).
	var (
		r1                  uintptr
		err1                syscall.Errno
		nextfd              int
		i                   int
		fdExecutable, capFD uintptr
	)

	if !hasCapabilities && attr.Capability {
		return pid, syscall.ENOSYS
	}

	// guard against side effects of shuffling fds below.
	// Make sure that nextfd is beyond any currently open files so
	// that we can't run the risk of overwriting any of them.
	fd := make([]int, len(attr.files))
	nextfd = len(attr.files)
	for i, ufd := range attr.files {
		if nextfd < int(ufd) {
			nextfd = int(ufd)
		}
		fd[i] = int(ufd)
	}
	nextfd++

	// About to call fork.
	// No more allocation or calls of non-assembly functions.
	r1, _, err1 = syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if err1 != 0 {
		return 0, err1
	}

	if r1 != 0 {
		// parent; return PID
		return int(r1), 0
	}

	// Fork succeeded, now in child.

	// Enable tracing if requested.
	if attr.Ptrace {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Session ID
	if attr.Setsid {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETSID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Set process group
	if attr.Setpgid {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chroot
	if chroot != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHROOT, uintptr(unsafe.Pointer(chroot)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// User and groups
	if cred := attr.Credential; cred != nil {
		ngroups := uintptr(len(cred.Groups))
		groups := uintptr(0)
		if ngroups > 0 {
			groups = uintptr(unsafe.Pointer(&cred.Groups[0]))
		}
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETGROUPS, ngroups, groups, 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETGID, uintptr(cred.Gid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
		_, _, err1 = syscall.RawSyscall(syscall.SYS_SETUID, uintptr(cred.Uid), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Chdir
	if dir != nil {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CHDIR, uintptr(unsafe.Pointer(dir)), 0, 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Pass 1: look for fd[i] < i and move those up above len(fd)
	// so that pass 2 won't stomp on an fd it needs later.
	if pipe < nextfd {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP2, uintptr(pipe), uintptr(nextfd), 0)
		if err1 != 0 {
			goto childerror
		}
		syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
		pipe = nextfd
		nextfd++
	}
	for i = 0; i < len(fd); i++ {
		if fd[i] >= 0 && fd[i] < int(i) {
			_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP2, uintptr(fd[i]), uintptr(nextfd), 0)
			if err1 != 0 {
				goto childerror
			}
			syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(nextfd), syscall.F_SETFD, syscall.FD_CLOEXEC)
			fd[i] = nextfd
			nextfd++
			if nextfd == pipe { // don't stomp on pipe
				nextfd++
			}
		}
	}

	// Pass 2: dup fd[i] down onto i.
	for i = 0; i < len(fd); i++ {
		if fd[i] == -1 {
			syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
			continue
		}
		if fd[i] == int(i) {
			// dup2(i, i) won't clear close-on-exec flag on Linux,
			// probably not elsewhere either.
			_, _, err1 = syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd[i]), syscall.F_SETFD, 0)
			if err1 != 0 {
				goto childerror
			}
			continue
		}
		// The new fd is created NOT close-on-exec,
		// which is exactly what we want.
		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP2, uintptr(fd[i]), uintptr(i), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// By convention, we don't close-on-exec the fds we are
	// started with, so if len(fd) < 3, close 0, 1, 2 as needed.
	// Programs that know they inherit fds >= 3 will need
	// to set them close-on-exec.
	for i = len(fd); i < 3; i++ {
		syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(i), 0, 0)
	}

	// Detach fd 0 from tty
	if attr.Noctty {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCNOTTY), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Make fd 0 the tty
	if attr.Setctty {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCSCTTY), 0)
		if err1 != 0 {
			goto childerror
		}
	}

	// Time to exec.
	if attr.Capability {
		fdExecutable, _, err1 = syscall.RawSyscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(argv0)), syscall.O_RDONLY, 0)
		if err1 != 0 {
			goto childerror
		}

		capFD, _, err1 = syscall.RawSyscall(syscall.SYS_CAP_NEW, fdExecutable, uintptr(CAP_FEXECVE|CAP_READ), 0)
		if err1 != 0 {
			goto childerror
		}

		_, _, err1 = syscall.RawSyscall(syscall.SYS_DUP2, uintptr(capFD), uintptr(fdExecutable), 0)
		if err1 != 0 {
			goto childerror
		}

		syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(fdExecutable), 0, 0)

		// Enter capability mode right before exec
		_, _, err1 = syscall.RawSyscall(syscall.SYS_CAP_ENTER, 0, 0, 0)
		if err1 != 0 {
			goto childerror
		}

		_, _, err1 = syscall.RawSyscall(syscall.SYS_FEXECVE,
			capFD,
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(&envv[0])))
	} else {
		_, _, err1 = syscall.RawSyscall(syscall.SYS_EXECVE,
			uintptr(unsafe.Pointer(argv0)),
			uintptr(unsafe.Pointer(&argv[0])),
			uintptr(unsafe.Pointer(&envv[0])))
	}

childerror:
	// send error code on pipe
	syscall.RawSyscall(syscall.SYS_WRITE, uintptr(pipe), uintptr(unsafe.Pointer(&err1)), unsafe.Sizeof(err1))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT, 253, 0, 0)
	}
}

// Try to open a pipe with O_CLOEXEC set on both file descriptors.
func forkExecPipe(p []int) error {
	err := syscall.Pipe(p)
	if err != nil {
		return err
	}
	_, err = fcntl(p[0], syscall.F_SETFD, syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}
	_, err = fcntl(p[1], syscall.F_SETFD, syscall.FD_CLOEXEC)
	return err
}

func forkExec(argv0 string, argv []string, attr *ProcAttr) (pid int, err error) {
	var p [2]int
	var n int
	var err1 syscall.Errno
	var wstatus syscall.WaitStatus

	p[0] = -1
	p[1] = -1

	// Convert args to C form.
	argv0p, err := syscall.BytePtrFromString(argv0)
	if err != nil {
		return 0, err
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}
	envvp, err := syscall.SlicePtrFromStrings(attr.Env)
	if err != nil {
		return 0, err
	}

	// freebsd needs this
	if len(argv[0]) > len(argv0) {
		argvp[0] = argv0p
	}

	var chroot *byte
	if attr.Chroot != "" {
		chroot, err = syscall.BytePtrFromString(attr.Chroot)
		if err != nil {
			return 0, err
		}
	}
	var dir *byte
	if attr.Dir != "" {
		dir, err = syscall.BytePtrFromString(attr.Dir)
		if err != nil {
			return 0, err
		}
	}

	// Fill in the fds
	for _, f := range attr.Files {
		attr.files = append(attr.files, f.Fd())
	}

	// Acquire the fork lock so that no other threads
	// create new fds that are not yet close-on-exec
	// before we fork.
	syscall.ForkLock.Lock()

	// Allocate child status pipe close on exec.
	if err = forkExecPipe(p[:]); err != nil {
		goto error
	}

	// Kick off child.
	pid, err1 = forkAndExecInChild(argv0p, argvp, envvp, chroot, dir, attr, p[1])
	if err1 != 0 {
		err = syscall.Errno(err1)
		goto error
	}
	syscall.ForkLock.Unlock()

	// Read child error status from pipe.
	syscall.Close(p[1])
	n, err = readlen(p[0], (*byte)(unsafe.Pointer(&err1)), int(unsafe.Sizeof(err1)))
	syscall.Close(p[0])
	if err != nil || n != 0 {
		if n == int(unsafe.Sizeof(err1)) {
			err = syscall.Errno(err1)
		}
		if err == nil {
			err = syscall.EPIPE
		}

		// Child failed; wait for it to exit, to make sure
		// the zombies don't accumulate.
		_, err1 := syscall.Wait4(pid, &wstatus, 0, nil)
		for err1 == syscall.EINTR {
			_, err1 = syscall.Wait4(pid, &wstatus, 0, nil)
		}
		return 0, err
	}

	// Read got EOF, so pipe closed on exec, so exec succeeded.
	return pid, nil

error:
	if p[0] >= 0 {
		syscall.Close(p[0])
		syscall.Close(p[1])
	}
	syscall.ForkLock.Unlock()
	return 0, err
}

func startProcess(name string, argv []string, attr *ProcAttr) (p *Process, err error) {
	// If there is no SysProcAttr (ie. no Chroot or changed
	// UID/GID), double-check existence of the directory we want
	// to chdir into.  We can make the error clearer this way.
	if attr.Dir != "" && attr.Chroot == "" {
		if _, err := os.Stat(attr.Dir); err != nil {
			pe := err.(*os.PathError)
			pe.Op = "chdir"
			return nil, pe
		}
	}

	if attr.Env == nil {
		attr.Env = syscall.Environ()
	}

	pid, e := forkExec(name, argv, attr)
	if e != nil {
		return nil, &os.PathError{"fork/exec", name, e}
	}
	return newProcess(pid), nil
}
