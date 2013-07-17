package gocapsicum

// +build freebsd

import (
	"syscall"
	"unsafe"
)

const (
	CAP_ACCEPT         = 0x200000000
	CAP_ACL_CHECK      = 0x20000000
	CAP_ACL_DELETE     = 0x40000000
	CAP_ACL_GET        = 0x80000000
	CAP_ACL_SET        = 0x100000000
	CAP_BIND           = 0x400000000
	CAP_CONNECT        = 0x800000000
	CAP_CREATE         = 0x80000
	CAP_DELETE         = 0x100000
	CAP_EXTATTR_DELETE = 0x2000000
	CAP_EXTATTR_GET    = 0x4000000
	CAP_EXTATTR_LIST   = 0x8000000
	CAP_EXTATTR_SET    = 0x10000000
	CAP_FCHDIR         = 0x200
	CAP_FCHFLAGS       = 0x100
	CAP_FCHMOD         = 0x400
	CAP_FCHOWN         = 0x800
	CAP_FCNTL          = 0x1000
	CAP_FEXECVE        = 0x10
	CAP_FLOCK          = 0x4000
	CAP_FPATHCONF      = 0x2000
	CAP_FSCK           = 0x8000
	CAP_FSTAT          = 0x10000
	CAP_FSTATFS        = 0x20000
	CAP_FSYNC          = 0x20
	CAP_FTRUNCATE      = 0x40
	CAP_FUTIMES        = 0x40000
	CAP_GETPEERNAME    = 0x1000000000
	CAP_GETSOCKNAME    = 0x2000000000
	CAP_GETSOCKOPT     = 0x4000000000
	CAP_IOCTL          = 0x4000000000000
	CAP_LISTEN         = 0x8000000000
	CAP_LOOKUP         = 0x1000000
	CAP_MAC_GET        = 0x80000000000
	CAP_MAC_SET        = 0x100000000000
	CAP_MAPEXEC        = 0x8
	CAP_MASK_VALID     = 0x7fffffffffffff
	CAP_MKDIR          = 0x200000
	CAP_MKFIFO         = 0x800000
	CAP_MMAP           = 0x4
	CAP_PDGETPID       = 0x10000000000000
	CAP_PDKILL         = 0x40000000000000
	CAP_PDWAIT         = 0x20000000000000
	CAP_PEELOFF        = 0x10000000000
	CAP_POLL_EVENT     = 0x1000000000000
	CAP_POST_EVENT     = 0x2000000000000
	CAP_READ           = 0x1
	CAP_RMDIR          = 0x400000
	CAP_SEEK           = 0x80
	CAP_SEM_GETVALUE   = 0x200000000000
	CAP_SEM_POST       = 0x400000000000
	CAP_SEM_WAIT       = 0x800000000000
	CAP_SETSOCKOPT     = 0x20000000000
	CAP_SHUTDOWN       = 0x40000000000
	CAP_TTYHOOK        = 0x8000000000000
	CAP_WRITE          = 0x2
)

type CapRights uint64

func Cap_new(fd int, rights uint64) (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_CAP_NEW, uintptr(fd), uintptr(rights), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func Cap_rights_get(fd int, rightsp *CapRights) (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_CAP_GETRIGHTS, uintptr(fd), uintptr(unsafe.Pointer(rightsp)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func Cap_enter() (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_CAP_ENTER, 0, 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func Cap_getmode(modep *uint) (err error) {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_CAP_GETMODE, uintptr(unsafe.Pointer(modep)), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

func readlen(fd int, buf *byte, nbuf int) (n int, err error) {
	r0, _, e1 := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(buf)), uintptr(nbuf))
	n = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}
