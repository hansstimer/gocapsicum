gocapsicum
==========
Go package that wraps FreeBSD [Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/). Of no value on any other OS.

Usage
---
Nearly identical use to os/exec.Cmd, but you set Cmd.Capability to true so the the target executable will run in Capabilities mode.

FDs should be set to the desired capabilites with gocapsicum.Cap_new, and then added to Cmd.ExtraFiles.

Warning
---
Most of this code is from Go 1.1.1, but it has been heavily mutilated so that only the needed portions can be placed in a few files. This means that it isn't easy to track against any bug fixes in the original files.