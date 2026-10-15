//go:build linux && amd64

package ssu2

// Linux does not expose sendmmsg through package syscall. This is the x86-64
// syscall number from arch/x86/entry/syscalls/syscall_64.tbl.
const sysSendmmsg = 307
