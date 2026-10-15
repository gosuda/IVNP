//go:build linux && arm64

package ssu2

// Linux does not expose sendmmsg through package syscall. This is the arm64
// syscall number from include/uapi/asm-generic/unistd.h (__NR_sendmmsg = 269).
const sysSendmmsg = 269
