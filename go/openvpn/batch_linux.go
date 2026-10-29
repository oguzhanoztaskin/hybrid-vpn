package openvpn

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr is struct mmsghdr (64-bit Linux).
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

type batchSys struct {
	msgs []mmsghdr
	iovs []unix.Iovec
}

// recv takes up to batchSize packets with one recvmmsg.
func (b *readBatch) recv(fd int) (int, error) {
	if b.sys.msgs == nil {
		b.sys.msgs = make([]mmsghdr, len(b.views))
		b.sys.iovs = make([]unix.Iovec, len(b.views))
	}
	for i, v := range b.views {
		s := v.AsSlice()
		b.sys.iovs[i].Base = &s[0]
		b.sys.iovs[i].SetLen(len(s))
		b.sys.msgs[i] = mmsghdr{}
		b.sys.msgs[i].hdr.Iov = &b.sys.iovs[i]
		b.sys.msgs[i].hdr.SetIovlen(1)
	}
	for {
		n, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&b.sys.msgs[0])),
			uintptr(len(b.sys.msgs)), unix.MSG_DONTWAIT, 0, 0)
		switch errno {
		case 0:
			for i := 0; i < int(n); i++ {
				b.sizes[i] = int(b.sys.msgs[i].len)
			}
			return int(n), nil
		case unix.EINTR:
			continue
		case unix.ENOSYS:
			return b.recvEach(fd)
		}
		return 0, errno
	}
}
