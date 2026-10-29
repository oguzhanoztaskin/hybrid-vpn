package openvpn

import (
	"io"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
)

// batchSize is how many packets one read takes from the core's socket.
const batchSize = 32

// readBatch reads several packets from the core per wake-up: one recvmmsg on
// Linux, otherwise reads until the socket is empty. Each slot is a netstack
// view, so a packet handed to netstack needs no copy (its slot then gets a
// fresh view).
type readBatch struct {
	size  int
	views []*buffer.View
	sizes []int
	sys   batchSys
}

func newReadBatch(size int) *readBatch {
	b := &readBatch{size: size, views: make([]*buffer.View, batchSize), sizes: make([]int, batchSize)}
	for i := range b.views {
		b.views[i] = buffer.NewViewSize(size)
	}
	return b
}

// take gives slot i's view away and puts a fresh one in its place.
func (b *readBatch) take(i int) *buffer.View {
	v := b.views[i]
	b.views[i] = buffer.NewViewSize(b.size)
	return v
}

func (b *readBatch) release() {
	for _, v := range b.views {
		v.Release()
	}
}

// read waits for at least one packet and returns how many slots it filled.
func (b *readBatch) read(rc syscall.RawConn) (int, error) {
	var n int
	var rerr error
	err := rc.Read(func(fd uintptr) bool {
		n, rerr = b.recv(int(fd))
		return rerr != unix.EAGAIN
	})
	if err != nil {
		return 0, err
	}
	return n, rerr
}

// recvEach reads one packet per read call until the socket is empty.
func (b *readBatch) recvEach(fd int) (int, error) {
	for i := range b.views {
		n, err := unix.Read(fd, b.views[i].AsSlice())
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if i > 0 && err == unix.EAGAIN {
				return i, nil
			}
			return i, err
		}
		if n == 0 {
			return i, io.EOF
		}
		b.sizes[i] = n
	}
	return len(b.views), nil
}
