//go:build !linux

package openvpn

type batchSys struct{}

func (b *readBatch) recv(fd int) (int, error) { return b.recvEach(fd) }
