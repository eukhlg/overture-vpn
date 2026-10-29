package l2tpipsec

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// Bridge tests send through ipsec-go's ESPSender (its own tests cover the
// sender); these fakes observe the sockets.

func newTestESPSender(t *testing.T, raw, natt net.PacketConn, capacity int) *ipsec.ESPSender {
	t.Helper()
	sender, err := ipsec.NewESPSender(context.Background(), raw, natt, capacity, udptransport.DefaultBatchSize, udptransport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

type batchWriteFunc func([]udptransport.Message) (int, error)

func (f batchWriteFunc) Write(m []udptransport.Message) (int, error) { return f(m) }

type senderConn struct {
	started  chan struct{}
	finished chan struct{}
	unblock  chan struct{}
	closed   chan struct{}
	once     sync.Once
	result   error
	short    bool
	mu       sync.Mutex
	writes   [][]byte
}

func newSenderConn() *senderConn {
	return &senderConn{started: make(chan struct{}, 100), finished: make(chan struct{}, 100), unblock: make(chan struct{}), closed: make(chan struct{})}
}
func (c *senderConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.started <- struct{}{}
	defer func() { c.finished <- struct{}{} }()
	select {
	case <-c.unblock:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	if c.result != nil {
		return 0, c.result
	}
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (c *senderConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *senderConn) Close() error                           { c.once.Do(func() { close(c.closed) }); return nil }
func (c *senderConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (c *senderConn) SetDeadline(time.Time) error            { return nil }
func (c *senderConn) SetReadDeadline(time.Time) error        { return nil }
func (c *senderConn) SetWriteDeadline(time.Time) error       { return nil }
func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}
func ownedDatagram(t *testing.T, peer net.Addr, value byte) (ipsec.ESPDatagram, []byte) {
	t.Helper()
	b, err := packetbuf.Copy(bytes.Repeat([]byte{value}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return ipsec.ESPDatagram{Payload: b.Bytes(), Peer: peer, Buffer: b}, b.Bytes()
}
func assertErased(t *testing.T, views ...[]byte) {
	t.Helper()
	for _, v := range views {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("owned packet not erased/released")
		}
	}
}
