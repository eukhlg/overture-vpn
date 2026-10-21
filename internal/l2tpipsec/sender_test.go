package l2tpipsec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/netio/packetbuf"
)

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

func TestSenderOwnershipShutdownAndFailedEnqueue(t *testing.T) {
	r := ipsec.NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, testESPPair(2)); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, r, peer, testESPPair(2))
	raw, natt := newSenderConn(), newSenderConn()
	sender, _ := NewESPSender(context.Background(), raw, natt, 1)
	first, a := ownedDatagram(t, peer, 1)
	second, b := ownedDatagram(t, peer, 2)
	third, c := ownedDatagram(t, peer, 3)
	if err := sender.Enqueue(association, first); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	if err := sender.Enqueue(association, second); err != nil {
		t.Fatal(err)
	}
	failed := make(chan error, 1)
	go func() { failed <- sender.Enqueue(association, third) }()
	sender.Close()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("enqueue unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("producer stuck")
	}
	assertErased(t, a, b)
	if c[0] != 3 {
		t.Fatal("failed enqueue stole caller ownership")
	}
	third.Release()
	assertErased(t, c)
}

func TestSenderWriteErrorsReleaseActiveAndBacklog(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short"}[short], func(t *testing.T) {
			r := ipsec.NewESPRegistry()
			defer r.Close()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			if err := r.Install(peer, testESPPair(2)); err != nil {
				t.Fatal(err)
			}
			association := openTestAssociation(t, r, peer, testESPPair(2))
			raw, natt := newSenderConn(), newSenderConn()
			raw.short = short
			if !short {
				raw.result = errors.New("write failed")
			}
			sender, _ := NewESPSender(context.Background(), raw, natt, 1)
			first, a := ownedDatagram(t, peer, 1)
			second, b := ownedDatagram(t, peer, 2)
			if err := sender.Enqueue(association, first); err != nil {
				t.Fatal(err)
			}
			waitSignal(t, raw.started)
			if err := sender.Enqueue(association, second); err != nil {
				t.Fatal(err)
			}
			close(raw.unblock)
			select {
			case err := <-sender.Done():
				if err == nil {
					t.Fatal("missing write error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("sender stuck")
			}
			sender.Close()
			assertErased(t, a, b)
		})
	}
}

func TestSenderFIFOAndRevocationRelease(t *testing.T) {
	r := ipsec.NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, testESPPair(2)); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, r, peer, testESPPair(2))
	raw, natt := newSenderConn(), newSenderConn()
	sender, _ := NewESPSender(context.Background(), raw, natt, 4)
	var views [][]byte
	for i := byte(1); i <= 3; i++ {
		d, v := ownedDatagram(t, peer, i)
		views = append(views, v)
		if err := sender.Enqueue(association, d); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			waitSignal(t, raw.started)
		}
	}
	close(raw.unblock)
	// A barrier packet blocks after all previous writes and releases complete.
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	sender.Close()
	assertErased(t, views...)
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if len(raw.writes) != 3 {
		t.Fatalf("writes=%d", len(raw.writes))
	}
	for i, p := range raw.writes {
		if p[0] != byte(i+1) {
			t.Fatal("packet ordering changed")
		}
	}
	// Revoked association rejection retains ownership with the producer.
	r.Remove(association.InboundSPI())
	d, v := ownedDatagram(t, peer, 9)
	if err := sender.Enqueue(association, d); err == nil {
		t.Fatal("accepted after shutdown")
	}
	if v[0] != 9 {
		t.Fatal("rejected buffer released")
	}
	d.Release()
}

func TestSenderRevokedQueuedPacket(t *testing.T) {
	r := ipsec.NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	pair := testESPPair(2)
	if err := r.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, r, peer, pair)
	replacement := pair
	replacement.Inbound.SPI++
	replacement.Outbound.SPI++
	if err := r.Install(peer, replacement); err != nil {
		t.Fatal(err)
	}
	other := openTestAssociation(t, r, peer, replacement)
	raw, natt := newSenderConn(), newSenderConn()
	sender, _ := NewESPSender(context.Background(), raw, natt, 4)
	first, a := ownedDatagram(t, peer, 1)
	revoked, b := ownedDatagram(t, peer, 2)
	barrier, c := ownedDatagram(t, peer, 3)
	if err := sender.Enqueue(other, first); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	if err := sender.Enqueue(association, revoked); err != nil {
		t.Fatal(err)
	}
	r.Remove(association.InboundSPI())
	rejected, d := ownedDatagram(t, peer, 4)
	if err := sender.Enqueue(association, rejected); !errors.Is(err, ipsec.ErrUnknownESP) {
		t.Fatal(err)
	}
	if d[0] != 4 {
		t.Fatal("rejection stole buffer")
	}
	rejected.Release()
	if err := sender.Enqueue(other, barrier); err != nil {
		t.Fatal(err)
	}
	close(raw.unblock)
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	sender.Close()
	assertErased(t, a, b, c, d)
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if len(raw.writes) != 2 || raw.writes[0][0] != 1 || raw.writes[1][0] != 3 {
		t.Fatal("revoked packet was transmitted")
	}
}

func TestSenderParentCancellationReleases(t *testing.T) {
	r := ipsec.NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	pair := testESPPair(2)
	if err := r.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, r, peer, pair)
	ctx, cancel := context.WithCancel(context.Background())
	raw, natt := newSenderConn(), newSenderConn()
	sender, _ := NewESPSender(ctx, raw, natt, 1)
	d, a := ownedDatagram(t, peer, 1)
	if err := sender.Enqueue(association, d); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	d, b := ownedDatagram(t, peer, 2)
	if err := sender.Enqueue(association, d); err != nil {
		t.Fatal(err)
	}
	cancel()
	sender.Close()
	assertErased(t, a, b)
	if err := <-sender.Done(); err != nil {
		t.Fatalf("normal cancellation: %v", err)
	}
}
