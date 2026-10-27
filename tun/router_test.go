package tun

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
)

type memoryDevice struct {
	mu      sync.Mutex
	written [][]byte
	reads   chan []byte
	closed  chan struct{}
	once    sync.Once
}

func newMemoryDevice() *memoryDevice {
	return &memoryDevice{reads: make(chan []byte, 1), closed: make(chan struct{})}
}
func (d *memoryDevice) Name() string { return "test0" }
func (d *memoryDevice) Close() error { d.once.Do(func() { close(d.closed) }); return nil }
func (d *memoryDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, p := range bufs {
		if _, err := d.writePacket(p[offset:]); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}
func (d *memoryDevice) BatchSize() int    { return 1 }
func (d *memoryDevice) MTU() (int, error) { return 1400, nil }
func (d *memoryDevice) writePacket(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), p...))
	return len(p), nil
}
func (d *memoryDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.readPacket(bufs[0][offset:])
	sizes[0] = n
	if n > 0 {
		return 1, err
	}
	return 0, err
}
func (d *memoryDevice) readPacket(p []byte) (int, error) {
	select {
	case packet := <-d.reads:
		return copy(p, packet), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func TestRouterBidirectional(t *testing.T) {
	device := newMemoryDevice()
	router, err := NewRouter(device)
	if err != nil {
		t.Fatal(err)
	}
	clientPacket := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	var returned []byte
	if err := router.RouteIPv4(context.Background(), server.DataFrame{IPv4: clientPacket}, func(packet []byte) error { returned = append([]byte(nil), packet...); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(device.written) != 1 || !bytes.Equal(device.written[0], clientPacket) {
		t.Fatalf("written=%x", device.written)
	}
	returnPacket := ipv4Packet([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2})
	if err := router.dispatch(returnPacket); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(returned, returnPacket) {
		t.Fatalf("returned=%x", returned)
	}
	router.Forget(netip.MustParseAddr("10.0.0.2"))
	if err := router.dispatch(returnPacket); err != ErrNoRoute {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRouterRunStopsWithContext(t *testing.T) {
	device := newMemoryDevice()
	router, _ := NewRouter(device)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRouterBindBeforeClientTraffic(t *testing.T) {
	router, _ := NewRouter(newMemoryDevice())
	var returned []byte
	router.Bind(netip.MustParseAddr("10.0.0.2"), func(packet []byte) error { returned = append([]byte(nil), packet...); return nil })
	packet := ipv4Packet([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2})
	if err := router.dispatch(packet); err != nil || !bytes.Equal(returned, packet) {
		t.Fatalf("returned=%x err=%v", returned, err)
	}
}

func TestRouterRunDropsUnsupportedPackets(t *testing.T) {
	device := newMemoryDevice()
	router, _ := NewRouter(device)
	clientPacket := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	delivered := make(chan []byte, 1)
	if err := router.RouteIPv4(context.Background(), server.DataFrame{IPv4: clientPacket}, func(packet []byte) error {
		delivered <- append([]byte(nil), packet...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- router.Run(ctx) }()
	device.reads <- []byte{0x60, 0, 0, 0} // IPv6 must be ignored, not fatal.
	returnPacket := ipv4Packet([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2})
	device.reads <- returnPacket
	if got := <-delivered; !bytes.Equal(got, returnPacket) {
		t.Fatalf("delivered=%x", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketAddressesRejectsMalformed(t *testing.T) {
	if _, _, err := packetAddresses([]byte{0x45}); err != ErrInvalidPacket {
		t.Fatalf("unexpected error: %v", err)
	}
}

func ipv4Packet(source, destination [4]byte) []byte {
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3], packet[8] = 0x45, 0, 20, 64
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}

func TestOwnedReturnRouteTransfersStorage(t *testing.T) {
	router, _ := NewRouter(newMemoryDevice())
	address := netip.MustParseAddr("10.0.0.2")
	packet := ipv4Packet([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2})
	owned, _ := packetbuf.Copy(packet)
	view := owned.Bytes()
	called := false
	router.BindOwned(address, func(b *packetbuf.Buffer) error {
		called = true
		if &b.Bytes()[0] != &view[0] {
			t.Fatal("return packet copied")
		}
		b.Release()
		return nil
	})
	if err := router.dispatchOwned(owned); err != nil || !called {
		t.Fatalf("called=%t err=%v", called, err)
	}
	if !bytes.Equal(view, make([]byte, len(view))) {
		t.Fatal("consumer failed to release")
	}
	// Existing writers retain independent slices after the pooled buffer is freed.
	var retained []byte
	router.Bind(address, func(p []byte) error { retained = p; return nil })
	owned, _ = packetbuf.Copy(packet)
	if err := router.dispatchOwned(owned); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, packet) {
		t.Fatal("legacy writer storage was recycled")
	}
	router.Forget(address)
	owned, _ = packetbuf.Copy(packet)
	view = owned.Bytes()
	if err := router.dispatchOwned(owned); err != ErrNoRoute {
		t.Fatal(err)
	}
	if !bytes.Equal(view, make([]byte, len(view))) {
		t.Fatal("no-route packet leaked")
	}
}

func TestProtectedRouteCannotBindAfterSessionClose(t *testing.T) {
	device := newMemoryDevice()
	router, err := NewRouter(device)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithBindingGuard(context.Background(), func(func()) bool { return false })
	packet := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	if err := router.RouteIPv4(ctx, server.DataFrame{IPv4: packet}, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(router.routes) != 0 || len(device.written) != 0 {
		t.Fatal("closed protected session published a route or TUN write")
	}
}
