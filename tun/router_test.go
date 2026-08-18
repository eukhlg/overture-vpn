package tun

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/eukhlg/l2tp-go/server"
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
func (d *memoryDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), p...))
	return len(p), nil
}
func (d *memoryDevice) Read(p []byte) (int, error) {
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
