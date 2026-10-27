package tun

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

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

func TestOwnedUploadBatchReferencesAndDriverIsolation(t *testing.T) {
	d := newMemoryDevice()
	r, _ := NewRouter(d)
	ctx, flush := r.NewRouteBatch(context.Background())
	other, flushOther := r.NewRouteBatch(context.Background())
	p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	a, b := make([]byte, 16+len(p)), make([]byte, 24+len(p))
	copy(a[16:], p)
	copy(b[24:], p)
	for i, s := range [][]byte{a, b} {
		off := 16 + i*8
		if err := r.RouteIPv4Owned(ctx, server.DataFrame{IPv4: s[off:]}, s, off, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.written) != 0 {
		t.Fatal("wrote before flush")
	}
	if err := flushOther(); err != nil {
		t.Fatal(err)
	}
	if len(d.written) != 0 {
		t.Fatal("driver state shared")
	}
	_ = other
	// The batch keeps references: changing the original bytes changes the write.
	a[16+8] = 42
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	if len(d.written) != 2 || d.written[0][8] != 42 {
		t.Fatal("packet copied or batch lost")
	}
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	if len(d.written) != 2 {
		t.Fatal("idle flush repeated packets")
	}
}

type directReadDevice struct {
	*memoryDevice
	packet []byte
	view   []byte
}

func (d *directReadDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.packet == nil {
		return d.memoryDevice.Read(bufs, sizes, offset)
	}
	sizes[0] = copy(bufs[0][offset:], d.packet)
	d.view = bufs[0][offset : offset+sizes[0]]
	d.packet = nil
	return 1, nil
}
func TestRouterRunTransfersTheReadBuffer(t *testing.T) {
	p := ipv4Packet([4]byte{8, 8, 8, 8}, [4]byte{10, 0, 0, 2})
	d := &directReadDevice{memoryDevice: newMemoryDevice(), packet: p}
	r, _ := NewRouter(d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	r.BindOwned(netip.MustParseAddr("10.0.0.2"), func(b *packetbuf.Buffer) error {
		called = true
		if &b.Bytes()[0] != &d.view[0] || b.Headroom() != packetbuf.Headroom {
			t.Error("read packet copied or headroom changed")
		}
		b.Release()
		cancel()
		return nil
	})
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("packet not dispatched")
	}
}

// growDevice mimics GRO: it grows the first entry into spare capacity by the
// second entry's packet, then swaps the two entries like the prepend path.
type growDevice struct{ *memoryDevice }

func (d *growDevice) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) >= 2 {
		bufs[0] = append(bufs[0], bufs[1][offset:]...)
		bufs[0], bufs[1] = bufs[1], bufs[0]
	}
	return len(bufs), nil
}

func TestOwnedBatchScrubsOffloadGrowthWithoutDirtyingSlots(t *testing.T) {
	d := &growDevice{newMemoryDevice()}
	r, _ := NewRouter(d)
	ctx, flush := r.NewRouteBatch(context.Background())
	p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	var buffers []*packetbuf.Buffer
	var full [][]byte
	for i := 0; i < 2; i++ {
		b, err := packetbuf.Acquire(32 + len(p))
		if err != nil {
			t.Fatal(err)
		}
		storage := b.BytesWithTailroom()
		copy(storage[32:], p)
		full = append(full, storage[:cap(storage)])
		buffers = append(buffers, b)
		if err := r.RouteIPv4Owned(ctx, server.DataFrame{IPv4: storage[32:]}, storage, 32, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	for i, f := range full {
		for j := 32 + len(p); j < len(f); j++ {
			if f[j] != 0 {
				t.Fatalf("buffer %d byte %d not zero after flush", i, j)
			}
		}
	}
	for _, b := range buffers {
		b.Release()
	}
}

func TestOwnedBatchRejectsClosedReboundForgottenOrCancelledPackets(t *testing.T) {
	for _, change := range []string{"close", "rebind", "owned-rebind", "forget", "cancel"} {
		t.Run(change, func(t *testing.T) {
			d := newMemoryDevice()
			r, _ := NewRouter(d)
			address := netip.MustParseAddr("10.0.0.2")
			var mu sync.Mutex
			active := true
			checks := 0
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, flush := r.NewRouteBatch(WithBindingGuard(parent, func(f func()) bool {
				mu.Lock()
				defer mu.Unlock()
				checks++
				if !active {
					return false
				}
				f()
				return true
			}))
			p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
			storage := make([]byte, 16+len(p))
			copy(storage[16:], p)
			staleCalled, replacementCalled := false, false
			if err := r.RouteIPv4Owned(ctx, server.DataFrame{IPv4: storage[16:]}, storage, 16, func([]byte) error { staleCalled = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if checks == 0 {
				t.Fatal("no eligibility check before enqueue")
			}
			if len(r.routes) != 0 {
				t.Fatal("route published before delivery")
			}
			switch change {
			case "close":
				mu.Lock()
				active = false
				mu.Unlock()
			case "rebind":
				r.Bind(address, func([]byte) error { replacementCalled = true; return nil })
			case "owned-rebind":
				r.BindOwned(address, func(b *packetbuf.Buffer) error { replacementCalled = true; b.Release(); return nil })
			case "forget":
				r.Forget(address)
			case "cancel":
				cancel()
			}
			if err := flush(); err != nil {
				t.Fatal(err)
			}
			if len(d.written) != 0 {
				t.Fatal("stale packet written")
			}
			if change == "rebind" {
				if err := r.routes[address](p); err != nil {
					t.Fatal(err)
				}
				if !replacementCalled {
					t.Fatal("replacement route overwritten")
				}
			}
			if change == "owned-rebind" {
				b, _ := packetbuf.Copy(p)
				if err := r.ownedRoutes[address](b); err != nil {
					t.Fatal(err)
				}
				if !replacementCalled {
					t.Fatal("owned replacement overwritten")
				}
			}
			if change != "rebind" && len(r.routes) != 0 {
				t.Fatal("stale packet learned a route")
			}
			if staleCalled {
				t.Fatal("stale route invoked")
			}
			if err := flush(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type blockedWriteDevice struct {
	*memoryDevice
	entered   chan struct{}
	release   chan struct{}
	onceWrite sync.Once
}

func (d *blockedWriteDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.onceWrite.Do(func() { close(d.entered); <-d.release })
	return d.memoryDevice.Write(bufs, offset)
}

func TestSessionCloseDuringBlockedFlushDoesNotBlockProcessingOrReviveRoute(t *testing.T) {
	for _, rebind := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "rebind"}[rebind], func(t *testing.T) {
			d := &blockedWriteDevice{memoryDevice: newMemoryDevice(), entered: make(chan struct{}), release: make(chan struct{})}
			r, _ := NewRouter(d)
			address := netip.MustParseAddr("10.0.0.2")
			var mu sync.Mutex
			active := true
			base := WithBindingGuard(context.Background(), func(f func()) bool {
				mu.Lock()
				defer mu.Unlock()
				if !active {
					return false
				}
				f()
				return true
			})
			queue := func() func() error {
				ctx, flush := r.NewRouteBatch(base)
				p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
				storage := make([]byte, 16+len(p))
				copy(storage[16:], p)
				if err := r.RouteIPv4Owned(ctx, server.DataFrame{IPv4: storage[16:]}, storage, 16, func([]byte) error { t.Error("stale route"); return nil }); err != nil {
					t.Error(err)
				}
				return flush
			}
			first := queue()
			doneFirst := make(chan error, 1)
			go func() { doneFirst <- first() }()
			<-d.entered
			// Processing another batch must progress while the device write is blocked.
			processed := make(chan func() error, 1)
			go func() { processed <- queue() }()
			var second func() error
			select {
			case second = <-processed:
			case <-time.After(time.Second):
				close(d.release)
				t.Fatal("processing waited on TUN write")
			}
			mu.Lock()
			active = false
			mu.Unlock()
			r.Forget(address)
			replacement := false
			if rebind {
				r.Bind(address, func([]byte) error { replacement = true; return nil })
			}
			doneSecond := make(chan error, 1)
			go func() { doneSecond <- second() }()
			close(d.release)
			if err := <-doneFirst; err != nil {
				t.Fatal(err)
			}
			if err := <-doneSecond; err != nil {
				t.Fatal(err)
			}
			if len(d.written) != 1 {
				t.Fatalf("queued stale packet written: %d", len(d.written))
			}
			if rebind {
				_ = r.routes[address](nil)
				if !replacement {
					t.Fatal("new binding overwritten")
				}
			} else if len(r.routes) != 0 {
				t.Fatal("closed route revived")
			}
		})
	}
}

func TestBindingGuardsComposeAndRejectBeforeQueue(t *testing.T) {
	d := newMemoryDevice()
	r, _ := NewRouter(d)
	for _, which := range []int{0, 1} {
		guard := func(n int) func(func()) bool {
			return func(f func()) bool {
				if n == which {
					return false
				}
				f()
				return true
			}
		}
		ctx, flush := r.NewRouteBatch(WithBindingGuard(WithBindingGuard(context.Background(), guard(0)), guard(1)))
		p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
		if err := r.RouteIPv4Owned(ctx, server.DataFrame{IPv4: p}, p, 0, nil); err != nil {
			t.Fatal(err)
		}
		if err := flush(); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.routes) != 0 || len(r.bindings) != 0 || len(d.written) != 0 {
		t.Fatal("rejected guard published state")
	}
}

// Steady-state owned routing must not allocate per packet, and flush must
// publish a session's route once per binding generation.
// countingDevice records writes without copying packets.
type countingDevice struct {
	*memoryDevice
	writes int
}

func (d *countingDevice) Write(bufs [][]byte, _ int) (int, error) {
	d.writes += len(bufs)
	return len(bufs), nil
}

func TestOwnedRoutingSteadyStateAllocatesNothing(t *testing.T) {
	d := &countingDevice{memoryDevice: newMemoryDevice()}
	r, _ := NewRouter(d)
	r.Bind(netip.MustParseAddr("10.0.0.2"), func([]byte) error { return nil })
	ctx, flush := r.NewRouteBatch(context.Background())
	p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, 8})
	storage := make([]byte, 16+len(p))
	copy(storage[16:], p)
	send := server.PacketWriter(func([]byte) error { return nil })
	frame := server.DataFrame{IPv4: storage[16:]}
	route := func() {
		if err := r.RouteIPv4Owned(ctx, frame, storage, 16, send); err != nil {
			t.Fatal(err)
		}
		if err := flush(); err != nil {
			t.Fatal(err)
		}
	}
	route()
	if allocs := testing.AllocsPerRun(100, route); allocs > 0.01 {
		t.Fatalf("owned route and flush allocate %v per packet", allocs)
	}
	if d.writes != 102 {
		t.Fatalf("writes=%d", d.writes)
	}
}

func TestBindingGuardSlot(t *testing.T) {
	ctx := WithBindingGuardSlot(context.Background())
	calls := 0
	guard := func(f func()) bool { calls++; f(); return true }
	if !SetBindingGuard(ctx, guard) || bindingGuard(ctx) == nil {
		t.Fatal("slot guard not set")
	}
	if allocs := testing.AllocsPerRun(100, func() { SetBindingGuard(ctx, guard) }); allocs != 0 {
		t.Fatalf("SetBindingGuard allocates %v", allocs)
	}
	SetBindingGuard(ctx, nil)
	if bindingGuard(ctx) != nil {
		t.Fatal("cleared slot still guards")
	}
	if SetBindingGuard(context.Background(), guard) {
		t.Fatal("set without slot reported success")
	}
}
