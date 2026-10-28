package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/flowhash"
	"github.com/eukhlg/netio/packetbuf"
)

// shardedDevice hands out writers that record packets per writer and fail on
// concurrent use, which the router must prevent with the shard lock.
type shardedDevice struct {
	*memoryDevice
	mu      sync.Mutex
	writers []*recordingWriter
	grow    bool
	discard bool // count writes only
}

type recordingWriter struct {
	device  *shardedDevice
	id      int
	busy    atomic.Bool
	written [][]byte
	writes  int
}

func (d *shardedDevice) OffloadEnabled() bool { return d.grow }

func (d *shardedDevice) NewWriter() (Writer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := &recordingWriter{device: d, id: len(d.writers)}
	d.writers = append(d.writers, w)
	return w, nil
}

func (w *recordingWriter) Write(bufs [][]byte, offset int) (int, error) {
	if !w.busy.CompareAndSwap(false, true) {
		return 0, errors.New("concurrent writer use")
	}
	defer w.busy.Store(false)
	w.writes++
	if w.device.discard {
		return len(bufs), nil
	}
	if w.device.grow && len(bufs) >= 2 {
		bufs[0] = append(bufs[0], bufs[1][offset:]...)
		bufs[0], bufs[1] = bufs[1], bufs[0]
		return len(bufs), nil
	}
	for _, p := range bufs {
		w.written = append(w.written, append([]byte(nil), p[offset:]...))
	}
	return len(bufs), nil
}

// flowPacket is an IPv4 packet whose flow is its destination and whose
// identification field carries a sequence number.
func flowPacket(destination byte, sequence uint16) []byte {
	p := ipv4Packet([4]byte{10, 0, 0, 2}, [4]byte{8, 8, 8, destination})
	binary.BigEndian.PutUint16(p[4:6], sequence)
	return p
}

func newShardedRouter(t *testing.T, d *shardedDevice, n int) *Router {
	t.Helper()
	r, _ := NewRouter(d)
	if got, err := r.SetWriteShards(n); err != nil || got != n || r.WriteShards() != n {
		t.Fatalf("SetWriteShards(%d)=%d, %v", n, got, err)
	}
	if _, err := r.SetWriteShards(n); err == nil {
		t.Fatal("second SetWriteShards accepted")
	}
	return r
}

func routeOwned(t *testing.T, r *Router, ctx context.Context, packet []byte) {
	t.Helper()
	frame, buffer := ownedFrame(t, packet)
	t.Cleanup(buffer.Release)
	if err := r.RouteIPv4Owned(ctx, frame, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestShardedFlushKeepsEachFlowOnOneWriterInOrder(t *testing.T) {
	d := &shardedDevice{memoryDevice: newMemoryDevice()}
	r := newShardedRouter(t, d, 4)
	const flows, packets = 16, 64
	var wg sync.WaitGroup
	// Two flushing goroutines, as two NAT-T delivery workers, own disjoint flows.
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, flush := r.NewRouteBatch(context.Background())
			for seq := 0; seq < packets; seq++ {
				for flow := worker; flow < flows; flow += 2 {
					routeOwned(t, r, ctx, flowPacket(byte(flow), uint16(seq)))
				}
				if seq%8 == 7 {
					if err := flush(); err != nil {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	owner := map[byte]int{}
	next := map[byte]uint16{}
	used, total := 0, 0
	for _, w := range d.writers {
		if len(w.written) > 0 {
			used++
		}
		for _, p := range w.written {
			flow, seq := p[19], binary.BigEndian.Uint16(p[4:6])
			if id, ok := owner[flow]; ok && id != w.id {
				t.Fatalf("flow %d on writers %d and %d", flow, id, w.id)
			}
			owner[flow] = w.id
			if seq != next[flow] {
				t.Fatalf("flow %d sequence %d, want %d", flow, seq, next[flow])
			}
			next[flow]++
			total++
		}
	}
	if total != flows*packets || used < 2 {
		t.Fatalf("written=%d writers used=%d", total, used)
	}
	if len(d.written) != 0 {
		t.Fatal("sharded flush used the device write path")
	}
}

// distinctShardFlows returns two flows that map to different shards.
func distinctShardFlows(n int) (byte, byte) {
	first := flowhash.Shard(flowhash.IPv4(flowPacket(0, 0)), n)
	for flow := 1; flow < 256; flow++ {
		if flowhash.Shard(flowhash.IPv4(flowPacket(byte(flow), 0)), n) != first {
			return 0, byte(flow)
		}
	}
	panic("no flow on another shard")
}

func TestShardedFlushScrubsGrowthPerShard(t *testing.T) {
	d := &shardedDevice{memoryDevice: newMemoryDevice(), grow: true}
	r := newShardedRouter(t, d, 2)
	a, b := distinctShardFlows(2)
	ctx, flush := r.NewRouteBatch(context.Background())
	var buffers []*packetbuf.Buffer
	for _, flow := range []byte{a, b, a, b} {
		frame, buffer := ownedFrame(t, flowPacket(flow, 0))
		defer buffer.Release()
		buffers = append(buffers, buffer)
		if err := r.RouteIPv4Owned(ctx, frame, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	for _, w := range d.writers {
		if w.writes != 1 {
			t.Fatalf("writer %d writes=%d, want 1", w.id, w.writes)
		}
	}
	for i, buffer := range buffers {
		f := buffer.BytesWithTailroom()
		f = f[:cap(f)]
		for j := 36; j < len(f); j++ {
			if f[j] != 0 {
				t.Fatalf("buffer %d byte %d not zero after flush", i, j)
			}
		}
	}
}

func TestShardedFlushRejectsIneligiblePackets(t *testing.T) {
	d := &shardedDevice{memoryDevice: newMemoryDevice()}
	r := newShardedRouter(t, d, 2)
	active := true
	ctx, flush := r.NewRouteBatch(WithBindingGuard(context.Background(), func(f func()) bool {
		if !active {
			return false
		}
		f()
		return true
	}))
	a, b := distinctShardFlows(2)
	routeOwned(t, r, ctx, flowPacket(a, 0))
	routeOwned(t, r, ctx, flowPacket(b, 0))
	active = false
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	for _, w := range d.writers {
		if w.writes != 0 {
			t.Fatalf("writer %d wrote an ineligible packet", w.id)
		}
	}
	if len(r.routes) != 0 {
		t.Fatal("ineligible packet learned a route")
	}
}

func TestSetWriteShardsFallsBackToOneWritePath(t *testing.T) {
	r, _ := NewRouter(newMemoryDevice())
	if n, err := r.SetWriteShards(4); err != nil || n != 1 || r.WriteShards() != 1 {
		t.Fatalf("device without writers: %d, %v", n, err)
	}
	r, _ = NewRouter(&shardedDevice{memoryDevice: newMemoryDevice()})
	if n, err := r.SetWriteShards(1); err != nil || n != 1 || r.shards != nil {
		t.Fatalf("one shard: %d, %v", n, err)
	}
}

func TestShardedFlushSteadyStateAllocatesNothing(t *testing.T) {
	d := &shardedDevice{memoryDevice: newMemoryDevice(), discard: true}
	r := newShardedRouter(t, d, 2)
	r.Bind(netipAddr("10.0.0.2"), func([]byte) error { return nil })
	a, b := distinctShardFlows(2)
	ctx, flush := r.NewRouteBatch(context.Background())
	var frames []server.DataFrame
	for _, flow := range []byte{a, b} {
		frame, buffer := ownedFrame(t, flowPacket(flow, 0))
		defer buffer.Release()
		frames = append(frames, frame)
	}
	send := server.PacketWriter(func([]byte) error { return nil })
	route := func() {
		for i := range frames {
			if err := r.RouteIPv4Owned(ctx, frames[i], send); err != nil {
				t.Fatal(err)
			}
		}
		if err := flush(); err != nil {
			t.Fatal(err)
		}
		for i := range frames {
			_ = frames[i].Buffer.TrimFront(16)
		}
	}
	route()
	if allocs := testing.AllocsPerRun(100, route); allocs > 0.01 {
		t.Fatalf("sharded route and flush allocate %v per batch", allocs)
	}
	if d.writers[0].writes != 102 || d.writers[1].writes != 102 {
		t.Fatalf("writes=%d/%d", d.writers[0].writes, d.writers[1].writes)
	}
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
