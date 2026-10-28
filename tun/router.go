package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/flowhash"
	"github.com/eukhlg/netio/packetbuf"
)

var (
	ErrInvalidPacket = errors.New("tun: invalid IPv4 packet")
	ErrNoRoute       = errors.New("tun: no route to PPP client")
)

type SendIPv4 = server.PacketWriter

// Router bridges IPv4 packets between PPP sessions and one TUN device. A
// client's route is learned from its validated first packet and may be removed
// explicitly when the session ends.
type Router struct {
	device      Device
	mu          sync.RWMutex
	writeMu     sync.Mutex
	routes      map[netip.Addr]SendIPv4
	ownedRoutes map[netip.Addr]func(*packetbuf.Buffer) error
	bindings    map[netip.Addr]uint64
	// published records the binding generation whose route is in routes, so
	// flush writes the route map only when a session's route actually changes.
	published   map[netip.Addr]uint64
	nextBinding uint64
	// shards, when set, replace writeMu and device.Write on the batch flush
	// path; helpers carries their work to the helper goroutines.
	shards  []*writeShard
	helpers chan *shardGroup
	offload bool
}

// writeShard is one parallel TUN write path. mu serialises its writer, whose
// coalescing state is not safe for concurrent use.
type writeShard struct {
	mu     sync.Mutex
	writer Writer
}

func NewRouter(device Device) (*Router, error) {
	if device == nil {
		return nil, errors.New("tun: device is required")
	}
	d, _ := device.(interface{ OffloadEnabled() bool })
	return &Router{device: device, offload: d != nil && d.OffloadEnabled(), routes: make(map[netip.Addr]SendIPv4), ownedRoutes: make(map[netip.Addr]func(*packetbuf.Buffer) error), bindings: make(map[netip.Addr]uint64), published: make(map[netip.Addr]uint64)}, nil
}

// SetWriteShards splits batch flushes into n flow-sharded TUN writers that
// write in parallel, each with its own descriptor and coalescing state. A flow
// always maps to one shard, so per-flow order and GRO coalescing survive.
// Call before routing traffic. It reports the shard count in effect: 1 when n
// <= 1 or the device has no parallel writers. Writers close with the device;
// the n-1 helper goroutines, idle when there is no traffic, live as long as
// the process, like the router.
func (r *Router) SetWriteShards(n int) (int, error) {
	if r.shards != nil {
		return 0, errors.New("tun: write shards already set")
	}
	source, ok := r.device.(WriterSource)
	if n <= 1 || !ok {
		return 1, nil
	}
	shards := make([]*writeShard, n)
	for i := range shards {
		writer, err := source.NewWriter()
		if err != nil {
			return 0, err
		}
		shards[i] = &writeShard{writer: writer}
	}
	r.shards, r.helpers = shards, make(chan *shardGroup, n)
	for i := 0; i < n-1; i++ {
		go func() {
			for g := range r.helpers {
				g.run()
				g.batch.helping.Done()
			}
		}()
	}
	return n, nil
}

// WriteShards reports the number of TUN write paths used by batch flushes.
func (r *Router) WriteShards() int { return max(len(r.shards), 1) }

func (r *Router) Bind(address netip.Addr, send SendIPv4) {
	r.mu.Lock()
	r.nextBinding++
	r.bindings[address] = r.nextBinding
	r.routes[address] = send
	r.published[address] = r.nextBinding
	delete(r.ownedRoutes, address)
	r.mu.Unlock()
}

// BindOwned installs a writer consuming its buffer on every outcome. Device
// I/O and routing remain unchanged; only return-packet storage is transferred.
// Ownership contract of the download path: Run hands each packet to send and
// never touches it again; send either releases it or passes it to a transport,
// whose sender goroutine releases it exactly once after the write (see
// udptransport.Datagram). Packets of one flow must reach one sender in order.
func (r *Router) BindOwned(address netip.Addr, send func(*packetbuf.Buffer) error) {
	r.mu.Lock()
	r.nextBinding++
	r.bindings[address] = r.nextBinding
	r.ownedRoutes[address] = send
	r.mu.Unlock()
}

// WithBindingGuard checks session identity at enqueue and delivery. Existing
// transport guards are composed with the new guard, in registration order.
// The guard must execute f synchronously and must not retain it.
func WithBindingGuard(ctx context.Context, guard func(func()) bool) context.Context {
	if previous, ok := ctx.Value(bindingGuardKey{}).(func(func()) bool); ok && previous != nil {
		next := guard
		guard = func(f func()) bool {
			accepted := false
			previous(func() { accepted = next(f) })
			return accepted
		}
	}
	return context.WithValue(ctx, bindingGuardKey{}, guard)
}

type bindingGuardKey struct{}
type bindingGuardSlotKey struct{}

// bindingGuardSlot carries the current packet's guard through a context created
// once per delivery goroutine, so per-packet dispatch allocates no context.
type bindingGuardSlot struct{ guard func(func()) bool }

// WithBindingGuardSlot returns a context whose guard is set per packet with
// SetBindingGuard. A guard set there takes precedence over WithBindingGuard.
func WithBindingGuardSlot(ctx context.Context) context.Context {
	return context.WithValue(ctx, bindingGuardSlotKey{}, &bindingGuardSlot{})
}

// SetBindingGuard sets (or, with nil, clears) the current packet's guard in a
// context from WithBindingGuardSlot. It reports false if ctx has no slot.
func SetBindingGuard(ctx context.Context, guard func(func()) bool) bool {
	slot, ok := ctx.Value(bindingGuardSlotKey{}).(*bindingGuardSlot)
	if ok {
		slot.guard = guard
	}
	return ok
}

func bindingGuard(ctx context.Context) func(func()) bool {
	if slot, ok := ctx.Value(bindingGuardSlotKey{}).(*bindingGuardSlot); ok && slot.guard != nil {
		return slot.guard
	}
	guard, _ := ctx.Value(bindingGuardKey{}).(func(func()) bool)
	return guard
}

// noop is the guarded operation for eligibility-only checks; a package-level
// func value, so checking a guard allocates nothing.
func noop() {}

// RouteIPv4 implements server.IPv4Router.
func (r *Router) RouteIPv4(ctx context.Context, frame server.DataFrame, send server.PacketWriter) error {
	p, ok, err := r.prepare(ctx, frame, send)
	if err != nil || !ok {
		return err
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	packets, accepted := [1]routePacket{p}, [1]bool{p.guard == nil || p.guard(noop)}
	r.admit(packets[:], accepted[:])
	if !accepted[0] {
		return nil
	}
	_, err = r.device.Write([][]byte{frame.IPv4}, 0)
	return err
}

// Run reads return traffic from TUN and dispatches it to the PPP session whose
// negotiated client address matches the IPv4 destination.
func (r *Router) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	defer func() { cancel(); <-stopped }()
	go func() { defer close(stopped); <-ctx.Done(); _ = r.device.Close() }()
	size := r.device.BatchSize()
	if size < 1 || size > 256 {
		return errors.New("tun: invalid device batch size")
	}
	slots := make([]packetbuf.ReceiveSlot, size)
	bufs := make([][]byte, size)
	sizes := make([]int, size)
	defer func() {
		for i := range slots {
			if slots[i].Buffer != nil {
				slots[i].Buffer.Release()
			}
		}
	}()
	const offset = 16
	for {
		for i := range slots {
			if slots[i].Buffer == nil {
				p, err := packetbuf.Acquire(packetbuf.MaxPacket)
				if err != nil {
					return err
				}
				if _, err = p.Prepend(offset); err != nil {
					p.Release()
					return err
				}
				slots[i].Buffer = p
			}
		}
		count, readErr := packetbuf.Receive(slots, func(loans []packetbuf.ReceiveSlot) (int, error) {
			for i := range loans {
				bufs[i] = loans[i].Payload
				sizes[i] = 0
			}
			n, err := r.device.Read(bufs, sizes, offset)
			if n >= 0 && n <= len(loans) {
				for i := 0; i < n; i++ {
					loans[i].N = sizes[i] + offset
				}
			}
			return n, err
		})
		clear(bufs)
		for i := 0; i < count; i++ {
			p := slots[i].Buffer
			// Receive validates the loan, but a hostile device can return an invalid size.
			if sizes[i] <= 0 || sizes[i] > packetbuf.MaxPacket {
				return ErrInvalidPacket
			}
			if err := p.TrimFront(offset); err != nil {
				return err
			}
			slots[i].Buffer = nil // dispatch consumes ownership on every outcome
			if err := r.dispatchOwned(p); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if errors.Is(err, ErrInvalidPacket) || errors.Is(err, ErrNoRoute) {
					continue
				}
				return err
			}
		}
		if readErr != nil {
			if ctx.Err() != nil || errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func (r *Router) dispatchOwned(packet *packetbuf.Buffer) error {
	_, destination, err := packetAddresses(packet.Bytes())
	if err != nil {
		packet.Release()
		return err
	}
	r.mu.RLock()
	send := r.ownedRoutes[destination]
	r.mu.RUnlock()
	if send != nil {
		return send(packet)
	}
	// Legacy writers may retain the independently owned slice.
	defer packet.Release()
	return r.dispatch(append([]byte(nil), packet.Bytes()...))
}

func (r *Router) dispatch(packet []byte) error {
	_, destination, err := packetAddresses(packet)
	if err != nil {
		return err
	}
	r.mu.RLock()
	send := r.routes[destination]
	r.mu.RUnlock()
	if send == nil {
		return ErrNoRoute
	}
	return send(packet)
}

func (r *Router) Forget(address netip.Addr) {
	r.mu.Lock()
	delete(r.routes, address)
	delete(r.ownedRoutes, address)
	delete(r.bindings, address)
	delete(r.published, address)
	r.mu.Unlock()
}

func packetAddresses(packet []byte) (netip.Addr, netip.Addr, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, ErrInvalidPacket
	}
	headerLength := int(packet[0]&15) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || totalLength < headerLength || totalLength != len(packet) {
		return netip.Addr{}, netip.Addr{}, ErrInvalidPacket
	}
	return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), nil
}

// prepare checks session eligibility and captures the address binding
// generation. Publication is deferred to flush for owned packets, so a queued
// packet cannot resurrect a forgotten route or overwrite a newer client's
// binding. No closures are created: the packet carries plain values.
func (r *Router) prepare(ctx context.Context, frame server.DataFrame, send server.PacketWriter) (routePacket, bool, error) {
	source, _, err := packetAddresses(frame.IPv4)
	if err != nil {
		return routePacket{}, false, err
	}
	if ctx.Err() != nil {
		return routePacket{}, false, nil
	}
	guard := bindingGuard(ctx)
	if guard != nil && !guard(noop) {
		return routePacket{}, false, nil
	}
	r.mu.RLock()
	generation, exists := r.bindings[source]
	r.mu.RUnlock()
	if !exists {
		r.mu.Lock()
		if generation, exists = r.bindings[source]; !exists {
			r.nextBinding++
			generation = r.nextBinding
			r.bindings[source] = generation
		}
		r.mu.Unlock()
	}
	return routePacket{ctx: ctx, source: source, generation: generation, send: send, guard: guard}, true, nil
}

// admit decides, under one router lock, which packets may still be delivered:
// their binding generation must be current. It publishes a route only when the
// generation's route is not yet in place. accepted holds guard results on entry.
func (r *Router) admit(packets []routePacket, accepted []bool) {
	var lastCtx context.Context
	lastCancelled := false
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range packets {
		if !accepted[i] {
			continue
		}
		p := &packets[i]
		if p.ctx != lastCtx {
			lastCtx, lastCancelled = p.ctx, p.ctx.Err() != nil
		}
		if lastCancelled || r.bindings[p.source] != p.generation {
			accepted[i] = false
			continue
		}
		if r.published[p.source] != p.generation {
			r.routes[p.source] = p.send
			r.published[p.source] = p.generation
		}
	}
}

type routeBatchKey struct{}
type routeBatch struct {
	router *Router
	writeRun
	pending  []routePacket
	accepted []bool
	// groups holds one entry per write shard; helping counts groups handed
	// to helper goroutines during a sharded flush.
	groups  []shardGroup
	helping sync.WaitGroup
}

// writeRun accumulates packets with equal offset into device writes.
type writeRun struct {
	bufs   [][]byte
	spans  []span
	offset int
}

// shardGroup holds one flush's packets for one write shard, as pending indices.
type shardGroup struct {
	batch *routeBatch
	shard *writeShard
	writeRun
	packets []int
	err     error
}

type routePacket struct {
	packet     []byte
	offset     int
	ctx        context.Context
	source     netip.Addr
	generation uint64
	send       server.PacketWriter
	guard      func(func()) bool
}

// span identifies a packet's storage by address so growth can be found after
// GRO swaps bufs entries.
type span struct {
	data *byte
	n    int
}

// NewRouteBatch allocates independent state for one delivery batch.
// The producer stops using it before transferring it to the flush consumer.
// No references may outlive flush; the driver owns and releases all storage.
func (r *Router) NewRouteBatch(ctx context.Context) (context.Context, func() error) {
	batch := &routeBatch{router: r, writeRun: writeRun{bufs: make([][]byte, 0, 128)}}
	return context.WithValue(ctx, routeBatchKey{}, batch), batch.flush
}
func (b *routeBatch) flush() error {
	if b.router.shards != nil {
		return b.flushSharded()
	}
	// Serialise delivery, then recheck each packet at admission to this write.
	// Guards protect only short checks, never blocking device I/O.
	b.router.writeMu.Lock()
	defer b.router.writeMu.Unlock()
	defer b.reset()
	b.check()
	for i := range b.pending {
		if !b.accepted[i] {
			continue
		}
		p := &b.pending[i]
		if err := b.add(b.router.device, p.packet, p.offset); err != nil {
			return err
		}
	}
	return b.write(b.router.device)
}

// check evaluates guards, which may take transport locks, before admission
// takes the router lock.
func (b *routeBatch) check() {
	b.accepted = b.accepted[:0]
	for i := range b.pending {
		g := b.pending[i].guard
		b.accepted = append(b.accepted, g == nil || g(noop))
	}
	b.router.admit(b.pending, b.accepted)
}

func (b *routeBatch) reset() {
	clear(b.pending)
	b.pending = b.pending[:0]
	b.accepted = b.accepted[:0]
}

// flushSharded writes each shard's packets under that shard's lock only, so
// flushes of different flows, and the shards of one flush, write in parallel.
// The flushing goroutine writes one group and helpers the others; it waits
// for all, so no reference outlives flush.
func (b *routeBatch) flushSharded() error {
	defer b.reset()
	b.check()
	shards := b.router.shards
	if b.groups == nil {
		b.groups = make([]shardGroup, len(shards))
		for i := range b.groups {
			b.groups[i].batch, b.groups[i].shard = b, shards[i]
		}
	}
	for i := range b.pending {
		if b.accepted[i] {
			p := &b.pending[i]
			g := &b.groups[flowhash.Shard(flowhash.IPv4(p.packet[p.offset:]), len(shards))]
			g.packets = append(g.packets, i)
		}
	}
	var own *shardGroup
	for i := range b.groups {
		g := &b.groups[i]
		if len(g.packets) == 0 {
			continue
		}
		if own == nil {
			own = g
			continue
		}
		b.helping.Add(1)
		select {
		case b.router.helpers <- g:
		default: // all helpers busy: write it here
			g.run()
			b.helping.Done()
		}
	}
	if own != nil {
		own.run()
	}
	b.helping.Wait()
	var err error
	for i := range b.groups {
		g := &b.groups[i]
		if err == nil {
			err = g.err
		}
		g.err = nil
		g.packets = g.packets[:0]
	}
	return err
}

func (g *shardGroup) run() {
	g.shard.mu.Lock()
	defer g.shard.mu.Unlock()
	writer := g.shard.writer
	for _, i := range g.packets {
		p := &g.batch.pending[i]
		if g.err = g.add(writer, p.packet, p.offset); g.err != nil {
			return
		}
	}
	g.err = g.write(writer)
}

// add appends a packet, first writing the run if the offset changes or the
// run is full.
func (w *writeRun) add(writer Writer, packet []byte, offset int) error {
	if len(w.bufs) > 0 && (w.offset != offset || len(w.bufs) == 128) {
		if err := w.write(writer); err != nil {
			return err
		}
	}
	w.offset = offset
	w.bufs = append(w.bufs, packet)
	return nil
}

// write runs only in the flush stage, holding the lock of writer (writeMu or
// a shard's). GRO may reorder and extend packets, so scrub all original spans
// before their owners release them.
func (w *writeRun) write(writer Writer) error {
	if len(w.bufs) == 0 {
		return nil
	}
	w.spans = w.spans[:0]
	for _, p := range w.bufs {
		w.spans = append(w.spans, span{unsafe.SliceData(p), len(p)})
	}
	_, err := writer.Write(w.bufs, w.offset)
	scrubGrowth(w.bufs, w.spans)
	clear(w.spans)
	clear(w.bufs)
	w.bufs = w.bufs[:0]
	return err
}

// RouteIPv4Owned retains only slice references until the driver flushes. It
// borrows frame.Buffer in place: it prepends up to 16 bytes of the buffer's
// headroom for the TUN virtio header and, with offload, lends GRO the
// buffer's tailroom (scrubbed after the write).
func (r *Router) RouteIPv4Owned(ctx context.Context, frame server.DataFrame, send server.PacketWriter) error {
	buffer := frame.Buffer
	if buffer == nil || buffer.Len() != len(frame.IPv4) {
		return ErrInvalidPacket
	}
	p, ok, err := r.prepare(ctx, frame, send)
	if err != nil || !ok {
		return err
	}
	// All packets reserve the same TUN headroom, so batches rarely split.
	headroom := min(buffer.Headroom(), 16)
	if _, err := buffer.Prepend(headroom); err != nil {
		return err
	}
	if r.offload {
		p.packet = buffer.BytesWithTailroom()
	} else {
		p.packet = buffer.Bytes()
	}
	p.offset = headroom
	batch, _ := ctx.Value(routeBatchKey{}).(*routeBatch)
	if batch == nil || batch.router != r {
		batch = &routeBatch{router: r}
		batch.pending = append(batch.pending, p)
		return batch.flush()
	}
	batch.pending = append(batch.pending, p)
	return nil
}

func (r *Router) OffloadEnabled() bool { return r.offload }

// scrubGrowth zeroes bytes a write-offload backend appended beyond each
// packet's original end. Owners record only the original packet as written, so
// this restores their invariant that unrecorded storage is zero, without
// marking whole slots dirty. Entries are matched by storage address because GRO
// swaps entries when it prepends. Growth that reallocated has a new address and
// left the owner's storage untouched. Runs after every Write, including errors.
func scrubGrowth(bufs [][]byte, spans []span) {
	for i, p := range bufs {
		data := unsafe.SliceData(p)
		n := -1
		if i < len(spans) && spans[i].data == data {
			n = spans[i].n
		} else {
			for _, s := range spans {
				if s.data == data {
					n = s.n
					break
				}
			}
		}
		if n >= 0 && len(p) > n {
			clear(p[n:])
		}
	}
}
