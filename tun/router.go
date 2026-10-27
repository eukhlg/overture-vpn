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
}

func NewRouter(device Device) (*Router, error) {
	if device == nil {
		return nil, errors.New("tun: device is required")
	}
	return &Router{device: device, routes: make(map[netip.Addr]SendIPv4), ownedRoutes: make(map[netip.Addr]func(*packetbuf.Buffer) error), bindings: make(map[netip.Addr]uint64), published: make(map[netip.Addr]uint64)}, nil
}

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
	router   *Router
	bufs     [][]byte
	spans    []span
	offset   int
	pending  []routePacket
	accepted []bool
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
	batch := &routeBatch{router: r, bufs: make([][]byte, 0, 128)}
	return context.WithValue(ctx, routeBatchKey{}, batch), batch.flush
}
func (b *routeBatch) flush() error {
	// Serialise delivery, then recheck each packet at admission to this write.
	// Guards protect only short checks, never blocking device I/O.
	b.router.writeMu.Lock()
	defer b.router.writeMu.Unlock()
	defer func() {
		clear(b.pending)
		b.pending = b.pending[:0]
		b.accepted = b.accepted[:0]
	}()
	// Guards may take transport locks, so evaluate them before the router lock.
	b.accepted = b.accepted[:0]
	for i := range b.pending {
		g := b.pending[i].guard
		b.accepted = append(b.accepted, g == nil || g(noop))
	}
	b.router.admit(b.pending, b.accepted)
	for i := range b.pending {
		if !b.accepted[i] {
			continue
		}
		p := &b.pending[i]
		if len(b.bufs) > 0 && (b.offset != p.offset || len(b.bufs) == 128) {
			if err := b.write(); err != nil {
				return err
			}
		}
		b.offset = p.offset
		b.bufs = append(b.bufs, p.packet)
	}
	return b.write()
}

// write runs only in the flush stage with writeMu held. GRO may reorder and
// extend packets, so scrub all original spans before their owners release them.
func (b *routeBatch) write() error {
	if len(b.bufs) == 0 {
		return nil
	}
	b.spans = b.spans[:0]
	for _, p := range b.bufs {
		b.spans = append(b.spans, span{unsafe.SliceData(p), len(p)})
	}
	_, err := b.router.device.Write(b.bufs, b.offset)
	scrubGrowth(b.bufs, b.spans)
	clear(b.spans)
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	return err
}

// RouteIPv4Owned retains only slice references until the driver flushes.
func (r *Router) RouteIPv4Owned(ctx context.Context, frame server.DataFrame, storage []byte, offset int, send server.PacketWriter) error {
	if offset < 0 || offset > len(storage) || len(frame.IPv4) > len(storage)-offset {
		return ErrInvalidPacket
	}
	p, ok, err := r.prepare(ctx, frame, send)
	if err != nil || !ok {
		return err
	}
	// Rebase without copying: all plain packets reserve the same TUN headroom.
	headroom := min(offset, 16)
	p.packet, p.offset = storage[offset-headroom:offset+len(frame.IPv4)], headroom
	batch, _ := ctx.Value(routeBatchKey{}).(*routeBatch)
	if batch == nil || batch.router != r {
		batch = &routeBatch{router: r}
		batch.pending = append(batch.pending, p)
		return batch.flush()
	}
	batch.pending = append(batch.pending, p)
	return nil
}

func (r *Router) OffloadEnabled() bool {
	d, ok := r.device.(interface{ OffloadEnabled() bool })
	return ok && d.OffloadEnabled()
}

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
