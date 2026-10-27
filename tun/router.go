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
}

func NewRouter(device Device) (*Router, error) {
	if device == nil {
		return nil, errors.New("tun: device is required")
	}
	return &Router{device: device, routes: make(map[netip.Addr]SendIPv4), ownedRoutes: make(map[netip.Addr]func(*packetbuf.Buffer) error)}, nil
}

func (r *Router) Bind(address netip.Addr, send SendIPv4) {
	r.mu.Lock()
	r.routes[address] = send
	delete(r.ownedRoutes, address)
	r.mu.Unlock()
}

// BindOwned installs a writer consuming its buffer on every outcome. Device
// I/O and routing remain unchanged; only return-packet storage is transferred.
func (r *Router) BindOwned(address netip.Addr, send func(*packetbuf.Buffer) error) {
	r.mu.Lock()
	r.ownedRoutes[address] = send
	r.mu.Unlock()
}

// WithBindingGuard checks a protected session at the instant a route is learned.
// The guard must execute f synchronously and must not retain it.
func WithBindingGuard(ctx context.Context, guard func(func()) bool) context.Context {
	return context.WithValue(ctx, bindingGuardKey{}, guard)
}

type bindingGuardKey struct{}

// RouteIPv4 implements server.IPv4Router.
func (r *Router) RouteIPv4(ctx context.Context, frame server.DataFrame, send server.PacketWriter) error {
	accepted, err := r.learn(ctx, frame, send)
	if err != nil || !accepted {
		return err
	}

	r.writeMu.Lock()
	_, err = r.device.Write([][]byte{frame.IPv4}, 0)
	r.writeMu.Unlock()
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

func (r *Router) learn(ctx context.Context, frame server.DataFrame, send server.PacketWriter) (bool, error) {
	source, _, err := packetAddresses(frame.IPv4)
	if err != nil {
		return false, err
	}
	bind := func() { r.mu.Lock(); r.routes[source] = send; r.mu.Unlock() }
	if guard, ok := ctx.Value(bindingGuardKey{}).(func(func()) bool); ok {
		if !guard(bind) {
			return false, nil
		}
	} else {
		bind()
	}
	return true, nil
}

type routeBatchKey struct{}
type routeBatch struct {
	router *Router
	bufs   [][]byte
	spans  []span
	offset int
}

// span identifies a packet's storage by address so growth can be found after
// GRO swaps bufs entries.
type span struct {
	data *byte
	n    int
}

// NewRouteBatch allocates independent state for one synchronous delivery driver.
// No references may outlive flush; the driver owns and releases all storage.
func (r *Router) NewRouteBatch(ctx context.Context) (context.Context, func() error) {
	batch := &routeBatch{router: r, bufs: make([][]byte, 0, 128)}
	return context.WithValue(ctx, routeBatchKey{}, batch), batch.flush
}
func (b *routeBatch) flush() error {
	if len(b.bufs) == 0 {
		return nil
	}
	b.spans = b.spans[:0]
	for _, p := range b.bufs {
		b.spans = append(b.spans, span{unsafe.SliceData(p), len(p)})
	}
	b.router.writeMu.Lock()
	_, err := b.router.device.Write(b.bufs, b.offset)
	b.router.writeMu.Unlock()
	scrubGrowth(b.bufs, b.spans)
	clear(b.spans)
	clear(b.bufs)
	b.bufs = b.bufs[:0]
	return err
}

// RouteIPv4Owned retains only slice references until the driver flushes.
func (r *Router) RouteIPv4Owned(ctx context.Context, frame server.DataFrame, storage []byte, offset int, send server.PacketWriter) error {
	accepted, err := r.learn(ctx, frame, send)
	if err != nil || !accepted {
		return err
	}
	if offset < 0 || offset > len(storage) || len(frame.IPv4) > len(storage)-offset {
		return ErrInvalidPacket
	}
	// Rebase the slice so all packets have the same headroom despite different
	// ESP/L2TP header lengths. Spare tail capacity remains available to GRO.
	headroom := min(offset, 16)
	packet := storage[offset-headroom : offset+len(frame.IPv4)]
	batch, _ := ctx.Value(routeBatchKey{}).(*routeBatch)
	if batch == nil || batch.router != r {
		bufs, spans := [][]byte{packet}, []span{{unsafe.SliceData(packet), len(packet)}}
		r.writeMu.Lock()
		_, err = r.device.Write(bufs, headroom)
		r.writeMu.Unlock()
		scrubGrowth(bufs, spans)
		return err
	}
	if len(batch.bufs) > 0 && (batch.offset != headroom || len(batch.bufs) == cap(batch.bufs)) {
		if err := batch.flush(); err != nil {
			return err
		}
	}
	batch.offset = headroom
	batch.bufs = append(batch.bufs, packet)
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
