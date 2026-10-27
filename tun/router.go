package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"

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
	source, _, err := packetAddresses(frame.IPv4)
	if err != nil {
		return err
	}
	bind := func() { r.mu.Lock(); r.routes[source] = send; r.mu.Unlock() }
	if guard, ok := ctx.Value(bindingGuardKey{}).(func(func()) bool); ok {
		if !guard(bind) {
			return nil
		}
	} else {
		bind()
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
	buffer := make([]byte, 65535)
	go func() { defer close(stopped); <-ctx.Done(); _ = r.device.Close() }()
	for {
		sizes := []int{0}
		nread, err := r.device.Read([][]byte{buffer}, sizes, 0)
		n := sizes[0]
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if nread == 0 {
			continue
		}
		packet, err := packetbuf.Copy(buffer[:n])
		if err != nil {
			return err
		}
		if err := r.dispatchOwned(packet); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// TUN interfaces can receive IPv6 and transient packets for which no
			// PPP route exists. Neither condition is fatal to the routing loop.
			if errors.Is(err, ErrInvalidPacket) || errors.Is(err, ErrNoRoute) {
				continue
			}
			return err
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
