package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"

	"l2tp-go/server"
)

var (
	ErrInvalidPacket = errors.New("tun: invalid IPv4 packet")
	ErrNoRoute       = errors.New("tun: no route to PPP client")
)

type SendIPv4 func([]byte) error

// Router bridges IPv4 packets between PPP sessions and one TUN device. A
// client's route is learned from its validated first packet and may be removed
// explicitly when the session ends.
type Router struct {
	device  Device
	mu      sync.RWMutex
	writeMu sync.Mutex
	routes  map[netip.Addr]SendIPv4
}

func NewRouter(device Device) (*Router, error) {
	if device == nil {
		return nil, errors.New("tun: device is required")
	}
	return &Router{device: device, routes: make(map[netip.Addr]SendIPv4)}, nil
}

func (r *Router) Bind(address netip.Addr, send SendIPv4) {
	r.mu.Lock()
	r.routes[address] = send
	r.mu.Unlock()
}

// RouteIPv4 implements server.IPv4Router.
func (r *Router) RouteIPv4(_ context.Context, frame server.DataFrame, send func([]byte) error) error {
	source, _, err := packetAddresses(frame.IPv4)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.routes[source] = send
	r.mu.Unlock()
	r.writeMu.Lock()
	_, err = r.device.Write(frame.IPv4)
	r.writeMu.Unlock()
	return err
}

// Run reads return traffic from TUN and dispatches it to the PPP session whose
// negotiated client address matches the IPv4 destination.
func (r *Router) Run(ctx context.Context) error {
	buffer := make([]byte, 65535)
	go func() { <-ctx.Done(); _ = r.device.Close() }()
	for {
		n, err := r.device.Read(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		packet := append([]byte(nil), buffer[:n]...)
		if err := r.dispatch(packet); err != nil {
			// TUN interfaces can receive IPv6 and transient packets for which no
			// PPP route exists. Neither condition is fatal to the routing loop.
			if errors.Is(err, ErrInvalidPacket) || errors.Is(err, ErrNoRoute) {
				continue
			}
			return err
		}
	}
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
