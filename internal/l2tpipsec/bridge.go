// Package l2tpipsec connects the independent L2TP and IPsec libraries.
package l2tpipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrNotL2TP = errors.New("overture: transport payload is not UDP/1701")

type ESPBridgeResult struct {
	Datagrams []ipsec.ESPDatagram
	L2TP      server.Result
}
type espFlow struct {
	session     *ipsec.Association
	peer        net.Addr
	logicalPeer net.Addr
	clientPort  uint16
}

type ESPBridge struct {
	// Sender is configured before serving. All ESP replies then share its FIFO.
	Sender                *ESPSender
	outboundMu            sync.Mutex
	Engine                *server.Engine
	Registry              *ipsec.ESPRegistry
	mu                    sync.RWMutex
	flows                 map[netip.AddrPort]espFlow
	authenticatedActivity func(isakmp.Cookie, time.Time)
	Tracef                func(string, ...any)
	Debugf                func(string, ...any)
	HandleResult          func(context.Context, ESPBridgeResult) error
}

func NewESPBridge(engine *server.Engine, registry *ipsec.ESPRegistry) (*ESPBridge, error) {
	if engine == nil || registry == nil {
		return nil, errors.New("esp server: engine and registry are required")
	}
	return &ESPBridge{Engine: engine, Registry: registry, flows: make(map[netip.AddrPort]espFlow)}, nil
}

// SetAuthenticatedActivityHandler registers a callback invoked after an ESP
// packet has passed authentication and replay checks.
func (b *ESPBridge) SetAuthenticatedActivityHandler(handler func(isakmp.Cookie, time.Time)) {
	b.mu.Lock()
	b.authenticatedActivity = handler
	b.mu.Unlock()
}

// CloseIKE removes protected L2TP flows owned by an expired IKE SA and closes
// their local tunnels. The caller remains responsible for removing the ESP SAs
// from the registry.
func (b *ESPBridge) CloseIKE(cookie isakmp.Cookie) []server.SessionInfo {
	b.mu.Lock()
	peers := make(map[netip.AddrPort]net.Addr)
	for key, flow := range b.flows {
		if b.Registry.BelongsToIKE(flow.session, cookie) {
			peers[key] = flow.logicalPeer
			delete(b.flows, key)
		}
	}
	b.mu.Unlock()
	var closed []server.SessionInfo
	for _, peer := range peers {
		if peer != nil {
			closed = append(closed, b.Engine.ClosePeer(peer)...)
		}
	}
	return closed
}

// Handle receives a bare ESP packet (raw protocol 50 or the UDP/4500 payload),
// authenticates it, and feeds its UDP/1701 body to the existing L2TP engine.
func (b *ESPBridge) Handle(peer net.Addr, wire []byte, now time.Time) (ESPBridgeResult, error) {
	return b.handle(peer, wire, now, false)
}
func (b *ESPBridge) handle(peer net.Addr, wire []byte, now time.Time, borrowed bool) (ESPBridgeResult, error) {
	open := b.Registry.Open
	if borrowed {
		open = b.Registry.OpenInPlace
	}
	session, udp, next, err := open(peer, wire)
	if err != nil {
		if b.Debugf != nil && errors.Is(err, esp.ErrReplay) {
			if state, ok := b.Registry.ReplayState(peer, wire); ok {
				b.Debugf("esp replay reject peer=%s spi=%08x sequence=%d highest=%d window=%d reason=%s", peer, state.SPI, state.Sequence, state.Highest, state.Window, state.Reason)
			}
		}
		return ESPBridgeResult{}, err
	}
	ikeCookie := b.Registry.Cookie(session)
	b.mu.RLock()
	authenticatedActivity := b.authenticatedActivity
	b.mu.RUnlock()
	if authenticatedActivity != nil && ikeCookie != (isakmp.Cookie{}) {
		authenticatedActivity(ikeCookie, now)
	}
	if next != esp.IPProtocolUDP {
		return ESPBridgeResult{}, ErrNotL2TP
	}
	sourcePort, destinationPort, payload, err := decodeUDP(udp)
	if err != nil || destinationPort != 1701 {
		return ESPBridgeResult{}, ErrNotL2TP
	}
	if b.Tracef != nil {
		b.Tracef("esp open peer=%s spi=%08x next_header=%d udp=%d->%d payload_bytes=%d encapsulation=%d", peer, session.InboundSPI(), next, sourcePort, destinationPort, len(payload), session.Encapsulation())
	}
	result, err := b.handleFlow(session, peer, sourcePort, payload, now, borrowed)
	if err != nil {
		return ESPBridgeResult{}, err
	}
	out := ESPBridgeResult{L2TP: result}
	if len(result.Replies) == 0 {
		return out, nil
	}
	// Only outbound sealing/enqueue needs ordering. Inbound data and TCP ACKs
	// must keep flowing when a producer is blocked by sender backpressure.
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	for _, reply := range result.Replies {
		datagram, err := b.sealUDPReply(session, peer, sourcePort, reply)
		if err != nil {
			if errors.Is(err, esp.ErrSALifetime) {
				b.Registry.Remove(session.InboundSPI())
			}
			return ESPBridgeResult{}, err
		}
		if b.Sender != nil {
			if err := b.Sender.Enqueue(session, datagram); err != nil {
				return ESPBridgeResult{}, err
			}
		} else {
			out.Datagrams = append(out.Datagrams, datagram)
		}
	}
	return out, nil
}

// SendL2TP seals on the calling goroutine, then queues owned ciphertext. The
// lock spans sequence allocation through enqueue, including control replies.
func (b *ESPBridge) SendL2TP(peer net.Addr, payload []byte) error {
	buffer, err := packetbuf.Copy(payload)
	if err != nil {
		return err
	}
	return b.sendL2TPBuffer(peer, buffer)
}

// SendIPv4Buffer consumes buffer on every outcome. It frames the original TUN
// copy in place, seals on the producer and transfers ownership to the sender.
func (b *ESPBridge) SendIPv4Buffer(tunnelID, sessionID uint16, buffer *packetbuf.Buffer) error {
	peer, err := b.Engine.PrependIPv4(tunnelID, sessionID, buffer)
	if err != nil {
		buffer.Release()
		return err
	}
	return b.sendL2TPBuffer(peer, buffer)
}

func (b *ESPBridge) sendL2TPBuffer(peer net.Addr, buffer *packetbuf.Buffer) error {
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	if b.Sender == nil {
		buffer.Release()
		return errors.New("esp bridge: sender is not configured")
	}
	b.mu.Lock()
	flow, ok := b.flows[flowKey(peer)]
	if !ok {
		b.mu.Unlock()
		buffer.Release()
		return ipsec.ErrESPPeer
	}
	seal := func() (ipsec.ESPDatagram, error) {
		if buffer.Len() > 65535-8 {
			return ipsec.ESPDatagram{}, packetbuf.ErrSize
		}
		header, err := buffer.Prepend(8)
		if err != nil {
			return ipsec.ESPDatagram{}, err
		}
		binary.BigEndian.PutUint16(header[:2], 1701)
		binary.BigEndian.PutUint16(header[2:4], flow.clientPort)
		binary.BigEndian.PutUint16(header[4:6], uint16(buffer.Len()))
		clear(header[6:8])
		datagram, err := b.Registry.SealBuffer(flow.session, flow.peer, buffer, esp.IPProtocolUDP)
		if err != nil {
			_ = buffer.TrimFront(8)
		}
		return datagram, err
	}
	datagram, err := seal()
	if errors.Is(err, esp.ErrSALifetime) {
		b.Registry.Remove(flow.session.InboundSPI())
	}
	if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, esp.ErrSALifetime) {
		if replacement := b.Registry.Replacement(flow.session); replacement != nil {
			flow.session, flow.peer = replacement, replacement.Peer()
			b.flows[flowKey(peer)] = flow
			datagram, err = seal()
		}
	}
	b.mu.Unlock()
	if err != nil {
		buffer.Release()
		return err
	}
	if err = b.Sender.Enqueue(flow.session, datagram); err != nil {
		datagram.Release()
	}
	return err
}

// SealL2TP returns an owned ciphertext packet for synchronous embedders.
// Production queued traffic uses SendL2TP so enqueue cannot reorder SA sequences.
func (b *ESPBridge) SealL2TP(peer net.Addr, payload []byte) (ipsec.ESPDatagram, error) {
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	_, datagram, err := b.sealL2TP(peer, payload)
	return datagram, err
}

func (b *ESPBridge) sealL2TP(peer net.Addr, payload []byte) (*ipsec.Association, ipsec.ESPDatagram, error) {
	// Keep the flow lock through replacement so CloseIKE cannot race with a
	// replacement update and resurrect a deleted flow.
	b.mu.Lock()
	defer b.mu.Unlock()
	flow, ok := b.flows[flowKey(peer)]
	if !ok {
		return nil, ipsec.ESPDatagram{}, ipsec.ErrESPPeer
	}
	datagram, err := b.sealUDPReply(flow.session, flow.peer, flow.clientPort, payload)
	if errors.Is(err, esp.ErrSALifetime) {
		b.Registry.Remove(flow.session.InboundSPI())
	}
	if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, esp.ErrSALifetime) {
		if replacement := b.Registry.Replacement(flow.session); replacement != nil {
			flow.session, flow.peer = replacement, replacement.Peer()
			b.flows[flowKey(peer)] = flow
			datagram, err = b.sealUDPReply(flow.session, flow.peer, flow.clientPort, payload)
		}
	}
	return flow.session, datagram, err
}

func (b *ESPBridge) sealUDPReply(session *ipsec.Association, peer net.Addr, clientPort uint16, payload []byte) (ipsec.ESPDatagram, error) {
	return b.Registry.Seal(session, peer, encodeUDP(1701, clientPort, payload), esp.IPProtocolUDP)
}

// HandlePacket adapts authenticated IPsec traffic to L2TP and publishes session events.
func (b *ESPBridge) HandlePacket(ctx context.Context, peer net.Addr, wire []byte, now time.Time) (ipsec.ESPPacketResult, error) {
	return b.handlePacket(ctx, peer, wire, now, false)
}

// HandlePacketInPlace borrows wire through synchronous Dispatch. Consumers
// retaining payload asynchronously must copy before returning from Dispatch.
func (b *ESPBridge) HandlePacketInPlace(ctx context.Context, peer net.Addr, wire []byte, now time.Time) (ipsec.ESPPacketResult, error) {
	return b.handlePacket(ctx, peer, wire, now, true)
}
func (b *ESPBridge) handlePacket(ctx context.Context, peer net.Addr, wire []byte, now time.Time, borrowed bool) (ipsec.ESPPacketResult, error) {
	result, err := b.handle(peer, wire, now, borrowed)
	if err != nil {
		return ipsec.ESPPacketResult{}, err
	}
	out := ipsec.ESPPacketResult{Datagrams: result.Datagrams}
	if b.HandleResult != nil {
		out.Dispatch = func(ctx context.Context) error { return b.HandleResult(ctx, result) }
	}
	return out, nil
}

func decodeUDP(wire []byte) (uint16, uint16, []byte, error) {
	if len(wire) < 8 {
		return 0, 0, nil, ErrNotL2TP
	}
	length := int(binary.BigEndian.Uint16(wire[4:6]))
	if length < 8 || length > len(wire) {
		return 0, 0, nil, ErrNotL2TP
	}
	return binary.BigEndian.Uint16(wire[:2]), binary.BigEndian.Uint16(wire[2:4]), wire[8:length:length], nil
}
func encodeUDP(source, destination uint16, payload []byte) []byte {
	wire := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(wire[:2], source)
	binary.BigEndian.PutUint16(wire[2:4], destination)
	binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)))
	copy(wire[8:], payload)
	return wire
}

// flowKey uses comparable address values instead of formatting a string for each
// packet. Logical L2TP peers use the authenticated IP and inner UDP source port.
func flowKey(peer net.Addr) netip.AddrPort {
	var addr netip.AddrPort
	switch p := peer.(type) {
	case *net.UDPAddr:
		addr = p.AddrPort()
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(p.IP)
		addr = netip.AddrPortFrom(ip, 0)
	default:
		addr, _ = netip.ParseAddrPort(peer.String())
	}
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}

func sameESPPeer(a, b net.Addr) bool {
	// Preserve the outer interface zone for replies, while logical L2TP keys use
	// only the authenticated IP. The common UDP/raw paths never format strings.
	switch p := a.(type) {
	case *net.UDPAddr:
		q, ok := b.(*net.UDPAddr)
		return ok && p.Port == q.Port && p.Zone == q.Zone && p.IP.Equal(q.IP)
	case *net.IPAddr:
		q, ok := b.(*net.IPAddr)
		return ok && p.Zone == q.Zone && p.IP.Equal(q.IP)
	default:
		return a.Network() == b.Network() && a.String() == b.String()
	}
}

func (b *ESPBridge) handleFlow(session *ipsec.Association, peer net.Addr, port uint16, payload []byte, now time.Time, borrowed bool) (server.Result, error) {
	key := netip.AddrPortFrom(flowKey(peer).Addr(), port)
	handle := b.Engine.HandleDatagram
	if borrowed {
		handle = b.Engine.HandleDatagramBorrowed
	}
	// Hold a read lock through engine processing so CloseIKE cannot close a
	// tunnel and then have an already authenticated packet recreate it.
	b.mu.RLock()
	flow, ok := b.flows[key]
	if ok && flow.session == session && flow.clientPort == port && sameESPPeer(flow.peer, peer) {
		defer b.mu.RUnlock()
		if !session.Active() {
			return server.Result{}, ipsec.ErrUnknownESP
		}
		return handle(flow.logicalPeer, payload, now)
	}
	b.mu.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !session.Active() {
		return server.Result{}, ipsec.ErrUnknownESP
	}
	// Recheck after upgrading: another caller may already have published it.
	flow, ok = b.flows[key]
	changed := !ok || flow.session != session || flow.clientPort != port || !sameESPPeer(flow.peer, peer)
	if !ok {
		flow.logicalPeer = net.UDPAddrFromAddrPort(key)
	}
	result, err := handle(flow.logicalPeer, payload, now)
	if err != nil {
		return server.Result{}, err
	}
	if changed {
		flow.session, flow.peer, flow.clientPort = session, cloneFlowPeer(peer), port
		b.flows[key] = flow
	}
	return result, nil
}

// The receive transport may reuse its address storage after Dispatch returns.
func cloneFlowPeer(peer net.Addr) net.Addr {
	switch p := peer.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), p.IP...), Port: p.Port, Zone: p.Zone}
	case *net.IPAddr:
		return &net.IPAddr{IP: append(net.IP(nil), p.IP...), Zone: p.Zone}
	default:
		return peer
	}
}
