// Package l2tpipsec connects the independent L2TP and IPsec libraries.
package l2tpipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"net"
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
	flows                 map[string]espFlow
	authenticatedActivity func(isakmp.Cookie, time.Time)
	Tracef                func(string, ...any)
	HandleResult          func(context.Context, ESPBridgeResult) error
}

func NewESPBridge(engine *server.Engine, registry *ipsec.ESPRegistry) (*ESPBridge, error) {
	if engine == nil || registry == nil {
		return nil, errors.New("esp server: engine and registry are required")
	}
	return &ESPBridge{Engine: engine, Registry: registry, flows: make(map[string]espFlow)}, nil
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
	peers := make(map[string]net.Addr)
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
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	session, udp, next, err := b.Registry.Open(peer, wire)
	if err != nil {
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
	logicalPeer := &net.UDPAddr{IP: append(net.IP(nil), session.PeerIP()...), Port: int(sourcePort)}
	if b.Tracef != nil {
		b.Tracef("esp open peer=%s spi=%08x next_header=%d udp=%d->%d payload_bytes=%d encapsulation=%d", peer, session.InboundSPI(), next, sourcePort, destinationPort, len(payload), session.Encapsulation())
	}
	// Serialize flow publication with CloseIKE, including engine tunnel creation.
	// A packet authenticated just before deletion cannot resurrect a dead tunnel.
	b.mu.Lock()
	if !session.Active() {
		b.mu.Unlock()
		return ESPBridgeResult{}, ipsec.ErrUnknownESP
	}
	result, err := b.Engine.HandleDatagram(logicalPeer, payload, now)
	if err != nil {
		b.mu.Unlock()
		return ESPBridgeResult{}, err
	}
	b.flows[logicalPeer.String()] = espFlow{session: session, peer: peer, logicalPeer: logicalPeer, clientPort: sourcePort}
	b.mu.Unlock()
	out := ESPBridgeResult{L2TP: result}
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
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	if b.Sender == nil {
		return errors.New("esp bridge: sender is not configured")
	}
	session, datagram, err := b.sealL2TP(peer, payload)
	if err != nil {
		return err
	}
	return b.Sender.Enqueue(session, datagram)
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
	flow, ok := b.flows[peer.String()]
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
			b.flows[peer.String()] = flow
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
	result, err := b.Handle(peer, wire, now)
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
	return binary.BigEndian.Uint16(wire[:2]), binary.BigEndian.Uint16(wire[2:4]), append([]byte(nil), wire[8:length]...), nil
}
func encodeUDP(source, destination uint16, payload []byte) []byte {
	wire := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(wire[:2], source)
	binary.BigEndian.PutUint16(wire[2:4], destination)
	binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)))
	copy(wire[8:], payload)
	return wire
}
