// Package l2tpipsec connects the independent L2TP and IPsec libraries.
package l2tpipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/flowhash"
	"github.com/eukhlg/netio/packetbuf"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrNotL2TP = errors.New("overture: transport payload is not UDP/1701")

type ESPBridgeResult struct {
	association *ipsec.Association
	logicalKey  netip.AddrPort
	eligible    func() bool
	// WithActive runs a short binding operation while excluding teardown.
	WithActive func(func()) bool
	Datagrams  []ipsec.ESPDatagram
	L2TP       server.Result
}
type espFlow struct {
	session     *ipsec.Association
	peer        net.Addr
	logicalPeer net.Addr
	clientPort  uint16
}

type ESPBridge struct {
	// deliveryMu protects protocol processing and short binding operations only.
	// Application callbacks and device I/O must never hold it.
	deliveryMu sync.RWMutex

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
	// Drops, when set, counts packets discarded at delivery and by owned sends.
	Drops *DropCounters
	// seals, when started, encrypts outbound ESP on workers (StartSealPipeline).
	seals *sealPipeline
}

// StartSealPipeline seals outbound ESP on workers goroutines once Sender is
// set, before serving. Workers 0 or 1 keep sealing on the producer. Packets
// reach the sender in sequence order for every SA (see sealPipeline).
func (b *ESPBridge) StartSealPipeline(ctx context.Context, workers int) {
	if workers <= 1 || b.Sender == nil {
		return
	}
	b.seals = newSealPipeline(ctx, workers, b.Sender.enqueue, func(err error) {
		if b.Debugf != nil {
			b.Debugf("esp sealed packet dropped at enqueue error=%v", err)
		}
	})
}

// CloseSealPipeline stops the workers and releases packets still inside.
func (b *ESPBridge) CloseSealPipeline() {
	if b.seals != nil {
		b.seals.close()
	}
}

// send consumes seal: it seals and enqueues inline, or submits it to the
// pipeline. Callers hold outboundMu between reservation and send.
func (b *ESPBridge) send(association *ipsec.Association, seal ipsec.ESPSeal) error {
	if b.seals != nil {
		return b.seals.submit(association, seal)
	}
	datagram := seal.Seal()
	err := b.Sender.Enqueue(association, datagram)
	if err != nil {
		datagram.Release()
	}
	return err
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
	b.deliveryMu.Lock()
	defer b.deliveryMu.Unlock()
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
	return b.handleDecrypted(session, peer, udp, next, now, borrowed)
}

func (b *ESPBridge) handleDecrypted(session *ipsec.Association, peer net.Addr, udp []byte, next uint8, now time.Time, borrowed bool) (ESPBridgeResult, error) {
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
	var eligible func() bool
	result, err := b.handleFlow(session, peer, sourcePort, payload, now, borrowed, func(r server.Result) {
		eligible = b.resultEligibility(r)
	})
	if err != nil {
		return ESPBridgeResult{}, err
	}
	out := ESPBridgeResult{L2TP: result, association: session, logicalKey: netip.AddrPortFrom(flowKey(peer).Addr(), sourcePort), eligible: eligible}
	if len(result.Replies) == 0 {
		return out, nil
	}
	// Only outbound sealing/enqueue needs ordering. Inbound data and TCP ACKs
	// must keep flowing when a producer is blocked by sender backpressure.
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	for _, reply := range result.Replies {
		if b.seals != nil {
			// Replies take the same ordered path as data, so no SA sequence
			// number overtakes another on the wire.
			if err := b.sendUDPReply(session, peer, sourcePort, reply); err != nil {
				return ESPBridgeResult{}, err
			}
			continue
		}
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

// SendFramedIPv4 is SendIPv4Buffer with a session framer captured at bind time,
// so the router frames without the L2TP engine lock. It consumes buffer.
func (b *ESPBridge) SendFramedIPv4(framer *server.SessionFramer, buffer *packetbuf.Buffer) error {
	if err := framer.PrependIPv4(buffer); err != nil {
		buffer.Release()
		return err
	}
	return b.sendL2TPBuffer(framer.Peer(), buffer)
}

func (b *ESPBridge) sendL2TPBuffer(peer net.Addr, buffer *packetbuf.Buffer) error {
	b.outboundMu.Lock()
	defer b.outboundMu.Unlock()
	if b.Sender == nil {
		buffer.Release()
		return errors.New("esp bridge: sender is not configured")
	}
	key := flowKey(peer)
	b.mu.RLock()
	flow, ok := b.flows[key]
	b.mu.RUnlock()
	if !ok {
		buffer.Release()
		return ipsec.ErrESPPeer
	}
	reserve := func() (ipsec.ESPSeal, error) {
		if buffer.Len() > 65535-8 {
			return ipsec.ESPSeal{}, packetbuf.ErrSize
		}
		header, err := buffer.Prepend(8)
		if err != nil {
			return ipsec.ESPSeal{}, err
		}
		binary.BigEndian.PutUint16(header[:2], 1701)
		binary.BigEndian.PutUint16(header[2:4], flow.clientPort)
		binary.BigEndian.PutUint16(header[4:6], uint16(buffer.Len()))
		clear(header[6:8])
		seal, err := b.Registry.ReserveSealBuffer(flow.session, flow.peer, buffer, esp.IPProtocolUDP)
		if err != nil {
			_ = buffer.TrimFront(8)
		}
		return seal, err
	}
	seal, err := reserve()
	if errors.Is(err, esp.ErrSALifetime) {
		b.Registry.Remove(flow.session.InboundSPI())
	}
	if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, esp.ErrSALifetime) {
		// Re-read under the write lock: inbound traffic may already have replaced
		// this flow, or CloseIKE may have removed it while sealing was in progress.
		// Never publish a replacement from the stale snapshot taken above.
		b.mu.Lock()
		current, exists := b.flows[key]
		if exists {
			if replacement := b.Registry.Replacement(current.session); replacement != nil && replacement.Active() {
				current.session, current.peer = replacement, replacement.Peer()
				b.flows[key] = current
			}
			flow = current
		}
		b.mu.Unlock()
		if !exists {
			err = ipsec.ErrUnknownESP
		} else if flow.session.Active() {
			seal, err = reserve()
		}
	}

	if err != nil {
		buffer.Release()
		return err
	}
	return b.send(flow.session, seal)
}

// SealL2TP returns an owned ciphertext packet for synchronous embedders.
// Production queued traffic uses SendL2TP so enqueue cannot reorder SA sequences;
// SealL2TP must not be mixed with a running seal pipeline for the same SA.
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

// sendUDPReply reserves a control reply in owned storage and sends it through
// the seal pipeline. Callers hold outboundMu.
func (b *ESPBridge) sendUDPReply(session *ipsec.Association, peer net.Addr, clientPort uint16, payload []byte) error {
	buffer, err := packetbuf.Copy(encodeUDP(1701, clientPort, payload))
	if err != nil {
		return err
	}
	seal, err := b.Registry.ReserveSealBuffer(session, peer, buffer, esp.IPProtocolUDP)
	if err != nil {
		buffer.Release()
		if errors.Is(err, esp.ErrSALifetime) {
			b.Registry.Remove(session.InboundSPI())
		}
		return err
	}
	return b.send(session, seal)
}

func (b *ESPBridge) sealUDPReply(session *ipsec.Association, peer net.Addr, clientPort uint16, payload []byte) (ipsec.ESPDatagram, error) {
	return b.Registry.Seal(session, peer, encodeUDP(1701, clientPort, payload), esp.IPProtocolUDP)
}

// HandlePacket adapts authenticated IPsec traffic to L2TP and publishes session events.
func (b *ESPBridge) HandlePacket(ctx context.Context, peer net.Addr, wire []byte, now time.Time) (ipsec.ESPPacketResult, error) {
	return b.handlePacket(ctx, peer, wire, now, false)
}

// HandlePacketInPlace borrows wire until its eventual Dispatch returns. Consumers
// retaining payload asynchronously must copy before returning from Dispatch.
func (b *ESPBridge) HandlePacketInPlace(ctx context.Context, peer net.Addr, wire []byte, now time.Time) (ipsec.ESPPacketResult, error) {
	return b.handlePacket(ctx, peer, wire, now, true)
}
func (b *ESPBridge) handlePacket(ctx context.Context, peer net.Addr, wire []byte, now time.Time, borrowed bool) (ipsec.ESPPacketResult, error) {
	result, err := b.handle(peer, wire, now, borrowed)
	if err != nil {
		return ipsec.ESPPacketResult{}, err
	}
	return b.packetResult(result), nil
}

// HandleDecryptedPacket receives registry-authenticated plaintext. The caller
// owns its storage through Dispatch; flow, PPP and reply handling stay here.
func (b *ESPBridge) HandleDecryptedPacket(ctx context.Context, session *ipsec.Association, peer net.Addr, payload []byte, next uint8, now time.Time) (ipsec.ESPPacketResult, error) {
	result, err := b.handleDecrypted(session, peer, payload, next, now, true)
	if err != nil {
		return ipsec.ESPPacketResult{}, err
	}
	return b.packetResult(result), nil
}

// resultSession identifies the session whose data or binding a result carries.
func resultSession(result server.Result) (uint16, uint16, bool) {
	switch {
	case result.Data != nil:
		return result.Data.TunnelID, result.Data.Session.LocalID, true
	case result.Opened != nil:
		return result.Opened.TunnelID, result.Opened.SessionID, true
	default:
		return 0, 0, false
	}
}

func (b *ESPBridge) resultEligibility(result server.Result) func() bool {
	var tunnelID, sessionID uint16
	if result.Opened != nil {
		tunnelID, sessionID = result.Opened.TunnelID, result.Opened.SessionID
	}
	if result.Data != nil {
		tunnelID, sessionID = result.Data.TunnelID, result.Data.Session.LocalID
	}
	return b.Engine.SessionEligibility(tunnelID, sessionID)
}

func (b *ESPBridge) packetResult(result ESPBridgeResult) ipsec.ESPPacketResult {
	out := ipsec.ESPPacketResult{Datagrams: result.Datagrams}
	// Data of an established session runs on its flow's delivery worker;
	// session events (open, close, control) stay ordered against everything.
	if data := result.L2TP.Data; data != nil && len(data.IPv4) != 0 && result.L2TP.Opened == nil && len(result.L2TP.Closed) == 0 {
		out.Flow, out.FlowValid = flowhash.IPv4(data.IPv4), true
	}
	if b.HandleResult != nil {
		sessionEligible := result.eligible
		if sessionEligible == nil {
			sessionEligible = b.resultEligibility(result.L2TP)
		}
		out.Dispatch = func(ctx context.Context) error {
			b.mu.RLock()
			flow, exists := b.flows[result.logicalKey]
			b.mu.RUnlock()
			eligible, reason := true, DropReason(0)
			switch {
			case !exists:
				eligible, reason = false, DropUpFlowMissing
			case flow.session != result.association:
				eligible, reason = false, DropUpFlowMismatch
			case !result.association.Active():
				eligible, reason = false, DropUpSAInactive
			case !sessionEligible():
				eligible, reason = false, DropUpSessionIneligible
			}
			// Never hold b.mu while invoking callbacks: they may send, acquiring
			// outboundMu and then b.mu. Never acquire outboundMu with b.mu held;
			// recursive RLock can deadlock when a writer is waiting.
			delivered := result
			delivered.WithActive = func(f func()) bool {
				b.deliveryMu.RLock()
				defer b.deliveryMu.RUnlock()
				b.mu.RLock()
				flow, exists := b.flows[result.logicalKey]
				active := exists && flow.session == result.association && result.association.Active()
				b.mu.RUnlock()
				if !active || !sessionEligible() {
					return false
				}
				f()
				return true
			}
			if !eligible {
				if tunnelID, sessionID, ok := resultSession(result.L2TP); ok {
					b.Drops.Record(tunnelID, sessionID, reason, result.logicalKey, nil)
				}
				delivered.L2TP.Opened = nil
				delivered.L2TP.Data = nil
			}
			return b.HandleResult(ctx, delivered)
		}
	}
	return out
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

func (b *ESPBridge) handleFlow(session *ipsec.Association, peer net.Addr, port uint16, payload []byte, now time.Time, borrowed bool, capture ...func(server.Result)) (result server.Result, err error) {
	// Only a pure IPv4 data frame cannot close or replace a PPP session.
	// Serialize all control/negotiation with delivery, but leave data processing
	// concurrent with router/TUN writes.
	packet, decodeErr := l2tp.DecodePacketView(payload)
	frame, frameErr := ppp.DecodeFrameView(packet.Payload)
	if decodeErr != nil || packet.Control || frameErr != nil || frame.Protocol != ppp.ProtocolIPv4 {
		b.deliveryMu.Lock()
		defer b.deliveryMu.Unlock()
	} else {
		b.deliveryMu.RLock()
		defer b.deliveryMu.RUnlock()
	}
	// Pin the engine identity before releasing the control/delivery gate and
	// before synchronous replies can block. Teardown cannot replace it in between.
	defer func() {
		if err == nil {
			for _, f := range capture {
				f(result)
			}
		}
	}()
	key := netip.AddrPortFrom(flowKey(peer).Addr(), port)
	handle := b.Engine.HandleDatagram
	if borrowed {
		handle = b.Engine.HandleDatagramBorrowed
	}
	// Hold a read lock through engine processing so CloseIKE cannot close a
	// tunnel and then have an already authenticated packet recreate it.
	b.mu.RLock()
	flow, ok := b.flows[key]
	if ok && flow.session == session && flow.clientPort == port && sameESPPeer(flow.peer, peer) && decodeErr == nil && !packet.Control && frameErr == nil && frame.Protocol == ppp.ProtocolIPv4 {
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
	result, err = handle(flow.logicalPeer, payload, now)
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
