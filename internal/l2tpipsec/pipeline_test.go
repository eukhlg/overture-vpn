package l2tpipsec

import (
	"context"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/l2tp-go/server"
	"net"
	"net/netip"
	"testing"
	"time"
)

func pipelineSession(t *testing.T) (*server.Engine, server.SessionInfo) {
	t.Helper()
	pool, err := server.NewAddressPool(netip.MustParsePrefix("10.0.0.0/24"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	engine := server.NewEngine(server.Config{HostName: "server", FirstTunnelID: 100, FirstSessionID: 200, ReceiveWindow: 4, AddressPool: pool, MaxSessionsPerTunnel: 1, MaxSessionsPerUser: 1, PPP: &ppp.SessionConfig{
		ServerAddress: netip.MustParseAddr("10.0.0.1"), ClientAddress: netip.MustParseAddr("10.0.0.2"),
		PrimaryDNS: netip.MustParseAddr("1.1.1.1"), Authenticate: ppp.StaticCredentials("alice", "secret"),
	}})
	client := l2tp.NewControlChannel(0, 4)
	peer := testPeer("192.0.2.1:1701")
	now := time.Unix(100, 0)

	sccrq := l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true),
		l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true),
		l2tp.StringAVP(l2tp.AttrHostName, "client", true),
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 50, true),
	}}
	wire, err := client.Queue(sccrq, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message := receiveOne(t, client, result)
	if message.Type != l2tp.SCCRP || message.TunnelID != 50 {
		t.Fatalf("SCCRP=%#v", message)
	}
	assigned, ok := message.Find(l2tp.AttrAssignedTunnelID)
	if !ok {
		t.Fatal("missing assigned tunnel ID")
	}
	serverTunnelID, err := assigned.Uint16()
	if err != nil || serverTunnelID != 100 {
		t.Fatalf("tunnel ID=%d err=%v", serverTunnelID, err)
	}
	client.PeerTunnelID = serverTunnelID

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.SCCCN}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, client, result)

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedSessionID, 70, true),
		l2tp.Uint32AVP(l2tp.AttrCallSerialNumber, 1, true),
	}}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message = receiveOne(t, client, result)
	if message.Type != l2tp.ICRP || message.SessionID != 70 {
		t.Fatalf("ICRP=%#v", message)
	}
	assigned, _ = message.Find(l2tp.AttrAssignedSessionID)
	serverSessionID, err := assigned.Uint16()
	if err != nil || serverSessionID != 200 {
		t.Fatalf("session ID=%d err=%v", serverSessionID, err)
	}

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrAssignedSessionID, 71, true),
		l2tp.Uint32AVP(l2tp.AttrCallSerialNumber, 2, true),
	}}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	if rejected := receiveOne(t, client, result); rejected.Type != l2tp.CDN || rejected.SessionID != 71 {
		t.Fatalf("session rejection=%#v", rejected)
	}

	wire, _ = client.Queue(l2tp.ControlMessage{Type: l2tp.ICCN, SessionID: serverSessionID}, now)
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Replies) != 2 {
		t.Fatalf("ICCN replies=%d", len(result.Replies))
	}
	receiveAck(t, client, server.Result{Replies: result.Replies[:1]})
	serverLCP := decodePPPControlDatagram(t, result.Replies[1])

	peerLCPData, _ := ppp.EncodeOptions(ppp.Option{Type: 1, Value: []byte{0x05, 0xdc}})
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolLCP, ppp.ControlPacket{Code: ppp.ConfigureRequest, Identifier: 4, Data: peerLCPData})
	if got := decodePPPControlDatagram(t, result.Replies[0]); got.Code != ppp.ConfigureAck {
		t.Fatalf("LCP reply=%#v", got)
	}
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolLCP, ppp.ControlPacket{Code: ppp.ConfigureAck, Identifier: serverLCP.Identifier, Data: serverLCP.Data})
	if len(result.Replies) != 0 {
		t.Fatalf("LCP ACK replies=%d", len(result.Replies))
	}

	papData := append([]byte{5}, []byte("alice")...)
	papData = append(papData, 6)
	papData = append(papData, []byte("secret")...)
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolPAP, ppp.ControlPacket{Code: 1, Identifier: 5, Data: papData})
	if len(result.Replies) != 2 || decodePPPControlDatagram(t, result.Replies[0]).Code != 2 {
		t.Fatalf("PAP replies=%d", len(result.Replies))
	}
	serverIPCP := decodePPPControlDatagram(t, result.Replies[1])
	clientIPCPData, _ := ppp.EncodeOptions(ppp.IPv4Option(3, netip.MustParseAddr("10.0.0.2")))
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolIPCP, ppp.ControlPacket{Code: ppp.ConfigureRequest, Identifier: 6, Data: clientIPCPData})
	if got := decodePPPControlDatagram(t, result.Replies[0]); got.Code != ppp.ConfigureAck {
		t.Fatalf("IPCP reply=%#v", got)
	}
	result = sendPPPControl(t, engine, peer, now, serverTunnelID, serverSessionID, ppp.ProtocolIPCP, ppp.ControlPacket{Code: ppp.ConfigureAck, Identifier: serverIPCP.Identifier, Data: serverIPCP.Data})
	if len(result.Replies) != 0 {
		t.Fatalf("IPCP ACK replies=%d", len(result.Replies))
	}
	if result.Opened == nil || result.Opened.Address.String() != "10.0.0.2" || result.Opened.Username != "alice" || !result.Opened.Connected {
		t.Fatalf("opened=%#v", result.Opened)
	}

	return engine, *result.Opened
}
func decodePPPControlDatagram(t *testing.T, wire []byte) ppp.ControlPacket {
	t.Helper()
	packet, err := l2tp.DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := ppp.DecodeFrame(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	control, err := ppp.DecodeControlPacket(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return control
}
func sendPPPControl(t *testing.T, engine *server.Engine, peer net.Addr, now time.Time, tid, sid uint16, protocol uint16, control ppp.ControlPacket) server.Result {
	t.Helper()
	payload, err := control.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := (ppp.Frame{Protocol: protocol, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (l2tp.Packet{TunnelID: tid, SessionID: sid, Payload: frame}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestDelayedProtectedDeliveryEligibility(t *testing.T) {
	for _, retire := range []string{"none", "close-ike", "delete-sa", "replace-sa", "close-ppp", "shutdown"} {
		t.Run(retire, func(t *testing.T) {
			engine, info := pipelineSession(t)
			registry := ipsec.NewESPRegistry()
			defer registry.Close()
			peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
			pair := testESPPair(isakmp.EncapsulationNATTTransport)
			pair.ResponderCookie = isakmp.Cookie{9}
			if err := registry.Install(peer, pair); err != nil {
				t.Fatal(err)
			}
			association := openTestAssociation(t, registry, peer, pair)
			bridge, _ := NewESPBridge(engine, registry)
			key := flowKey(info.Peer)
			bridge.flows[key] = espFlow{session: association, peer: peer, logicalPeer: info.Peer, clientPort: 1701}
			var events []string
			bridge.HandleResult = func(_ context.Context, r ESPBridgeResult) error {
				// Callbacks must be able to take b.mu, including while a writer waits.
				bridge.mu.Lock()
				bridge.mu.Unlock()
				if r.L2TP.Opened != nil {
					events = append(events, "bind")
				}
				if r.L2TP.Data != nil {
					events = append(events, "data")
				}
				if len(r.L2TP.Closed) != 0 {
					events = append(events, "closed")
				}
				return nil
			}
			opened := bridge.packetResult(ESPBridgeResult{association: association, logicalKey: key, L2TP: server.Result{Opened: &info}})
			data := bridge.packetResult(ESPBridgeResult{association: association, logicalKey: key, L2TP: server.Result{Data: &server.DataFrame{TunnelID: info.TunnelID, Session: l2tp.Session{LocalID: info.SessionID}}}})
			switch retire {
			case "close-ike":
				registry.RemoveIKE(pair.ResponderCookie)
				bridge.CloseIKE(pair.ResponderCookie)
			case "delete-sa":
				registry.Remove(pair.Inbound.SPI)
			case "replace-sa":
				pair.Inbound.SPI++
				pair.Outbound.SPI++
				if err := registry.Install(peer, pair); err != nil {
					t.Fatal(err)
				}
				f := bridge.flows[key]
				f.session = openTestAssociation(t, registry, peer, pair)
				bridge.flows[key] = f
			case "close-ppp":
				engine.ClosePeer(info.Peer)
			case "shutdown":
				if _, _, err := engine.Shutdown(); err != nil {
					t.Fatal(err)
				}
			}
			if err := opened.Dispatch(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := data.Dispatch(context.Background()); err != nil {
				t.Fatal(err)
			}
			if retire == "none" {
				if len(events) != 2 || events[0] != "bind" || events[1] != "data" {
					t.Fatal(events)
				}
			} else if len(events) != 0 {
				t.Fatalf("retired result delivered: %v", events)
			}
			closed := bridge.packetResult(ESPBridgeResult{association: association, logicalKey: key, L2TP: server.Result{Closed: []server.SessionInfo{info}}})
			if err := closed.Dispatch(context.Background()); err != nil {
				t.Fatal(err)
			}
			if events[len(events)-1] != "closed" {
				t.Fatal("cleanup suppressed")
			}
		})
	}
}

func TestStalledCallbackDoesNotBlockCloseIKE(t *testing.T) {
	engine, info := pipelineSession(t)
	registry := ipsec.NewESPRegistry()
	defer registry.Close()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, registry, peer, pair)
	bridge, _ := NewESPBridge(engine, registry)
	key := flowKey(info.Peer)
	bridge.flows[key] = espFlow{session: association, peer: peer, logicalPeer: info.Peer, clientPort: 1701}
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	control := expiredPipelineControl(t, testPeer("192.0.2.2:500"))
	var maintained bool
	var bound bool
	bridge.HandleResult = func(_ context.Context, r ESPBridgeResult) error {
		close(entered)
		<-resume
		r.WithActive(func() { bound = true })
		return nil
	}
	result := bridge.packetResult(ESPBridgeResult{association: association, logicalKey: key, L2TP: server.Result{Opened: &info}})
	go func() { defer close(done); _ = result.Dispatch(context.Background()) }()
	<-entered
	closed := make(chan struct{})
	go func() {
		for _, event := range control.Maintain(time.Now()) {
			if event.Type == isakmp.LifecycleExpireIKE {
				maintained = true
			}
		}
		registry.RemoveIKE(pair.ResponderCookie)
		bridge.CloseIKE(pair.ResponderCookie)
		bridge.CloseIKE(isakmp.Cookie{10})
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		close(resume)
		<-done
		t.Fatal("lifecycle blocked by callback")
	}
	close(resume)
	<-done
	if !maintained || control.SACount() != 0 {
		t.Fatal("other peer maintenance/expiry stalled")
	}
	if bound || engine.TunnelCount() != 0 {
		t.Fatalf("binding after close=%v tunnels=%d", bound, engine.TunnelCount())
	}
}

func TestPendingCryptoCannotReviveClosedProtectedSession(t *testing.T) {
	for _, retire := range []string{"ike", "esp", "ppp"} {
		t.Run(retire, func(t *testing.T) {
			engine, info := pipelineSession(t)
			registry := ipsec.NewESPRegistry()
			defer registry.Close()
			peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
			pair := testESPPair(isakmp.EncapsulationNATTTransport)
			pair.ResponderCookie = isakmp.Cookie{9}
			if err := registry.Install(peer, pair); err != nil {
				t.Fatal(err)
			}
			association := openTestAssociation(t, registry, peer, pair)
			bridge, _ := NewESPBridge(engine, registry)
			key := flowKey(info.Peer)
			bridge.flows[key] = espFlow{session: association, peer: peer, logicalPeer: info.Peer, clientPort: 1701}
			ipv4 := make([]byte, 20)
			ipv4[0] = 0x45
			ipv4[3] = 20
			frame, err := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: ipv4}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			l2tpWire, err := (l2tp.Packet{TunnelID: info.TunnelID, SessionID: info.SessionID, Payload: frame}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			client, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = client.Seal([]byte{0}, 17) // sequence one was consumed by openTestAssociation
			wire, err := client.Seal(encodeUDP(1701, 1701, l2tpWire), esp.IPProtocolUDP)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := registry.Precheck(peer, wire)
			if err != nil {
				t.Fatal(err)
			}
			switch retire {
			case "ike":
				registry.RemoveIKE(pair.ResponderCookie)
				bridge.CloseIKE(pair.ResponderCookie)
			case "esp":
				registry.Remove(pair.Inbound.SPI)
				engine.ClosePeer(info.Peer)
			case "ppp":
				engine.ClosePeer(info.Peer)
			}
			// This is the same retained phased work item a worker holds across teardown.
			pending.Authenticate()
			sa, payload, next, err := pending.Commit()
			delivered := false
			bridge.HandleResult = func(_ context.Context, r ESPBridgeResult) error {
				delivered = r.L2TP.Opened != nil || r.L2TP.Data != nil
				return nil
			}
			if retire == "ppp" {
				if err != nil {
					t.Fatal(err)
				}
				result, err := bridge.HandleDecryptedPacket(context.Background(), sa, peer, payload, next, time.Now())
				if err == nil && result.Dispatch != nil {
					if err := result.Dispatch(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
			} else if err != ipsec.ErrUnknownESP {
				t.Fatalf("retired commit=%v", err)
			}
			if delivered || engine.TunnelCount() != 0 {
				t.Fatalf("resurrection delivered=%v tunnels=%d", delivered, engine.TunnelCount())
			}
		})
	}
}
