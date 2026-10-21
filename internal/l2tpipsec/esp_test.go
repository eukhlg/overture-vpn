package l2tpipsec

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/server"
)

func testESPPair(encapsulation uint16) isakmp.ESPPair {
	return isakmp.ESPPair{Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196, Encapsulation: encapsulation, KeyBits: 128}, Inbound: isakmp.ESPDirectionalKeys{SPI: 0x11111111, EncryptionKey: bytes.Repeat([]byte{1}, 16), AuthenticationKey: bytes.Repeat([]byte{2}, 20)}, Outbound: isakmp.ESPDirectionalKeys{SPI: 0x22222222, EncryptionKey: bytes.Repeat([]byte{3}, 16), AuthenticationKey: bytes.Repeat([]byte{4}, 20)}}
}

func TestESPBridgeProtectedL2TPHandshake(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	registry := ipsec.NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(server.NewEngine(server.Config{HostName: "server"}), registry)
	if err != nil {
		t.Fatal(err)
	}
	var activityCount int
	var activityCookie isakmp.Cookie
	var activityAt time.Time
	bridge.SetAuthenticatedActivityHandler(func(cookie isakmp.Cookie, now time.Time) {
		activityCount++
		activityCookie, activityAt = cookie, now
	})
	clientOutbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 256))})
	if err != nil {
		t.Fatal(err)
	}
	clientInbound, _ := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	sccrq := l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true), l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 77, true)}}
	clientControl := l2tp.NewControlChannel(0, 1)
	l2tpWire, err := clientControl.Queue(sccrq, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	protected, err := clientOutbound.Seal(encodeUDP(40000, 1701, l2tpWire), esp.IPProtocolUDP)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bridge.Handle(peer, protected, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if activityCount != 1 || activityCookie != pair.ResponderCookie || !activityAt.Equal(time.Unix(1, 0)) {
		t.Fatalf("activity count=%d cookie=%x at=%s", activityCount, activityCookie, activityAt)
	}
	if len(result.Datagrams) != 1 {
		t.Fatalf("datagrams=%d", len(result.Datagrams))
	}
	udp, next, err := clientInbound.Open(result.Datagrams[0].Payload)
	if err != nil || next != esp.IPProtocolUDP {
		t.Fatalf("next=%d err=%v", next, err)
	}
	source, destination, reply, err := decodeUDP(udp)
	if err != nil || source != 1701 || destination != 40000 {
		t.Fatalf("ports=%d/%d err=%v", source, destination, err)
	}
	message, err := l2tp.DecodeControlMessage(reply)
	if err != nil || message.Type != l2tp.SCCRP {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	if _, err := bridge.Handle(peer, protected, time.Unix(2, 0)); err != esp.ErrReplay {
		t.Fatalf("replay error=%v", err)
	}
	if activityCount != 1 {
		t.Fatalf("replayed ESP refreshed activity: count=%d", activityCount)
	}
}

func TestESPBridgeMovesFlowToReplacementSAAfterDelete(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	logicalPeer := &net.UDPAddr{IP: peer.IP, Port: 40000}
	cookie := isakmp.Cookie{9}
	first := testESPPair(isakmp.EncapsulationNATTTransport)
	first.ResponderCookie = cookie
	second := testESPPair(isakmp.EncapsulationNATTTransport)
	second.ResponderCookie = cookie
	second.Inbound.SPI, second.Outbound.SPI = 0x33333333, 0x44444444
	registry := ipsec.NewESPRegistry()
	if err := registry.Install(peer, first); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(server.NewEngine(server.Config{HostName: "server"}), registry)
	if err != nil {
		t.Fatal(err)
	}
	oldSession := openTestAssociation(t, registry, peer, first)
	bridge.flows[flowKey(logicalPeer)] = espFlow{session: oldSession, peer: peer, logicalPeer: logicalPeer, clientPort: 40000}
	if err := registry.Install(peer, second); err != nil {
		t.Fatal(err)
	}
	registry.Remove(first.Outbound.SPI)

	datagram, err := bridge.SealL2TP(logicalPeer, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("seal after rekey: %v", err)
	}
	if got := binary.BigEndian.Uint32(datagram.Payload[:4]); got != second.Outbound.SPI {
		t.Fatalf("outbound SPI=%08x want=%08x", got, second.Outbound.SPI)
	}
}

func TestESPBridgeCloseIKERemovesOwnedFlowsAndTunnels(t *testing.T) {
	engine, _, logicalPeer, _ := establishTunnel(t)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	cookie := isakmp.Cookie{9}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = cookie
	registry := ipsec.NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(engine, registry)
	if err != nil {
		t.Fatal(err)
	}
	session := openTestAssociation(t, registry, peer, pair)
	bridge.flows[flowKey(logicalPeer)] = espFlow{session: session, peer: peer, logicalPeer: logicalPeer, clientPort: 40000}

	if closed := bridge.CloseIKE(isakmp.Cookie{8}); len(closed) != 0 || engine.TunnelCount() != 1 || len(bridge.flows) != 1 {
		t.Fatalf("unrelated close: closed=%#v tunnels=%d flows=%d", closed, engine.TunnelCount(), len(bridge.flows))
	}
	if closed := bridge.CloseIKE(cookie); len(closed) != 0 || engine.TunnelCount() != 0 || len(bridge.flows) != 0 {
		t.Fatalf("owned close: closed=%#v tunnels=%d flows=%d", closed, engine.TunnelCount(), len(bridge.flows))
	}
}

func openTestAssociation(t *testing.T, registry *ipsec.ESPRegistry, peer net.Addr, pair isakmp.ESPPair) *ipsec.Association {
	t.Helper()
	client, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.Seal([]byte{1}, esp.IPProtocolUDP)
	if err != nil {
		t.Fatal(err)
	}
	association, _, _, err := registry.Open(peer, wire)
	if err != nil {
		t.Fatal(err)
	}
	return association
}

type testPeer string

func (p testPeer) Network() string { return "udp" }
func (p testPeer) String() string  { return string(p) }
func establishTunnel(t *testing.T) (*server.Engine, *l2tp.ControlChannel, testPeer, time.Time) {
	t.Helper()
	engine := server.NewEngine(server.Config{HostName: "server", FirstTunnelID: 100, ReceiveWindow: 4})
	client := l2tp.NewControlChannel(0, 4)
	peer, now := testPeer("192.0.2.1:1701"), time.Unix(100, 0)
	wire, err := client.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 50, true),
	}}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	message := receiveOne(t, client, result)
	assigned, _ := message.Find(l2tp.AttrAssignedTunnelID)
	client.PeerTunnelID, _ = assigned.Uint16()
	wire, err = client.Queue(l2tp.ControlMessage{Type: l2tp.SCCCN}, now)
	if err != nil {
		t.Fatal(err)
	}
	result, err = engine.HandleDatagram(peer, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	receiveAck(t, client, result)
	return engine, client, peer, now
}

func receiveOne(t *testing.T, channel *l2tp.ControlChannel, result server.Result) l2tp.ControlMessage {
	t.Helper()
	if len(result.Replies) != 1 {
		t.Fatalf("replies=%d", len(result.Replies))
	}
	message, err := channel.Receive(result.Replies[0])
	if err != nil || message == nil {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	return *message
}

func receiveAck(t *testing.T, channel *l2tp.ControlChannel, result server.Result) {
	t.Helper()
	if len(result.Replies) != 1 {
		t.Fatalf("replies=%d", len(result.Replies))
	}
	message, err := channel.Receive(result.Replies[0])
	if err != nil || message != nil {
		t.Fatalf("message=%#v err=%v", message, err)
	}
}
