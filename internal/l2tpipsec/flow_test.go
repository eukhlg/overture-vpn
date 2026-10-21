package l2tpipsec

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/server"
)

func flowSCCRQ(t *testing.T) []byte {
	t.Helper()
	c := l2tp.NewControlChannel(0, 4)
	wire, err := c.Queue(l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{
		l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true),
		l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true),
		l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true),
		l2tp.StringAVP(l2tp.AttrHostName, "client", true),
		l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 77, true),
	}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestFlowPublicationAndReplacement(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	registry := ipsec.NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, _ := NewESPBridge(server.NewEngine(server.Config{HostName: "server"}), registry)
	first := openTestAssociation(t, registry, peer, pair)
	wire := flowSCCRQ(t)
	receive := func(s *ipsec.Association, port uint16) {
		t.Helper()
		if _, err := bridge.handleFlow(s, peer, port, wire, time.Now(), true); err != nil {
			t.Fatal(err)
		}
	}
	receive(first, 40000)
	key := flowKey(&net.UDPAddr{IP: peer.IP, Port: 40000})
	initial := bridge.flows[key]
	if len(bridge.flows) != 1 || initial.session != first {
		t.Fatal("new flow missing")
	}
	for i := 0; i < 10; i++ {
		receive(first, 40000)
	}
	if bridge.flows[key].logicalPeer != initial.logicalPeer || bridge.flows[key].peer != initial.peer {
		t.Fatal("unchanged flow rewritten")
	}
	peer.Port = 4501
	receive(first, 40000)
	if bridge.flows[key].peer.(*net.UDPAddr).Port != 4501 || initial.peer.(*net.UDPAddr).Port != 4500 {
		t.Fatal("peer change missing or retained mutable address")
	}
	pair.Inbound.SPI++
	pair.Outbound.SPI++
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	replacement := openTestAssociation(t, registry, peer, pair)
	receive(replacement, 40000)
	if bridge.flows[key].session != replacement || bridge.flows[key].logicalPeer != initial.logicalPeer {
		t.Fatal("rekey lost flow identity")
	}
	receive(replacement, 40001)
	if len(bridge.flows) != 2 {
		t.Fatal("new client port missing")
	}
	registry.RemoveIKE(pair.ResponderCookie)
	bridge.CloseIKE(pair.ResponderCookie)
	if _, err := bridge.handleFlow(replacement, peer, 40000, wire, time.Now(), true); !errors.Is(err, ipsec.ErrUnknownESP) {
		t.Fatalf("deleted session: %v", err)
	}
	if len(bridge.flows) != 0 || bridge.Engine.TunnelCount() != 0 {
		t.Fatal("deleted tunnel resurrected")
	}
}

func TestAuthenticatedPacketCannotResurrectClosedIKE(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	registry := ipsec.NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, _ := NewESPBridge(server.NewEngine(server.Config{HostName: "server"}), registry)
	bridge.SetAuthenticatedActivityHandler(func(cookie isakmp.Cookie, _ time.Time) {
		registry.RemoveIKE(cookie)
		bridge.CloseIKE(cookie)
	})
	client, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.Seal(encodeUDP(40000, 1701, flowSCCRQ(t)), 17)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bridge.Handle(peer, wire, time.Now()); !errors.Is(err, ipsec.ErrUnknownESP) {
		t.Fatal(err)
	}
	if len(bridge.flows) != 0 || bridge.Engine.TunnelCount() != 0 {
		t.Fatal("authenticated packet resurrected tunnel")
	}
}

func TestESPPeerIdentityIncludesPortZoneAndTransport(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 4500, Zone: "eth0"}
	for _, tc := range []struct {
		peer  net.Addr
		equal bool
	}{
		{&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 4500, Zone: "eth0"}, true},
		{&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 4501, Zone: "eth0"}, false},
		{&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 4500, Zone: "eth1"}, false},
		{&net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}, false},
	} {
		if sameESPPeer(a, tc.peer) != tc.equal {
			t.Fatalf("peer identity %v", tc.peer)
		}
	}
	// A native IPv4 peer and its mapped representation share one logical flow.
	if flowKey(&net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 1701}) != flowKey(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1701}) {
		t.Fatal("IPv4 flow identity differs")
	}
}
