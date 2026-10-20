package l2tpipsec

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/l2tp-go/server"
)

func TestFramingViewCompatibility(t *testing.T) {
	for _, size := range []int{0, 64, 1400, 65000} {
		payload := bytes.Repeat([]byte{0x45}, size)
		buffer, _ := packetbuf.Copy(payload)
		if err := ppp.PrependFrame(buffer, ppp.ProtocolIPv4); err != nil {
			t.Fatal(err)
		}
		if err := l2tp.PrependData(buffer, 1, 2); err != nil {
			t.Fatal(err)
		}
		frame, _ := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: payload}).MarshalBinary()
		legacy, _ := (l2tp.Packet{TunnelID: 1, SessionID: 2, Payload: frame}).MarshalBinary()
		if !bytes.Equal(buffer.Bytes(), legacy) {
			t.Fatal("framing changed on wire")
		}
		udp := encodeUDP(1701, 1701, legacy)
		_, _, inner, err := decodeUDP(udp)
		if err != nil {
			t.Fatal(err)
		}
		if len(inner) > 0 && (&inner[0] != &udp[8] || cap(inner) != len(inner)) {
			t.Fatal("UDP decoder copied or unbounded")
		}
		p, err := l2tp.DecodePacketView(inner)
		if err != nil {
			t.Fatal(err)
		}
		f, err := ppp.DecodeFrameView(p.Payload)
		if err != nil || !bytes.Equal(f.Payload, payload) {
			t.Fatal("view decapsulation")
		}
		buffer.Release()
	}
	for _, wire := range [][]byte{nil, {1, 2, 3}, {0, 1, 0, 2, 0, 7, 0, 0}, {0, 1, 0, 2, 255, 255, 0, 0}} {
		if _, _, _, err := decodeUDP(wire); err == nil {
			t.Fatal("malformed UDP accepted")
		}
	}
}

func TestOwnedBridgeReplacementAndEnqueueFailure(t *testing.T) {
	for _, failEnqueue := range []bool{false, true} {
		peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
		logical := &net.UDPAddr{IP: peer.IP, Port: 40000}
		first := testESPPair(isakmp.EncapsulationNATTTransport)
		first.ResponderCookie = isakmp.Cookie{9}
		second := first
		second.Inbound.SPI++
		second.Outbound.SPI++
		registry := ipsec.NewESPRegistry()
		defer registry.Close()
		if err := registry.Install(peer, first); err != nil {
			t.Fatal(err)
		}
		bridge, _ := NewESPBridge(server.NewEngine(server.Config{}), registry)
		association := openTestAssociation(t, registry, peer, first)
		bridge.flows[logical.String()] = espFlow{session: association, peer: peer, logicalPeer: logical, clientPort: 40000}
		if err := registry.Install(peer, second); err != nil {
			t.Fatal(err)
		}
		registry.Remove(first.Inbound.SPI)
		raw, natt := newSenderConn(), newSenderConn()
		sender, _ := NewESPSender(context.Background(), raw, natt, 1)
		bridge.Sender = sender
		if failEnqueue {
			sender.Close()
		}
		payload := []byte{1, 2, 3}
		buffer, _ := packetbuf.Copy(payload)
		storage := buffer.Bytes()
		err := bridge.sendL2TPBuffer(logical, buffer)
		if failEnqueue {
			if err == nil {
				t.Fatal("enqueue after shutdown succeeded")
			}
			assertErased(t, storage)
		} else {
			if err != nil {
				t.Fatal(err)
			}
			waitSignal(t, natt.started)
			close(natt.unblock)
			waitSignal(t, natt.finished)
			sender.Close()
			assertErased(t, storage)
			natt.mu.Lock()
			wire := natt.writes[0]
			natt.mu.Unlock()
			client, err := esp.NewSA(esp.SAConfig{SPI: second.Outbound.SPI, Transform: second.Transform, EncryptionKey: second.Outbound.EncryptionKey, AuthenticationKey: second.Outbound.AuthenticationKey})
			if err != nil {
				t.Fatal(err)
			}
			udp, _, err := client.Open(wire)
			if err != nil {
				t.Fatal(err)
			}
			source, destination, body, err := decodeUDP(udp)
			if err != nil || source != 1701 || destination != 40000 || !bytes.Equal(body, payload) {
				t.Fatalf("replacement double-framed UDP: %x %v", udp, err)
			}
		}
	}
}
