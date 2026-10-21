package l2tpipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
)

type pipelinePacketConn struct {
	packets          chan []byte
	stopped          chan struct{}
	once             sync.Once
	peer             net.Addr
	timeoutWhenEmpty bool
}

func (c *pipelinePacketConn) ReadFrom(wire []byte) (int, net.Addr, error) {
	if c.timeoutWhenEmpty && len(c.packets) == 0 {
		c.timeoutWhenEmpty = false
		return 0, nil, pipelineTimeout{}
	}
	select {
	case packet := <-c.packets:
		return copy(wire, packet), c.peer, nil
	case <-c.stopped:
		return 0, nil, net.ErrClosed
	}
}
func (c *pipelinePacketConn) WriteTo(wire []byte, _ net.Addr) (int, error) { return len(wire), nil }
func (c *pipelinePacketConn) Close() error                                 { c.once.Do(func() { close(c.stopped) }); return nil }
func (c *pipelinePacketConn) LocalAddr() net.Addr                          { return c.peer }
func (c *pipelinePacketConn) SetReadDeadline(deadline time.Time) error {
	if time.Until(deadline) <= 0 {
		return c.Close()
	}
	return nil
}
func (c *pipelinePacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *pipelinePacketConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}

type pipelineTimeout struct{}

func (pipelineTimeout) Error() string   { return "injected socket timeout" }
func (pipelineTimeout) Timeout() bool   { return true }
func (pipelineTimeout) Temporary() bool { return true }

func TestReceivePipelineMixedAuthenticatedSAs(t *testing.T) {
	for _, natt := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "natt"}[natt], func(t *testing.T) {
			const count = 1000
			peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
			conn := &pipelinePacketConn{packets: make(chan []byte, count+(count+31)/32), stopped: make(chan struct{}), peer: peer}
			registry := ipsec.NewESPRegistry()
			defer registry.Close()
			var clients [2]*esp.SA
			var spis [2]uint32
			encapsulation := uint16(isakmp.EncapsulationTransport)
			if natt {
				encapsulation = isakmp.EncapsulationNATTTransport
			}
			for i := range clients {
				pair := testESPPair(encapsulation)
				pair.Inbound.SPI += uint32(i)
				pair.Outbound.SPI += uint32(i)
				if err := registry.Install(peer, pair); err != nil {
					t.Fatal(err)
				}
				var err error
				clients[i], err = esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
				if err != nil {
					t.Fatal(err)
				}
				spis[i] = pair.Inbound.SPI
			}
			for i := 0; i < count; i++ {
				payload := make([]byte, 4)
				binary.BigEndian.PutUint32(payload, uint32(i))
				wire, err := clients[i%2].Seal(payload, esp.IPProtocolUDP)
				if err != nil {
					t.Fatal(err)
				}
				conn.packets <- wire
				if i%32 == 0 {
					conn.packets <- wire
				} // authenticated duplicates must never dispatch
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			delivered, rejected := 0, 0
			handler := func(_ context.Context, peer net.Addr, wire []byte, _ time.Time) (ipsec.ESPPacketResult, error) {
				sa, payload, next, err := registry.OpenInPlace(peer, wire)
				if err != nil {
					if errors.Is(err, esp.ErrReplay) {
						rejected++
						return ipsec.ESPPacketResult{}, err
					}
					t.Errorf("open: %v", err)
					cancel()
					return ipsec.ESPPacketResult{}, err
				}
				value := binary.BigEndian.Uint32(payload)
				if next != esp.IPProtocolUDP || sa.InboundSPI() != spis[value%2] {
					t.Error("wrong SA or next header")
					cancel()
				}
				return ipsec.ESPPacketResult{Dispatch: func(context.Context) error {
					if value != uint32(delivered) || binary.BigEndian.Uint32(payload) != value {
						return errors.New("mixed-SA delivery reordered or borrowed buffer reused")
					}
					delivered++
					if delivered == count {
						cancel()
					}
					return nil
				}}, nil
			}
			listener := &ipsec.ESPTransportServer{Conn: conn, NATT: natt, HandlePacketInPlace: handler}
			if err := listener.Serve(ctx); err != nil {
				t.Fatal(err)
			}
			if delivered != count || rejected != (count+31)/32 {
				t.Fatalf("delivered=%d replay rejects=%d", delivered, rejected)
			}
		})
	}
}

func TestReceivePipelineMaintainsWhileDeliveryRuns(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	control, err := isakmp.NewControlPlane(isakmp.ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: isakmp.Identification{IDType: isakmp.IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 1024)), HandshakeTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	transform := isakmp.Transform{Number: 1, ID: isakmp.TransformIKE, Attributes: []isakmp.Attribute{
		isakmp.TVAttribute(isakmp.AttributeP1Encryption, isakmp.EncryptionAESCBC), isakmp.TVAttribute(isakmp.AttributeP1Hash, isakmp.HashSHA1), isakmp.TVAttribute(isakmp.AttributeP1AuthMethod, isakmp.AuthPreSharedKey), isakmp.TVAttribute(isakmp.AttributeP1DHGroup, isakmp.DHGroup2), isakmp.TVAttribute(isakmp.AttributeP1KeyLength, 128),
	}}
	sa := isakmp.SecurityAssociation{DOI: isakmp.DOIIPsec, Situation: isakmp.SituationIdentityOnly, Proposals: []isakmp.Proposal{{Number: 1, ProtocolID: isakmp.ProtocolIKE, Transforms: []isakmp.Transform{transform}}}}
	request, err := (isakmp.Packet{InitiatorCookie: isakmp.Cookie{1}, Exchange: isakmp.ExchangeIdentityProtect, Payloads: []isakmp.Payload{sa}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.HandleDatagram(peer, request, time.Now().Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	conn := &pipelinePacketConn{packets: make(chan []byte, 1), stopped: make(chan struct{}), peer: peer, timeoutWhenEmpty: true}
	conn.packets <- []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	running := make(chan struct{})
	finished := false
	maintained := false
	listener := &ipsec.ESPTransportServer{Conn: conn, NATT: true, ControlPlane: control}
	listener.HandlePacket = func(context.Context, net.Addr, []byte, time.Time) (ipsec.ESPPacketResult, error) {
		return ipsec.ESPPacketResult{Dispatch: func(ctx context.Context) error { close(running); <-ctx.Done(); finished = true; return nil }}, nil
	}
	listener.Lifecycle = func(_ context.Context, events []isakmp.LifecycleEvent) {
		select {
		case <-running:
		case <-time.After(time.Second):
			t.Error("delivery did not start")
		}
		for _, event := range events {
			if event.Type == isakmp.LifecycleExpireIKE {
				maintained = true
			}
		}
		cancel()
	}
	if err := listener.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	if !maintained || !finished || control.SACount() != 0 {
		t.Fatalf("maintained=%v callback finished=%v SAs=%d", maintained, finished, control.SACount())
	}
}
