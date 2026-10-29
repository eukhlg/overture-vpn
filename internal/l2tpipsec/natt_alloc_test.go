package l2tpipsec

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
)

// nattDataWires seals count NAT-T ESP packets of L2TP data carrying one TCP
// flow from the session's client address.
func nattDataWires(t *testing.T, client *esp.SA, tunnelID, sessionID uint16, count int) [][]byte {
	t.Helper()
	ip := make([]byte, 1300)
	ip[0], ip[9] = 0x45, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(ip[20:22], 40000)
	binary.BigEndian.PutUint16(ip[22:24], 443)
	frame, err := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: ip}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	l2tpWire, err := (l2tp.Packet{TunnelID: tunnelID, SessionID: sessionID, Payload: frame}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	udp := encodeUDP(1701, 1701, l2tpWire)
	wires := make([][]byte, count)
	for i := range wires {
		if wires[i], err = client.Seal(udp, esp.IPProtocolUDP); err != nil {
			t.Fatal(err)
		}
	}
	return wires
}

// NAT-T upload through ipsec-go's receive pipeline (two decrypt workers,
// ordered commit, delivery) and the bridge allocates nothing per packet,
// counted across every goroutine of the path.
func TestNATTUploadAllocations(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
	engine, info := pipelineSessionAt(t, &net.UDPAddr{IP: peer.IP, Port: 1701})
	registry := ipsec.NewESPRegistry()
	defer registry.Close()
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(engine, registry)
	if err != nil {
		t.Fatal(err)
	}
	client, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	const warm, count = 1000, 20000
	wires := nattDataWires(t, client, info.TunnelID, info.SessionID, warm+count)
	conn := &pipelinePacketConn{packets: make(chan []byte, len(wires)), stopped: make(chan struct{}), peer: peer}
	for _, wire := range wires {
		conn.packets <- wire
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var delivered atomic.Int64
	var before runtime.MemStats
	measured := make(chan uint64, 1)
	bridge.HandleResult = func(ctx context.Context, result ESPBridgeResult) error {
		if data := result.L2TP.Data; data != nil {
			data.Buffer = ipsec.DeliveryBuffer(ctx)
			switch delivered.Add(1) {
			case warm:
				runtime.ReadMemStats(&before)
			case warm + count:
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				measured <- after.Mallocs - before.Mallocs
				cancel()
			}
		}
		return nil
	}
	listener := &ipsec.ESPTransportServer{Conn: conn, NATT: true, Registry: registry, ReceiveWorkers: 2,
		HandlePacketInPlace: bridge.HandlePacketInPlace, HandleDecrypted: bridge.HandleDecryptedPacket,
		// As the app's delivery batches: per-packet state returns after flush.
		NewDeliveryBatch: func(ctx context.Context) (context.Context, func() error) {
			return bridge.WithDeliveryBatch(ctx, func() error { return nil })
		}}
	if err := listener.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case mallocs := <-measured:
		perPacket := float64(mallocs) / count
		t.Logf("NAT-T upload: %.2f allocations per packet", perPacket)
		// sync.Pool keeps per-packet state; a GC may empty it now and then.
		// The race detector drops pooled objects at random, so it only logs.
		if perPacket > 0.1 && !raceEnabled {
			t.Fatalf("NAT-T upload allocates %.2f times per packet", perPacket)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("delivered %d of %d", delivered.Load(), warm+count)
	}
}
