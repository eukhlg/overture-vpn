package l2tpipsec

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

func sealPipelineBridge(t *testing.T, writer udptransport.Writer) (*ESPBridge, *net.UDPAddr, isakmp.ESPPair, *ipsec.ESPSender) {
	t.Helper()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	logical := &net.UDPAddr{IP: peer.IP, Port: 40000}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	registry := ipsec.NewESPRegistry()
	t.Cleanup(registry.Close)
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, _ := NewESPBridge(server.NewEngine(server.Config{}), registry)
	association := openTestAssociation(t, registry, peer, pair)
	bridge.flows[flowKey(logical)] = espFlow{session: association, peer: peer, logicalPeer: logical, clientPort: 40000}
	sender, err := ipsec.NewESPSenderWithWriter(context.Background(), newSenderConn(), newSenderConn(), writer, 8, 32)
	if err != nil {
		t.Fatal(err)
	}
	bridge.Sender = sender
	return bridge, logical, pair, sender
}

// Data from the router and control replies from delivery, sealed on four
// workers, must reach the socket in SA sequence order.
func TestSealPipelineKeepsSequenceOrder(t *testing.T) {
	var mu sync.Mutex
	var wire [][]byte
	writer := batchWriteFunc(func(m []udptransport.Message) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		for _, msg := range m {
			wire = append(wire, append([]byte(nil), msg.Payload...))
		}
		return len(m), nil
	})
	bridge, logical, pair, sender := sealPipelineBridge(t, writer)
	bridge.StartSealPipeline(context.Background(), 4)
	const data, replies = 400, 40
	var producers sync.WaitGroup
	producers.Add(2)
	go func() {
		defer producers.Done()
		for i := 0; i < data; i++ {
			buffer, _ := packetbuf.Copy([]byte{'d', byte(i >> 8), byte(i)})
			if err := bridge.sendL2TPBuffer(logical, buffer); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer producers.Done()
		flow := bridge.flows[flowKey(logical)]
		for i := 0; i < replies; i++ {
			bridge.outboundMu.Lock()
			err := bridge.sendUDPReply(flow.session, flow.peer, flow.clientPort, []byte{'r', byte(i)})
			bridge.outboundMu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	producers.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(wire)
		mu.Unlock()
		if n == data+replies {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d packets written", n, data+replies)
		}
		time.Sleep(time.Millisecond)
	}
	bridge.CloseSealPipeline()
	sender.Close()
	mu.Lock()
	defer mu.Unlock()
	client, err := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	last := uint32(0)
	nextData := 0
	for _, w := range wire {
		sequence := binary.BigEndian.Uint32(w[4:8])
		if sequence != last+1 {
			t.Fatalf("sequence %d after %d: packets reordered", sequence, last)
		}
		last = sequence
		payload, _, err := client.Open(w)
		if err != nil {
			t.Fatalf("sequence %d: %v", sequence, err)
		}
		if body := payload[8:]; body[0] == 'd' {
			if got := int(body[1])<<8 | int(body[2]); got != nextData {
				t.Fatalf("data %d arrived as %d", nextData, got)
			}
			nextData++
		}
	}
}

// Close releases every reserved packet still inside the pipeline or sender.
func TestSealPipelineCloseReleasesInFlight(t *testing.T) {
	block := make(chan struct{})
	writer := batchWriteFunc(func(m []udptransport.Message) (int, error) {
		<-block
		return 0, net.ErrClosed
	})
	bridge, logical, _, sender := sealPipelineBridge(t, writer)
	bridge.StartSealPipeline(context.Background(), 3)
	var views [][]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < SealCapacity+udptransport.SenderQueueCapacity; i++ {
			buffer, _ := packetbuf.Copy([]byte{1, 2, 3, 4})
			views = append(views, buffer.Bytes()[:4])
			if err := bridge.sendL2TPBuffer(logical, buffer); err != nil {
				return // shutdown: the buffer was consumed
			}
		}
	}()
	time.Sleep(50 * time.Millisecond) // let the pipeline and sender queue fill
	bridge.CloseSealPipeline()
	close(block)
	sender.Close()
	<-done
	assertErased(t, views...)
}
