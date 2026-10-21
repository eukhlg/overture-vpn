package l2tpipsec

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
)

func TestOwnedSendDoesNotRequireFlowWriteLock(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	logical := &net.UDPAddr{IP: peer.IP, Port: 40000}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	registry := ipsec.NewESPRegistry()
	defer registry.Close()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, _ := NewESPBridge(server.NewEngine(server.Config{}), registry)
	association := openTestAssociation(t, registry, peer, pair)
	bridge.flows[flowKey(logical)] = espFlow{session: association, peer: peer, logicalPeer: logical, clientPort: 40000}
	sender, _ := NewESPSender(context.Background(), newSenderConn(), newSenderConn(), 1)
	sender.Close()
	bridge.Sender = sender
	buffer, _ := packetbuf.Copy([]byte("data"))
	storage := buffer.Bytes()
	done := make(chan error, 1)
	// An established sender must progress alongside receive-side flow readers.
	bridge.mu.RLock()
	go func() { done <- bridge.sendL2TPBuffer(logical, buffer) }()
	select {
	case err := <-done:
		bridge.mu.RUnlock()
		if err == nil {
			t.Fatal("closed sender accepted packet")
		}
	case <-time.After(3 * time.Second):
		bridge.mu.RUnlock()
		<-done
		t.Fatal("established send required the flow write lock")
	}
	assertErased(t, storage)
}

func TestOwnedSendRekeyRaceCannotResurrectDeletedFlow(t *testing.T) {
	for i := 0; i < 32; i++ {
		peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
		logical := &net.UDPAddr{IP: peer.IP, Port: 40000}
		first := testESPPair(isakmp.EncapsulationNATTTransport)
		first.ResponderCookie = isakmp.Cookie{9}
		second := first
		second.Inbound.SPI++
		second.Outbound.SPI++
		registry := ipsec.NewESPRegistry()
		if err := registry.Install(peer, first); err != nil {
			t.Fatal(err)
		}
		bridge, _ := NewESPBridge(server.NewEngine(server.Config{}), registry)
		association := openTestAssociation(t, registry, peer, first)
		bridge.flows[flowKey(logical)] = espFlow{session: association, peer: peer, logicalPeer: logical, clientPort: 40000}
		if err := registry.Install(peer, second); err != nil {
			t.Fatal(err)
		}
		registry.Remove(first.Inbound.SPI)
		sender, _ := NewESPSender(context.Background(), newSenderConn(), newSenderConn(), 1)
		sender.Close()
		bridge.Sender = sender
		start := make(chan struct{})
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			buffer, _ := packetbuf.Copy([]byte("data"))
			storage := buffer.Bytes()
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := bridge.sendL2TPBuffer(logical, buffer); err == nil {
					t.Error("closed sender accepted packet")
				}
				assertErased(t, storage)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			registry.RemoveIKE(first.ResponderCookie)
			bridge.CloseIKE(first.ResponderCookie)
		}()
		close(start)
		wg.Wait()
		if len(bridge.flows) != 0 {
			t.Fatal("rekey resurrected deleted flow")
		}
		registry.Close()
	}
}
