package l2tpipsec

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/server"
)

func TestDropCountersCountTakeAndNil(t *testing.T) {
	var nilCounters *DropCounters
	nilCounters.Record(1, 2, DropDownNoFlow, nil, nil)
	if nilCounters.Take(1, 2) != "" || nilCounters.Count(1, 2, DropDownNoFlow) != 0 {
		t.Fatal("nil counters must be inert")
	}
	d := NewDropCounters(nil)
	d.Record(1, 2, DropDownSALifetime, "peer", nil)
	d.Record(1, 2, DropDownSALifetime, "peer", nil)
	d.Record(1, 2, DropUpFlowMismatch, "peer", nil)
	d.Record(1, 3, DropDownNoFlow, "peer", nil)
	d.Record(1, 2, dropReasonCount, "peer", nil) // out of range: ignored
	if got := d.Count(1, 2, DropDownSALifetime); got != 2 {
		t.Fatalf("count=%d", got)
	}
	if got := d.Take(1, 2); got != "up-flow-sa-mismatch:1,down-sa-lifetime:2" {
		t.Fatalf("summary=%q", got)
	}
	if d.Take(1, 2) != "" || d.Count(1, 2, DropDownSALifetime) != 0 {
		t.Fatal("Take must reset the session")
	}
	if got := d.Take(1, 3); got != "down-no-flow:1" {
		t.Fatalf("other session=%q", got)
	}
}

func TestDropCountersRateLimitedLog(t *testing.T) {
	now := time.Unix(100, 0)
	var lines []string
	d := NewDropCounters(func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	d.now = func() time.Time { return now }
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 1701}
	for i := 0; i < 4; i++ {
		d.Record(5, 6, DropDownUnknownSA, peer, ipsec.ErrUnknownESP)
		now = now.Add(time.Second)
	}
	d.Record(5, 6, DropDownNoFlow, peer, ipsec.ErrESPPeer) // other reason: own limiter
	now = now.Add(DropLogInterval)
	d.Record(5, 6, DropDownUnknownSA, peer, ipsec.ErrUnknownESP)
	if len(lines) != 3 {
		t.Fatalf("lines=%q", lines)
	}
	if !strings.Contains(lines[0], "reason=down-unknown-sa") || !strings.Contains(lines[0], "count=1") || strings.Contains(lines[0], "suppressed") {
		t.Fatalf("first=%q", lines[0])
	}
	if !strings.Contains(lines[1], "reason=down-no-flow") {
		t.Fatalf("second=%q", lines[1])
	}
	if !strings.Contains(lines[2], "count=5") || !strings.HasSuffix(lines[2], "suppressed=3") {
		t.Fatalf("flush=%q", lines[2])
	}
	for reason := DropReason(0); reason <= dropReasonCount; reason++ {
		if reason.String() == "" {
			t.Fatalf("empty name for %d", reason)
		}
	}
}

func TestDropCountersConcurrent(t *testing.T) {
	d := NewDropCounters(func(string, ...any) {})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				d.Record(1, uint16(g%2), DropUpSAInactive, nil, nil)
			}
		}(g)
	}
	wg.Wait()
	if got := d.Count(1, 0, DropUpSAInactive) + d.Count(1, 1, DropUpSAInactive); got != 8000 {
		t.Fatalf("total=%d", got)
	}
}

// TestDeliveryDropReasons checks that each retirement path that suppresses
// delivered data or bindings records its own reason for the session.
func TestDeliveryDropReasons(t *testing.T) {
	cases := map[string]DropReason{
		"close-ike":  DropUpFlowMissing,
		"delete-sa":  DropUpSAInactive,
		"replace-sa": DropUpFlowMismatch,
		"close-ppp":  DropUpSessionIneligible,
		"shutdown":   DropUpSessionIneligible,
	}
	for retire, want := range cases {
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
			bridge.Drops = NewDropCounters(nil)
			key := flowKey(info.Peer)
			bridge.flows[key] = espFlow{session: association, peer: peer, logicalPeer: info.Peer, clientPort: 1701}
			delivered := 0
			bridge.HandleResult = func(_ context.Context, r ESPBridgeResult) error {
				if r.L2TP.Data != nil || r.L2TP.Opened != nil {
					delivered++
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
			for _, result := range []ipsec.ESPPacketResult{opened, data} {
				if err := result.Dispatch(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if delivered != 0 {
				t.Fatalf("retired results delivered: %d", delivered)
			}
			if got := bridge.Drops.Count(info.TunnelID, info.SessionID, want); got != 2 {
				t.Fatalf("%s count=%d, want 2 (summary %q)", want, got, bridge.Drops.Take(info.TunnelID, info.SessionID))
			}
		})
	}
}

func TestDeliveryNoDropWhenEligible(t *testing.T) {
	engine, info := pipelineSession(t)
	registry := ipsec.NewESPRegistry()
	defer registry.Close()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := openTestAssociation(t, registry, peer, pair)
	bridge, _ := NewESPBridge(engine, registry)
	bridge.Drops = NewDropCounters(nil)
	key := flowKey(info.Peer)
	bridge.flows[key] = espFlow{session: association, peer: peer, logicalPeer: info.Peer, clientPort: 1701}
	bridge.HandleResult = func(context.Context, ESPBridgeResult) error { return nil }
	data := bridge.packetResult(ESPBridgeResult{association: association, logicalKey: key, L2TP: server.Result{Data: &server.DataFrame{TunnelID: info.TunnelID, Session: l2tp.Session{LocalID: info.SessionID}}}})
	if err := data.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := bridge.Drops.Take(info.TunnelID, info.SessionID); got != "" {
		t.Fatalf("unexpected drops %q", got)
	}
}
