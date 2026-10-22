package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
)

func TestFormatRemoveEvent(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 4500}
	bytes := formatRemoveEvent(ipsec.RemoveEvent{Reason: ipsec.RemoveLifetime, Direction: ipsec.RemoveDirectionOutbound, Lifetime: &esp.LifetimeError{Reason: esp.LifetimeBytes, Packets: 3, Bytes: 4000, Limit: 4096}, InboundSPI: 0xa, OutboundSPI: 0xb, Peer: peer, IKECookie: isakmp.Cookie{1}})
	for _, want := range []string{"ipsec sa removed reason=lifetime", "peer=198.51.100.7:4500", "inbound_spi=0000000a", "outbound_spi=0000000b", "direction=outbound", "limit=bytes", "packets=3 bytes=4000 max=4096"} {
		if !strings.Contains(bytes, want) {
			t.Fatalf("%q missing %q", bytes, want)
		}
	}
	timed := formatRemoveEvent(ipsec.RemoveEvent{Reason: ipsec.RemoveLifetime, Direction: ipsec.RemoveDirectionInbound, Lifetime: &esp.LifetimeError{Reason: esp.LifetimeTime, Age: time.Hour, Lifetime: time.Hour}})
	if !strings.Contains(timed, "limit=time age=1h0m0s lifetime=1h0m0s") || !strings.Contains(timed, "direction=inbound") {
		t.Fatalf("timed=%q", timed)
	}
	explicit := formatRemoveEvent(ipsec.RemoveEvent{Reason: ipsec.RemoveExplicit, InboundSPI: 1, OutboundSPI: 2, Peer: peer})
	if strings.Contains(explicit, "direction=") || strings.Contains(explicit, "limit=") || !strings.Contains(explicit, "reason=explicit") {
		t.Fatalf("explicit=%q", explicit)
	}
}
