package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"l2tp-go/protocol/ppp"
	"l2tp-go/server"
)

func main() {
	listen := flag.String("listen", ":1701", "UDP address on which to listen")
	hostname := flag.String("hostname", "l2tp-go", "L2TP host name advertised to peers")
	username := flag.String("username", "vpn", "PAP username")
	serverIP := flag.String("server-ip", "10.0.0.1", "PPP server IPv4 address")
	clientIP := flag.String("client-ip", "10.0.0.2", "PPP client IPv4 address")
	dns := flag.String("dns", "1.1.1.1", "DNS server offered through IPCP")
	flag.Parse()
	password := os.Getenv("L2TP_PASSWORD")
	if password == "" {
		log.Fatal("L2TP_PASSWORD must be set")
	}
	parseIP := func(value string) netip.Addr {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			log.Fatalf("invalid IPv4 address %q", value)
		}
		return address
	}

	s, err := server.Listen(*listen, server.Config{HostName: *hostname, PPP: &ppp.SessionConfig{
		ServerAddress: parseIP(*serverIP), ClientAddress: parseIP(*clientIP), PrimaryDNS: parseIP(*dns),
		Authenticate: ppp.StaticCredentials(*username, password),
	}})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	s.HandleData = func(_ context.Context, frame server.DataFrame) error {
		log.Printf("PPP frame: peer=%s tunnel=%d session=%d protocol=%#x bytes=%d", frame.Peer, frame.TunnelID, frame.Session.LocalID, frame.PPP.Protocol, len(frame.PPP.Payload))
		return nil
	}
	s.RouteIPv4 = func(_ context.Context, frame server.DataFrame, _ func([]byte) error) error {
		log.Printf("IPv4 packet ready for routing: peer=%s bytes=%d", frame.Peer, len(frame.IPv4))
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("L2TP listener started on %s (unencrypted; IPsec transport is not implemented yet)", s.Conn.LocalAddr())
	if err := s.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}
