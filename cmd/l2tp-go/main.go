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
	"l2tp-go/tun"
)

func main() {
	listen := flag.String("listen", ":1701", "UDP address on which to listen")
	hostname := flag.String("hostname", "l2tp-go", "L2TP host name advertised to peers")
	username := flag.String("username", "vpn", "PAP username")
	serverIP := flag.String("server-ip", "10.0.0.1", "PPP server IPv4 address")
	clientIP := flag.String("client-ip", "10.0.0.2", "PPP client IPv4 address")
	dns := flag.String("dns", "1.1.1.1", "DNS server offered through IPCP")
	enableTUN := flag.Bool("tun", false, "create and configure a TUN interface for IPv4 routing")
	tunName := flag.String("tun-name", "", "requested TUN name (empty selects automatically)")
	tunPrefix := flag.String("tun-prefix", "10.0.0.1/24", "IPv4 prefix configured on TUN")
	mtu := flag.Int("mtu", 1400, "TUN and PPP routing MTU")
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
	var router *tun.Router
	var cleanup func(context.Context) error
	if *enableTUN {
		device, err := tun.Open(tun.Config{Name: *tunName})
		if err != nil {
			log.Fatal(err)
		}
		defer device.Close()
		prefix, err := netip.ParsePrefix(*tunPrefix)
		if err != nil {
			log.Fatalf("invalid TUN prefix %q: %v", *tunPrefix, err)
		}
		cleanup, err = tun.Configure(context.Background(), device, tun.LinkConfig{Address: prefix, MTU: *mtu}, nil)
		if err != nil {
			log.Fatal(err)
		}
		router, err = tun.NewRouter(device)
		if err != nil {
			log.Fatal(err)
		}
		s.RouteIPv4 = router.RouteIPv4
		log.Printf("TUN routing enabled on %s (%s)", device.Name(), prefix)
	} else {
		s.RouteIPv4 = func(_ context.Context, frame server.DataFrame, _ func([]byte) error) error {
			log.Printf("IPv4 packet ready for routing: peer=%s bytes=%d (enable -tun to forward)", frame.Peer, len(frame.IPv4))
			return nil
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cleanup != nil {
		defer cleanup(context.Background())
	}
	log.Printf("L2TP listener started on %s (unencrypted; IPsec transport is not implemented yet)", s.Conn.LocalAddr())
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Serve(ctx) }()
	if router == nil {
		if err := <-serverDone; err != nil {
			log.Fatal(err)
		}
		return
	}
	routerDone := make(chan error, 1)
	go func() { routerDone <- router.Run(ctx) }()
	select {
	case err := <-serverDone:
		stop()
		if err != nil {
			log.Fatal(err)
		}
	case err := <-routerDone:
		stop()
		if err != nil {
			log.Fatal(err)
		}
	}
}
