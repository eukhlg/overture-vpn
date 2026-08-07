package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"l2tp-go/protocol/ppp"
	"l2tp-go/server"
	"l2tp-go/tun"
)

func main() {
	listen := flag.String("listen", envString("L2TP_LISTEN", ":1701"), "UDP address on which to listen")
	hostname := flag.String("hostname", envString("L2TP_HOSTNAME", "l2tp-go"), "L2TP host name advertised to peers")
	username := flag.String("username", envString("L2TP_USERNAME", "vpn"), "PAP username")
	serverIP := flag.String("server-ip", envString("L2TP_SERVER_IP", "10.0.0.1"), "PPP server IPv4 address")
	clientIP := flag.String("client-ip", envString("L2TP_CLIENT_IP", "10.0.0.2"), "PPP client IPv4 address")
	dns := flag.String("dns", envString("L2TP_DNS", "1.1.1.1"), "DNS server offered through IPCP")
	enableTUN := flag.Bool("tun", envBool("L2TP_TUN_ENABLED", false), "create and configure a TUN interface for IPv4 routing")
	tunName := flag.String("tun-name", envString("L2TP_TUN_NAME", ""), "requested TUN name (empty selects automatically)")
	tunPrefix := flag.String("tun-prefix", envString("L2TP_TUN_PREFIX", "10.0.0.1/24"), "IPv4 prefix configured on TUN")
	mtu := flag.Int("mtu", envInt("L2TP_MTU", 1400), "TUN and PPP routing MTU")
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
	serverAddress, clientAddress := parseIP(*serverIP), parseIP(*clientIP)
	if serverAddress == clientAddress {
		log.Fatal("server-ip and client-ip must be different")
	}

	s, err := server.Listen(*listen, server.Config{HostName: *hostname, PPP: &ppp.SessionConfig{
		ServerAddress: serverAddress, ClientAddress: clientAddress, PrimaryDNS: parseIP(*dns),
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
		if !prefix.Contains(serverAddress) || !prefix.Contains(clientAddress) {
			log.Fatalf("TUN prefix %s must contain server %s and client %s", prefix, serverAddress, clientAddress)
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
			log.Fatalf("L2TP server stopped: %v", err)
		}
	case err := <-routerDone:
		stop()
		if err != nil {
			log.Fatalf("TUN router stopped: %v", err)
		}
	}
}

func envString(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Fatalf("%s must be a boolean: %v", name, err)
	}
	return parsed
}

func envInt(name string, fallback int) int {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("%s must be an integer: %v", name, err)
	}
	return parsed
}
