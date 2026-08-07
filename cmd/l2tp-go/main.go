package main

import (
	"context"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"l2tp-go/protocol/ppp"
	"l2tp-go/server"
	"l2tp-go/tun"
)

func main() {
	listen := flag.String("listen", envString("L2TP_LISTEN", ":1701"), "UDP address on which to listen")
	hostname := flag.String("hostname", envString("L2TP_HOSTNAME", "l2tp-go"), "L2TP host name advertised to peers")
	username := flag.String("username", envString("L2TP_USERNAME", "vpn"), "PPP username")
	authMethod := flag.String("auth", envString("L2TP_AUTH", "mschapv2"), "PPP authentication method: mschapv2 or pap")
	dns := flag.String("dns", envString("L2TP_DNS", "1.1.1.1"), "DNS server offered through IPCP")
	enableTUN := flag.Bool("tun", envBool("L2TP_TUN_ENABLED", false), "create and configure a TUN interface for IPv4 routing")
	tunName := flag.String("tun-name", envString("L2TP_TUN_NAME", ""), "requested TUN name (empty selects automatically)")
	mtu := flag.Int("mtu", envInt("L2TP_MTU", 1400), "TUN and PPP routing MTU")
	debug := flag.Bool("debug", envBool("L2TP_DEBUG", false), "enable protocol debug tracing")
	flag.Parse()
	usersValue := os.Getenv("L2TP_USERS")
	if usersValue == "" {
		password := os.Getenv("L2TP_PASSWORD")
		if password == "" {
			log.Fatal("L2TP_USERS or L2TP_PASSWORD must be set")
		}
		usersValue = *username + "=" + password
	}
	users, err := parseUsers(usersValue)
	if err != nil {
		log.Fatal(err)
	}
	network, err := loadNetworkConfig()
	if err != nil {
		log.Fatal(err)
	}
	parseIP := func(value string) netip.Addr {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			log.Fatalf("invalid IPv4 address %q", value)
		}
		return address
	}
	pool, err := server.NewAddressPool(network.Subnet, network.PoolStart, network.PoolEnd)
	if err != nil {
		log.Fatal(err)
	}
	pppConfig := &ppp.SessionConfig{ServerAddress: network.Server, ClientAddress: network.PoolStart, PrimaryDNS: parseIP(*dns), AuthenticatorName: *hostname}
	switch strings.ToLower(*authMethod) {
	case "mschapv2", "ms-chap-v2":
		pppConfig.Authentication = ppp.AuthenticationMSCHAPv2
		pppConfig.LookupPassword = ppp.Passwords(users)
	case "pap":
		pppConfig.Authentication = ppp.AuthenticationPAP
		pppConfig.Authenticate = ppp.Credentials(users)
	default:
		log.Fatalf("unsupported authentication method %q; use mschapv2 or pap", *authMethod)
	}
	serverConfig := server.Config{HostName: *hostname, PPP: pppConfig, AddressPool: pool, MaxSessions: envInt("L2TP_MAX_SESSIONS", network.PoolSize), MaxSessionsPerTunnel: envInt("L2TP_MAX_SESSIONS_PER_TUNNEL", 1), MaxSessionsPerUser: envInt("L2TP_MAX_SESSIONS_PER_USER", 1)}
	if serverConfig.MaxSessions < 0 || serverConfig.MaxSessionsPerTunnel < 0 || serverConfig.MaxSessionsPerUser < 0 {
		log.Fatal("session limits must be zero (unlimited) or positive")
	}
	if *debug {
		serverConfig.Debugf = func(format string, args ...any) { log.Printf("DEBUG "+format, args...) }
	}
	s, err := server.Listen(*listen, serverConfig)
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
		prefix := network.TUNPrefix
		cleanup, err = tun.Configure(context.Background(), device, tun.LinkConfig{Address: prefix, MTU: *mtu}, nil)
		if err != nil {
			log.Fatal(err)
		}
		router, err = tun.NewRouter(device)
		if err != nil {
			log.Fatal(err)
		}
		s.RouteIPv4 = router.RouteIPv4
		s.SessionOpened = func(_ context.Context, info server.SessionInfo, send func([]byte) error) error {
			router.Bind(info.Address, send)
			return nil
		}
		s.SessionClosed = func(_ context.Context, info server.SessionInfo) { router.Forget(info.Address) }
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
	log.Printf("Client pool ready: subnet=%s server=%s range=%s-%s users=%d limits=%d/%d/%d", network.Subnet, network.Server, network.PoolStart, network.PoolEnd, len(users), serverConfig.MaxSessions, serverConfig.MaxSessionsPerTunnel, serverConfig.MaxSessionsPerUser)
	if *debug {
		log.Printf("DEBUG protocol tracing enabled")
	}
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
