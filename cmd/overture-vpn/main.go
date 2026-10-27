package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"errors"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
	"github.com/eukhlg/overture-vpn/internal/l2tpipsec"
	"github.com/eukhlg/overture-vpn/internal/plainl2tp"
	"github.com/eukhlg/overture-vpn/tun"
)

func main() {
	args, err := serverArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	os.Args = append(os.Args[:1], args...)
	configPath := configPathFromArgs(os.Args[1:])
	resolved, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	flag.StringVar(&configPath, "config", configPath, "TOML configuration file")
	flag.StringVar(&resolved.Server.Listen, "listen", resolved.Server.Listen, "UDP address on which to listen")
	flag.StringVar(&resolved.Server.Hostname, "hostname", resolved.Server.Hostname, "L2TP host name advertised to peers")
	legacyUsername := flag.String("username", "", "override the username when exactly one PPP user is configured")
	flag.StringVar(&resolved.Authentication.Method, "auth", resolved.Authentication.Method, "PPP authentication method: mschapv2 or pap")
	flag.StringVar(&resolved.Network.DNS, "dns", resolved.Network.DNS, "DNS server offered through IPCP")
	flag.BoolVar(&resolved.TUN.Enabled, "tun", resolved.TUN.Enabled, "create and configure a TUN interface for IPv4 routing")
	flag.StringVar(&resolved.TUN.Name, "tun-name", resolved.TUN.Name, "requested TUN name (empty selects automatically)")
	flag.IntVar(&resolved.Network.MTU, "mtu", resolved.Network.MTU, "TUN and PPP routing MTU")
	flag.IntVar(&resolved.Server.Debug, "debug", resolved.Server.Debug, "debug level: 0=off, 1=control plane, 2=packet trace")
	printValue := flag.String("print-config-value", "", "print one resolved value and exit")
	flag.Parse()
	if *legacyUsername != "" {
		if len(resolved.Authentication.Users) != 1 {
			log.Fatal("-username requires exactly one configured authentication user")
		}
		resolved.Authentication.Users[0].Username = *legacyUsername
	}
	network, users, err := resolved.validate()
	if err != nil {
		log.Fatal(err)
	}
	if *printValue != "" {
		if err := printResolvedValue(*printValue, resolved, network); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Printf("IPsec ESP receive workers=%d source=%s", resolved.IPsec.ReceiveWorkers, resolved.receiveWorkersSource)
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
	pppConfig := &ppp.SessionConfig{ServerAddress: network.Server, ClientAddress: network.PoolStart, PrimaryDNS: parseIP(resolved.Network.DNS), AuthenticatorName: resolved.Server.Hostname}
	switch strings.ToLower(resolved.Authentication.Method) {
	case "mschapv2", "ms-chap-v2":
		pppConfig.Authentication = ppp.AuthenticationMSCHAPv2
		pppConfig.LookupPassword = ppp.Passwords(users)
	case "pap":
		pppConfig.Authentication = ppp.AuthenticationPAP
		pppConfig.Authenticate = ppp.Credentials(users)
	default:
		log.Fatalf("unsupported authentication method %q; use mschapv2 or pap", resolved.Authentication.Method)
	}
	serverConfig := server.Config{HostName: resolved.Server.Hostname, PPP: pppConfig, AddressPool: pool, MaxSessions: resolved.Limits.Sessions, MaxSessionsPerTunnel: resolved.Limits.SessionsPerTunnel, MaxSessionsPerUser: resolved.Limits.SessionsPerUser, NewTunnelsPerSecond: resolved.Limits.NewTunnelsPerSecond, NewTunnelBurst: resolved.Limits.NewTunnelBurst}
	if serverConfig.MaxSessions < 0 || serverConfig.MaxSessionsPerTunnel < 0 || serverConfig.MaxSessionsPerUser < 0 {
		log.Fatal("session limits must be zero (unlimited) or positive")
	}
	if resolved.Server.Debug >= 1 {
		serverConfig.Debugf = func(format string, args ...any) { log.Printf("DEBUG "+format, args...) }
	}
	if resolved.Server.Debug >= 2 {
		serverConfig.Tracef = func(format string, args ...any) { log.Printf("TRACE "+format, args...) }
	}
	// Build the batched transport before the server exists, so the server
	// only ever sees the adapter and never the raw socket.
	conn, err := net.ListenPacket("udp", resolved.Server.Listen)
	if err != nil {
		log.Fatal(err)
	}
	if err := configureReceiveBuffer("plain L2TP", conn, resolved.L2TP.ReceiveBuffer, udptransport.SetReceiveBuffer, log.Printf); err != nil {
		_ = conn.Close()
		log.Fatal(err)
	}
	plain, err := plainl2tp.NewWithOptions(conn, resolved.L2TP.UDPBatch, udptransport.Options{DisableGSO: !resolved.L2TP.UDPGSO}) // owns conn from here on
	if err != nil {
		conn.Close()
		log.Fatal(err)
	}
	log.Printf("plain L2TP UDP GSO active=%t requested=%t", plain.GSOEnabled(), resolved.L2TP.UDPGSO)
	s, err := server.New(plain, serverConfig)
	if err != nil {
		plain.Close()
		log.Fatal(err)
	}
	// Callbacks get borrowed views of plain's pooled receive buffers (see server.BorrowedReceive).
	s.BorrowedReceive = true
	defer s.Close()
	var router *tun.Router
	var cleanup func(context.Context) error
	if resolved.TUN.Enabled {
		device, err := tun.Open(tun.Config{Name: resolved.TUN.Name, Backend: resolved.TUN.Backend, MTU: resolved.Network.MTU})
		if err != nil {
			log.Fatal(err)
		}
		defer device.Close()
		prefix := network.TUNPrefix
		cleanup, err = tun.Configure(context.Background(), device, tun.LinkConfig{Address: prefix, MTU: resolved.Network.MTU}, nil)
		if err != nil {
			log.Fatal(err)
		}
		router, err = tun.NewRouter(device)
		if err != nil {
			log.Fatal(err)
		}
		s.RouteIPv4 = router.RouteIPv4
		s.RouteIPv4Owned = router.RouteIPv4Owned
		s.NewRouteBatch = router.NewRouteBatch
		log.Printf("TUN routing enabled on %s (%s)", device.Name(), prefix)
	} else {
		s.RouteIPv4 = func(_ context.Context, frame server.DataFrame, _ server.PacketWriter) error {
			log.Printf("IPv4 packet ready for routing: peer=%s bytes=%d (enable -tun to forward)", frame.Peer, len(frame.IPv4))
			return nil
		}
	}
	s.SessionOpened = func(_ context.Context, info server.SessionInfo, send server.PacketWriter) error {
		log.Printf("VPN client connected: user=%q address=%s protocol=%s peer=%s tunnel=%d session=%d", info.Username, info.Address, info.Protocol, info.Peer, info.TunnelID, info.SessionID)
		if router != nil && info.Protocol == "l2tp" {
			router.Bind(info.Address, send)
			if info.Protocol == "l2tp" {
				owned := s.OwnedWriter(info.TunnelID, info.SessionID)
				router.BindOwned(info.Address, func(buffer *packetbuf.Buffer) error {
					err := owned(buffer)
					if errors.Is(err, server.ErrUnknownTunnel) || errors.Is(err, server.ErrSessionNotEstablished) {
						return nil
					}
					return err
				})
			}
		}
		return nil
	}
	var dropDebugf func(string, ...any)
	if resolved.Server.Debug >= 1 {
		dropDebugf = func(format string, args ...any) { log.Printf("DEBUG "+format, args...) }
	}
	drops := l2tpipsec.NewDropCounters(dropDebugf)
	s.SessionClosed = func(_ context.Context, info server.SessionInfo) {
		dropped := drops.Take(info.TunnelID, info.SessionID)
		if info.Connected {
			line := fmt.Sprintf("VPN client disconnected: user=%q address=%s protocol=%s peer=%s tunnel=%d session=%d", info.Username, info.Address, info.Protocol, info.Peer, info.TunnelID, info.SessionID)
			if dropped != "" {
				line += " drops=" + dropped
			}
			log.Print(line)
		} else if dropped != "" {
			log.Printf("VPN session closed before connecting: tunnel=%d session=%d drops=%s", info.TunnelID, info.SessionID, dropped)
		}
		if router != nil {
			router.Forget(info.Address)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var ipsec *ipsecRuntime
	var ipsecDone <-chan error
	if resolved.IPsec.Enabled {
		ipsec, err = startIPsec(ctx, resolved, s, router, drops)
		if err != nil {
			log.Fatal(err)
		}
		defer ipsec.Close()
		ipsecDone = ipsec.done
		log.Printf("IKEv1 listeners started on %s and NAT-T %s; server ID %s force_natt=%t replay_window=%d lifetimes=%s/%s dpd=%s limits=%d/%d/%d", resolved.IPsec.IKEListen, resolved.IPsec.NATTListen, resolved.IPsec.ServerID, resolved.IPsec.ForceNATT, resolved.IPsec.ReplayWindowSize, resolved.IPsec.IKELifetime, resolved.IPsec.ESPLifetime, resolved.IPsec.DPDInterval, resolved.IPsec.MaxSAs, resolved.IPsec.MaxHalfOpen, resolved.IPsec.MaxSAsPerPeer)
	}
	if cleanup != nil {
		defer cleanup(context.Background())
	}
	log.Printf("L2TP listener started on %s (raw L2TP)", s.Conn.LocalAddr())
	log.Printf("Client pool ready: subnet=%s server=%s range=%s-%s users=%d limits=%d/%d/%d", network.Subnet, network.Server, network.PoolStart, network.PoolEnd, len(users), serverConfig.MaxSessions, serverConfig.MaxSessionsPerTunnel, serverConfig.MaxSessionsPerUser)
	if resolved.Server.Debug > 0 {
		log.Printf("DEBUG protocol tracing enabled level=%d", resolved.Server.Debug)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.Serve(ctx) }()
	var routerDone <-chan error
	if router != nil {
		done := make(chan error, 1)
		routerDone = done
		go func() { done <- router.Run(ctx) }()
	}
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
	case err := <-ipsecDone:
		stop()
		if err != nil {
			log.Fatalf("IPsec server stopped: %v", err)
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

// serverArgs keeps flag-only invocations compatible with the original server.
func serverArgs(args []string) ([]string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args, nil
	}
	switch args[0] {
	case "server":
		return args[1:], nil
	case "client":
		return nil, fmt.Errorf("Overture VPN client mode is not implemented yet")
	default:
		return nil, fmt.Errorf("unknown command %q; use overture-vpn server [flags]", args[0])
	}
}
