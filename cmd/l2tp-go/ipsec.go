package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"l2tp-go/protocol/esp"
	"l2tp-go/protocol/isakmp"
	"l2tp-go/server"
)

type ipsecRuntime struct {
	ike       *server.IKEServer
	esp, natt *server.ESPTransportServer
	registry  *server.ESPRegistry
	control   *isakmp.ControlPlane
	done      chan error
}

func startIPsec(ctx context.Context, config appConfig, l2tpServer *server.Server) (*ipsecRuntime, error) {
	identityIP := net.ParseIP(config.IPsec.ServerID).To4()
	identity, _ := netip.ParseAddr(config.IPsec.ServerID)
	ikeLifetime, _ := time.ParseDuration(config.IPsec.IKELifetime)
	espLifetime, _ := time.ParseDuration(config.IPsec.ESPLifetime)
	dpdInterval, _ := time.ParseDuration(config.IPsec.DPDInterval)
	var debugf func(string, ...any)
	if config.Server.Debug >= 1 {
		debugf = func(format string, args ...any) { log.Printf("DEBUG "+format, args...) }
	}
	var tracef func(string, ...any)
	if config.Server.Debug >= 2 {
		tracef = func(format string, args ...any) { log.Printf("TRACE "+format, args...) }
	}
	control, err := isakmp.NewControlPlane(isakmp.ControlPlaneConfig{PreSharedKey: []byte(config.IPsec.PreSharedKey), ResponderID: isakmp.Identification{IDType: isakmp.IDIPv4Address, ProtocolID: 17, Port: 500, Data: identityIP}, ResponderEndpoint: netip.AddrPortFrom(identity, 500), MaxPhase1SAs: config.IPsec.MaxSAs, MaxHalfOpen: config.IPsec.MaxHalfOpen, MaxSAsPerPeer: config.IPsec.MaxSAsPerPeer, Phase1Lifetime: ikeLifetime, ESPLifetime: espLifetime, DPDInterval: dpdInterval, ForceNATT: config.IPsec.ForceNATT, Debugf: debugf})
	if err != nil {
		return nil, fmt.Errorf("create IKE control plane: %w", err)
	}
	ike, err := server.ListenIKEWithControl(config.IPsec.IKEListen, control)
	if err != nil {
		return nil, fmt.Errorf("listen IKE: %w", err)
	}
	registry := server.NewESPRegistry()
	bridge, err := server.NewESPBridge(l2tpServer.Engine, registry)
	if err != nil {
		_ = ike.Close()
		return nil, err
	}
	bridge.Tracef = tracef
	raw, err := server.ListenRawESP(config.IPsec.ESPListen, bridge)
	if err != nil {
		_ = ike.Close()
		return nil, fmt.Errorf("listen raw ESP: %w", err)
	}
	natt, err := server.ListenNATTWithIKE(config.IPsec.NATTListen, bridge, control)
	if err != nil {
		_ = raw.Close()
		_ = ike.Close()
		return nil, fmt.Errorf("listen NAT-T: %w", err)
	}
	ike.Debugf, raw.Debugf, natt.Debugf = debugf, debugf, debugf
	raw.Tracef, natt.Tracef = tracef, tracef
	established := func(_ context.Context, peer net.Addr, pair isakmp.ESPPair) {
		if err := registry.Install(peer, pair); err != nil {
			log.Printf("IPsec SA install failed: peer=%s error=%v", peer, err)
			return
		}
		log.Printf("IPsec ESP SA established: peer=%s inbound_spi=%08x outbound_spi=%08x", peer, pair.Inbound.SPI, pair.Outbound.SPI)
	}
	ike.Established, natt.Established = established, established
	lifecycle := func(_ context.Context, events []isakmp.LifecycleEvent) {
		for _, event := range events {
			switch event.Type {
			case isakmp.LifecycleDeleteESP:
				for _, spi := range event.SPIs {
					registry.Remove(spi)
				}
				log.Printf("IPsec ESP SA delete received: spis=%x", event.SPIs)
			case isakmp.LifecycleDeleteIKE, isakmp.LifecycleExpireIKE:
				registry.RemoveIKE(event.ResponderCookie)
				log.Printf("IKEv1 SA retired: responder_cookie=%x reason=%d", event.ResponderCookie, event.Type)
			}
		}
	}
	ike.Lifecycle, natt.Lifecycle = lifecycle, lifecycle
	sendControl := func(datagram isakmp.ControlDatagram) error {
		payload, conn := datagram.Payload, ike.Conn
		if datagram.NATT {
			payload, conn = esp.EncapsulateNATTIKE(payload), natt.Conn
		}
		_, err := conn.WriteTo(payload, datagram.Peer)
		return err
	}
	send := func(datagram server.ESPDatagram) error {
		if datagram.NATT {
			_, err := natt.Conn.WriteTo(datagram.Payload, datagram.Peer)
			return err
		}
		peer := datagram.Peer
		if udp, ok := peer.(*net.UDPAddr); ok {
			peer = &net.IPAddr{IP: udp.IP}
		}
		_, err := raw.Conn.WriteTo(datagram.Payload, peer)
		return err
	}
	handleResult := func(callbackContext context.Context, result server.ESPBridgeResult) error {
		l2tpResult := result.L2TP
		if l2tpResult.Opened != nil && l2tpServer.SessionOpened != nil {
			info := *l2tpResult.Opened
			if err := l2tpServer.SessionOpened(callbackContext, info, func(payload []byte) error {
				packet, err := l2tpServer.Engine.SendIPv4(info.TunnelID, info.SessionID, payload)
				if err != nil {
					return err
				}
				datagram, err := bridge.SealL2TP(info.Peer, packet.Payload)
				if err != nil {
					return err
				}
				return send(datagram)
			}); err != nil {
				return err
			}
		}
		if l2tpServer.SessionClosed != nil {
			for _, info := range l2tpResult.Closed {
				l2tpServer.SessionClosed(callbackContext, info)
			}
		}
		if l2tpResult.Data != nil && l2tpServer.HandleData != nil {
			if err := l2tpServer.HandleData(callbackContext, *l2tpResult.Data); err != nil {
				return err
			}
		}
		if l2tpResult.Data != nil && l2tpResult.Data.IPv4 != nil && l2tpServer.RouteIPv4 != nil {
			frame := *l2tpResult.Data
			return l2tpServer.RouteIPv4(callbackContext, frame, func(payload []byte) error {
				packet, err := l2tpServer.Engine.SendIPv4(frame.TunnelID, frame.Session.LocalID, payload)
				if err != nil {
					return err
				}
				datagram, err := bridge.SealL2TP(frame.Peer, packet.Payload)
				if err != nil {
					return err
				}
				return send(datagram)
			})
		}
		return nil
	}
	raw.HandleResult, natt.HandleResult = handleResult, handleResult
	runtime := &ipsecRuntime{ike: ike, esp: raw, natt: natt, registry: registry, control: control, done: make(chan error, 3)}
	go func() { runtime.done <- ike.Serve(ctx) }()
	go func() { runtime.done <- raw.Serve(ctx) }()
	go func() { runtime.done <- natt.Serve(ctx) }()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				lifecycle(ctx, control.Maintain(now))
				for _, datagram := range control.PollDPD(now) {
					if err := sendControl(datagram); err != nil && config.Server.Debug >= 1 {
						log.Printf("DEBUG ipsec lifecycle dpd tx failed peer=%s error=%v", datagram.Peer, err)
					}
				}
			}
		}
	}()
	return runtime, nil
}

func (r *ipsecRuntime) Close() {
	if r == nil {
		return
	}
	for _, datagram := range r.control.Shutdown() {
		payload := datagram.Payload
		conn := r.ike.Conn
		if datagram.NATT {
			payload = esp.EncapsulateNATTIKE(payload)
			conn = r.natt.Conn
		}
		_, _ = conn.WriteTo(payload, datagram.Peer)
	}
	_ = r.ike.Close()
	_ = r.esp.Close()
	_ = r.natt.Close()
	r.registry.Close()
}
