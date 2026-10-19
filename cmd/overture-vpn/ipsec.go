package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/overture-vpn/internal/l2tpipsec"
)

type ipsecRuntime struct {
	ike       *ipsec.IKEServer
	esp, natt *ipsec.ESPTransportServer
	registry  *ipsec.ESPRegistry
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
	ike, err := ipsec.ListenIKEWithControl(config.IPsec.IKEListen, control)
	if err != nil {
		return nil, fmt.Errorf("listen IKE: %w", err)
	}
	registry := ipsec.NewESPRegistry()
	bridge, err := l2tpipsec.NewESPBridge(l2tpServer.Engine, registry)
	if err != nil {
		_ = ike.Close()
		return nil, err
	}
	bridge.SetAuthenticatedActivityHandler(func(cookie isakmp.Cookie, now time.Time) {
		control.NotePeerActivity(cookie, now)
	})
	bridge.Tracef = tracef
	raw, err := ipsec.ListenRawESP(config.IPsec.ESPListen, bridge.HandlePacket)
	if err != nil {
		_ = ike.Close()
		return nil, fmt.Errorf("listen raw ESP: %w", err)
	}
	natt, err := ipsec.ListenNATTWithIKE(config.IPsec.NATTListen, bridge.HandlePacket, control)
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
	lifecycle := func(callbackContext context.Context, events []isakmp.LifecycleEvent) {
		for _, event := range events {
			switch event.Type {
			case isakmp.LifecycleRebindIKE:
				registry.RebindIKE(event.ResponderCookie, event.ReplacementCookie)
				log.Printf("IPsec ESP SAs rebound: predecessor_cookie=%x replacement_cookie=%x", event.ResponderCookie, event.ReplacementCookie)
			case isakmp.LifecycleDeleteESP:
				for _, spi := range event.SPIs {
					registry.Remove(spi)
				}
				log.Printf("IPsec ESP SA delete received: spis=%x", event.SPIs)
			case isakmp.LifecycleDeleteIKE, isakmp.LifecycleExpireIKE:
				registry.RemoveIKE(event.ResponderCookie)
				for _, info := range bridge.CloseIKE(event.ResponderCookie) {
					info.Protocol = "l2tp/ipsec"
					if l2tpServer.SessionClosed != nil {
						l2tpServer.SessionClosed(callbackContext, info)
					}
				}
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
	send := func(datagram ipsec.ESPDatagram) error {
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
	handleResult := func(callbackContext context.Context, result l2tpipsec.ESPBridgeResult) error {
		return l2tpServer.Dispatch(callbackContext, result.L2TP, "l2tp/ipsec", func(peer net.Addr, _, _ uint16, payload []byte) error {
			datagram, err := bridge.SealL2TP(peer, payload)
			if err != nil {
				if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, ipsec.ErrESPPeer) || errors.Is(err, esp.ErrSALifetime) {
					if debugf != nil {
						debugf("ipsec stale client packet dropped peer=%s error=%v", peer, err)
					}
					return nil
				}
				return err
			}
			return send(datagram)
		})
	}
	bridge.HandleResult = handleResult
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
				for _, datagram := range control.PollRekey(now) {
					if err := sendControl(datagram); err != nil && config.Server.Debug >= 1 {
						log.Printf("DEBUG ipsec proactive rekey tx failed peer=%s error=%v", datagram.Peer, err)
					}
				}
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
