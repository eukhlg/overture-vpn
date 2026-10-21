package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/overture-vpn/internal/l2tpipsec"
	"github.com/eukhlg/overture-vpn/tun"
)

type ipsecRuntime struct {
	ike       *ipsec.IKEServer
	esp, natt *ipsec.ESPTransportServer
	registry  *ipsec.ESPRegistry
	control   *isakmp.ControlPlane
	done      chan error
	sender    *l2tpipsec.ESPSender
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func startIPsec(ctx context.Context, config appConfig, l2tpServer *server.Server, router *tun.Router) (*ipsecRuntime, error) {
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
	registry, err := ipsec.NewESPRegistryWithConfig(ipsec.ESPRegistryConfig{ReplayWindowSize: uint32(config.IPsec.ReplayWindowSize)})
	if err != nil {
		_ = ike.Close()
		return nil, fmt.Errorf("create ESP registry: %w", err)
	}
	bridge, err := l2tpipsec.NewESPBridge(l2tpServer.Engine, registry)
	if err != nil {
		_ = ike.Close()
		return nil, err
	}
	bridge.SetAuthenticatedActivityHandler(func(cookie isakmp.Cookie, now time.Time) {
		control.NotePeerActivity(cookie, now)
	})
	bridge.Tracef, bridge.Debugf = tracef, debugf
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
	raw.HandlePacketInPlace, natt.HandlePacketInPlace = bridge.HandlePacketInPlace, bridge.HandlePacketInPlace
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
	ctx, cancel := context.WithCancel(ctx)
	sender, err := l2tpipsec.NewESPSender(ctx, raw.Conn, natt.Conn, l2tpipsec.SenderQueueCapacity)
	if err != nil {
		cancel()
		_ = raw.Close()
		_ = natt.Close()
		_ = ike.Close()
		return nil, err
	}
	bridge.Sender = sender
	handleResult := func(callbackContext context.Context, result l2tpipsec.ESPBridgeResult) error {
		err := l2tpServer.DispatchIPv4(callbackContext, result.L2TP, "l2tp/ipsec", func(peer net.Addr, tunnelID, sessionID uint16, payload []byte) error {
			buffer, err := packetbuf.Copy(payload)
			if err != nil {
				return err
			}
			err = bridge.SendIPv4Buffer(tunnelID, sessionID, buffer)
			if err != nil {
				if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, ipsec.ErrESPPeer) || errors.Is(err, esp.ErrSALifetime) {
					if debugf != nil {
						debugf("ipsec stale client packet dropped peer=%s error=%v", peer, err)
					}
					return nil
				}
				return err
			}
			return nil
		})
		if err == nil && router != nil && result.L2TP.Opened != nil {
			info := *result.L2TP.Opened
			router.BindOwned(info.Address, func(buffer *packetbuf.Buffer) error {
				err := bridge.SendIPv4Buffer(info.TunnelID, info.SessionID, buffer)
				if errors.Is(err, ipsec.ErrUnknownESP) || errors.Is(err, ipsec.ErrESPPeer) || errors.Is(err, esp.ErrSALifetime) {
					return nil
				}
				return err
			})
		}
		return err
	}
	bridge.HandleResult = handleResult
	runtime := &ipsecRuntime{ike: ike, esp: raw, natt: natt, registry: registry, control: control, done: make(chan error, 4), sender: sender, cancel: cancel}
	runtime.wg.Add(5)
	serve := func(run func(context.Context) error) {
		defer runtime.wg.Done()
		err := run(ctx)
		if ctx.Err() != nil {
			err = nil
		}
		runtime.done <- err
	}
	go serve(ike.Serve)
	go serve(raw.Serve)
	go serve(natt.Serve)
	go func() { defer runtime.wg.Done(); runtime.done <- <-sender.Done() }()
	go func() {
		defer runtime.wg.Done()
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
	r.closeOnce.Do(func() {
		// Bound best-effort IKE delete writes before interrupting data transmission.
		_ = r.ike.Conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		_ = r.natt.Conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		for _, datagram := range r.control.Shutdown() {
			payload, conn := datagram.Payload, r.ike.Conn
			if datagram.NATT {
				payload, conn = esp.EncapsulateNATTIKE(payload), r.natt.Conn
			}
			_, _ = conn.WriteTo(payload, datagram.Peer)
		}
		r.cancel()
		r.sender.Close()
		_ = r.ike.Close()
		r.wg.Wait()
		r.registry.Close()
	})
}
