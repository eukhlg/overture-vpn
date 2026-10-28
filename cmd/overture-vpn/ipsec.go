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
	"github.com/eukhlg/netio/udptransport"
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
	bridge    *l2tpipsec.ESPBridge
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func startIPsec(ctx context.Context, config appConfig, l2tpServer *server.Server, router *tun.Router, drops *l2tpipsec.DropCounters) (*ipsecRuntime, error) {
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
	bridge.Drops = drops
	if debugf != nil {
		registry.SetRemoveHandler(func(event ipsec.RemoveEvent) { debugf("%s", formatRemoveEvent(event)) })
	}
	raw, err := ipsec.ListenRawESP(config.IPsec.ESPListen, bridge.HandlePacket)
	if err != nil {
		_ = ike.Close()
		return nil, fmt.Errorf("listen raw ESP: %w", err)
	}
	if err := configureReceiveBuffer("raw ESP", raw.Conn, config.IPsec.ReceiveBuffer, udptransport.SetReceiveBuffer, log.Printf); err != nil {
		_ = raw.Close()
		_ = ike.Close()
		return nil, err
	}
	natt, err := ipsec.ListenNATTWithIKE(config.IPsec.NATTListen, bridge.HandlePacket, control)
	if err != nil {
		_ = raw.Close()
		_ = ike.Close()
		return nil, fmt.Errorf("listen NAT-T: %w", err)
	}
	if err := configureReceiveBuffer("NAT-T", natt.Conn, config.IPsec.ReceiveBuffer, udptransport.SetReceiveBuffer, log.Printf); err != nil {
		_ = natt.Close()
		_ = raw.Close()
		_ = ike.Close()
		return nil, err
	}
	natt.UDPBatchSize = config.IPsec.UDPBatch
	raw.HandlePacketInPlace, natt.HandlePacketInPlace = bridge.HandlePacketInPlace, bridge.HandlePacketInPlace
	raw.Registry, natt.Registry = registry, registry
	raw.ReceiveWorkers, natt.ReceiveWorkers = config.IPsec.ReceiveWorkers, config.IPsec.ReceiveWorkers
	raw.HandleDecrypted, natt.HandleDecrypted = bridge.HandleDecryptedPacket, bridge.HandleDecryptedPacket
	if router != nil {
		// One context per delivery goroutine, with a slot for the per-packet
		// guard, so delivering a packet allocates no context.
		newBatch := func(ctx context.Context) (context.Context, func() error) {
			ctx, flush := router.NewRouteBatch(ctx)
			return tun.WithBindingGuardSlot(ctx), flush
		}
		raw.NewDeliveryBatch, natt.NewDeliveryBatch = newBatch, newBatch
	}
	workers := config.deliveryWorkers()
	raw.DeliveryWorkers, natt.DeliveryWorkers = workers, workers
	log.Printf("IPsec ESP delivery workers=%d requested=%d (0 = one)", workers, config.IPsec.DeliveryWorkers)
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
	sender, err := l2tpipsec.NewESPSenderWithOptions(ctx, raw.Conn, natt.Conn, l2tpipsec.SenderQueueCapacity, config.IPsec.UDPSendBatch, udptransport.Options{DisableGSO: !config.IPsec.UDPGSO})
	if err != nil {
		cancel()
		_ = raw.Close()
		_ = natt.Close()
		_ = ike.Close()
		return nil, err
	}
	log.Printf("NAT-T UDP GSO active=%t requested=%t send_batch=%d", sender.GSOEnabled(), config.IPsec.UDPGSO, config.IPsec.UDPSendBatch)
	log.Print("NAT-T UDP GRO active=false")
	bridge.Sender = sender
	bridge.StartSealPipeline(ctx, config.IPsec.SealWorkers)
	log.Printf("IPsec ESP seal workers=%d source=%s (0 or 1 = serial)", config.IPsec.SealWorkers, config.sealWorkersSource)
	handleResult := func(callbackContext context.Context, result l2tpipsec.ESPBridgeResult) error {
		if !tun.SetBindingGuard(callbackContext, result.WithActive) {
			callbackContext = tun.WithBindingGuard(callbackContext, result.WithActive)
		}
		defer tun.SetBindingGuard(callbackContext, nil)
		if data := result.L2TP.Data; data != nil {
			// Delivery owns the decrypted buffer until its flush hook returns;
			// the router borrows it in place (see server.OwnedIPv4Router).
			data.Buffer = ipsec.DeliveryBuffer(callbackContext)
		}
		err := l2tpServer.DispatchIPv4(callbackContext, result.L2TP, "l2tp/ipsec", func(peer net.Addr, tunnelID, sessionID uint16, payload []byte) error {
			buffer, err := packetbuf.Copy(payload)
			if err != nil {
				return err
			}
			err = bridge.SendIPv4Buffer(tunnelID, sessionID, buffer)
			if reason, dropped := downloadDrop(err); dropped {
				drops.Record(tunnelID, sessionID, reason, peer, err)
				return nil
			}
			return err
		})
		if err == nil && router != nil && result.L2TP.Opened != nil {
			info := *result.L2TP.Opened
			result.WithActive(func() {
				send := func(buffer *packetbuf.Buffer) error {
					return bridge.SendIPv4Buffer(info.TunnelID, info.SessionID, buffer)
				}
				if framer, err := l2tpServer.Engine.SessionFramer(info.TunnelID, info.SessionID); err == nil {
					send = func(buffer *packetbuf.Buffer) error { return bridge.SendFramedIPv4(framer, buffer) }
				}
				router.BindOwned(info.Address, func(buffer *packetbuf.Buffer) error {
					err := send(buffer)
					if reason, dropped := downloadDrop(err); dropped {
						drops.Record(info.TunnelID, info.SessionID, reason, info.Peer, err)
						return nil
					}
					return err
				})
			})
		}
		return err
	}
	bridge.HandleResult = handleResult
	runtime := &ipsecRuntime{ike: ike, esp: raw, natt: natt, registry: registry, control: control, done: make(chan error, 4), sender: sender, bridge: bridge, cancel: cancel}
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
		r.bridge.CloseSealPipeline()
		r.sender.Close()
		_ = r.ike.Close()
		r.wg.Wait()
		r.registry.Close()
	})
}

// downloadDrop classifies send errors that mean the client's SA or flow is
// gone. Such packets are dropped without failing the TUN read loop.
func downloadDrop(err error) (l2tpipsec.DropReason, bool) {
	switch {
	case err == nil:
		return 0, false
	case errors.Is(err, esp.ErrSALifetime):
		return l2tpipsec.DropDownSALifetime, true
	case errors.Is(err, ipsec.ErrESPPeer):
		return l2tpipsec.DropDownNoFlow, true
	case errors.Is(err, ipsec.ErrUnknownESP):
		return l2tpipsec.DropDownUnknownSA, true
	default:
		return 0, false
	}
}

// formatRemoveEvent renders an ESP association removal for the debug log.
func formatRemoveEvent(event ipsec.RemoveEvent) string {
	line := fmt.Sprintf("ipsec sa removed reason=%s peer=%v inbound_spi=%08x outbound_spi=%08x", event.Reason, event.Peer, event.InboundSPI, event.OutboundSPI)
	if event.Direction != ipsec.RemoveDirectionNone {
		line += fmt.Sprintf(" direction=%s", event.Direction)
	}
	if lifetime := event.Lifetime; lifetime != nil {
		line += fmt.Sprintf(" limit=%s", lifetime.Reason)
		if lifetime.Reason == esp.LifetimeTime {
			line += fmt.Sprintf(" age=%s lifetime=%s", lifetime.Age, lifetime.Lifetime)
		} else {
			line += fmt.Sprintf(" packets=%d bytes=%d max=%d", lifetime.Packets, lifetime.Bytes, lifetime.Limit)
		}
	}
	return line
}
