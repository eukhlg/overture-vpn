package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"l2tp-go/protocol/isakmp"
	"l2tp-go/server"
)

type ipsecRuntime struct {
	ike  *server.IKEServer
	esp  *server.ESPTransportServer
	done chan error
}

func startIPsec(ctx context.Context, config appConfig, l2tpServer *server.Server) (*ipsecRuntime, error) {
	identityIP := net.ParseIP(config.IPsec.ServerID).To4()
	ike, err := server.ListenIKE(config.IPsec.IKEListen, isakmp.ControlPlaneConfig{PreSharedKey: []byte(config.IPsec.PreSharedKey), ResponderID: isakmp.Identification{IDType: isakmp.IDIPv4Address, ProtocolID: 17, Port: 500, Data: identityIP}, MaxPhase1SAs: config.IPsec.MaxSAs})
	if err != nil {
		return nil, fmt.Errorf("listen IKE: %w", err)
	}
	registry := server.NewESPRegistry()
	bridge, err := server.NewESPBridge(l2tpServer.Engine, registry)
	if err != nil {
		_ = ike.Close()
		return nil, err
	}
	raw, err := server.ListenRawESP(config.IPsec.ESPListen, bridge)
	if err != nil {
		_ = ike.Close()
		return nil, fmt.Errorf("listen raw ESP: %w", err)
	}
	ike.Established = func(_ context.Context, peer net.Addr, pair isakmp.ESPPair) {
		if err := registry.Install(peer, pair); err != nil {
			log.Printf("IPsec SA install failed: peer=%s error=%v", peer, err)
			return
		}
		log.Printf("IPsec ESP SA established: peer=%s inbound_spi=%08x outbound_spi=%08x", peer, pair.Inbound.SPI, pair.Outbound.SPI)
	}
	send := func(datagram server.ESPDatagram) error {
		peer := datagram.Peer
		if udp, ok := peer.(*net.UDPAddr); ok {
			peer = &net.IPAddr{IP: udp.IP}
		}
		_, err := raw.Conn.WriteTo(datagram.Payload, peer)
		return err
	}
	raw.HandleResult = func(callbackContext context.Context, result server.ESPBridgeResult) error {
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
	runtime := &ipsecRuntime{ike: ike, esp: raw, done: make(chan error, 2)}
	go func() { runtime.done <- ike.Serve(ctx) }()
	go func() { runtime.done <- raw.Serve(ctx) }()
	return runtime, nil
}

func (r *ipsecRuntime) Close() {
	if r == nil {
		return
	}
	_ = r.ike.Close()
	_ = r.esp.Close()
}
