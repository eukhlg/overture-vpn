# Embedding the Overture libraries

Overture VPN is the application. Its reusable protocol runtimes live in two
independently versioned Go modules, neither of which imports the other. Both
build on netio, so packet storage is one type (`packetbuf.Buffer`) from
socket to TUN in either direction.

| Module/package | Responsibility |
| --- | --- |
| `github.com/eukhlg/l2tp-go/protocol/l2tp` | L2TPv2 wire format and control state |
| `github.com/eukhlg/l2tp-go/protocol/ppp` | PPP, PAP, MS-CHAPv2, and IPCP |
| `github.com/eukhlg/l2tp-go/server` | L2TP engine, UDP listener and netio transport, address pool, session limits, and raw IPv4 callbacks |
| `github.com/eukhlg/ipsec-go/protocol/isakmp` | IKEv1 control plane |
| `github.com/eukhlg/ipsec-go/protocol/esp` | ESP protection, replay checks, and NAT-T framing |
| `github.com/eukhlg/ipsec-go/server` | IKE/NAT-T/raw ESP listeners and association registry |
| `github.com/eukhlg/netio/packetbuf` | Exclusively owned pooled packet buffers |
| `github.com/eukhlg/netio/udptransport` | Batched UDP I/O and bounded owned sender |

## L2TP packet boundary

```go
service, err := server.New(conn, config) // dedicated net.PacketConn
if err != nil {
    return err
}
defer service.Close()
service.SessionOpened = onSessionOpened
service.SessionClosed = onSessionClosed
service.RouteIPv4 = func(ctx context.Context, frame server.DataFrame, send server.PacketWriter) error {
    return packetStack.HandleIPv4(ctx, frame.IPv4, send)
}
return service.Serve(ctx)
```

After PPP authentication and IPCP complete, `RouteIPv4` receives a validated raw
IPv4 packet. Its retained `PacketWriter` replies to the same PPP session. `Close`
closes the injected connection; shared sockets need dedicated wrappers.

## IPsec packet boundary

`ipsec-go/server.NewIKEServer`, `NewNATTServer`, and `NewRawESPServer` accept
injected packet connections. The ESP constructors take an `ESPPacketHandler`,
which returns encrypted reply datagrams and an optional post-send `Dispatch`
callback. Applications can use `ESPRegistry.Open` to authenticate and decrypt,
retain its opaque association, and call `Seal` for replies. `Replacement` follows
an overlapping rekey, while `Cookie` and `BelongsToIKE` support lifecycle cleanup.

The application must enforce its payload policy after decryption. Overture's
`internal/l2tpipsec` adapter validates UDP/1701, hands L2TP datagrams to the L2TP
engine, and closes protected sessions when their IKE owner is retired.

The libraries do not parse TOML, create TUN devices, configure routes or NAT,
or depend on Docker. Overture owns those application responsibilities.

## Existing users

The L2TP and PPP import paths are retained. IPsec imports move from
`github.com/eukhlg/l2tp-go` to `github.com/eukhlg/ipsec-go`. The former combined
`server.ESPBridge` is application integration and now belongs to Overture.
The `tun` package moves to `github.com/eukhlg/overture-vpn/tun`.
