# Embedding l2tp-go

The repository is a public Go module:

```go
require github.com/eukhlg/l2tp-go <version>
```

Protocol and session code is independent from the standalone frontend:

| Package | Responsibility |
| --- | --- |
| `protocol/isakmp` | IKEv1 control plane |
| `protocol/esp` | ESP packet protection and replay checks |
| `protocol/l2tp` | L2TPv2 wire format and control state |
| `protocol/ppp` | PPP, PAP, MS-CHAPv2, and IPCP |
| `server` | Embeddable listeners, sessions, IPsec bridge, and raw IPv4 callbacks |
| `tun` | Optional native Linux/macOS TUN frontend support |
| `cmd/l2tp-go` | Standalone TOML/environment/Docker application |

## Injecting transports

Embedding applications should create and own the socket policy, then inject a
dedicated connection into the server:

```go
conn, err := net.ListenPacket("udp", ":1701")
if err != nil {
	return err
}

service, err := server.New(conn, config)
if err != nil {
	return err
}
service.SessionOpened = onSessionOpened
service.SessionClosed = onSessionClosed
service.RouteIPv4 = onIPv4

return service.Serve(ctx)
```

Equivalent injected constructors exist for IKE, NAT-T, and raw ESP:

- `server.NewIKEServer`
- `server.NewNATTServer`
- `server.NewRawESPServer`

The `Listen*` functions remain convenience constructors for the standalone
frontend.

## Packet boundary

After PPP authentication and IPCP complete, `Server.RouteIPv4` receives a
validated raw IPv4 packet. Its `server.PacketWriter` callback sends a raw IPv4
reply to that same session:

```go
service.RouteIPv4 = func(ctx context.Context, frame server.DataFrame, write server.PacketWriter) error {
	return packetStack.HandleIPv4(ctx, frame.IPv4, write)
}
```

`Server.Dispatch` makes this boundary independent of the outer transport. Raw
L2TP and protected L2TP/IPsec use the same callbacks and differ only in the
transport-specific final writer. This is the intended integration point for a
sing-box/fuzz-box endpoint and its system or userspace packet stack.

The reusable packages do not parse TOML or environment variables, create a TUN
device, install routes, configure NAT, or depend on Docker. Those responsibilities
remain in the standalone frontend or the embedding application.
