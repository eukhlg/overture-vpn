# l2tp-go

A lightweight Go L2TPv2 server under active development. The current server
supports raw (unencrypted) L2TP, PPP LCP, MS-CHAPv2 and PAP authentication,
IPCP, IPv4, and a native TUN data path on Linux and macOS.

IPsec is not implemented yet. PAP sends credentials without encryption, and
MS-CHAPv2 is vulnerable to offline password attacks; all user traffic remains
unencrypted. Use this release only on a trusted test network or behind another
secure transport.

The current release supports one connected client using a fixed IPv4 address.

## Docker Compose

Docker deployment is intended for a Linux Docker host with `/dev/net/tun`.
Docker Desktop on macOS does not expose a macOS `utun` device to Linux
containers; use the native macOS instructions below instead.

Create the environment file and change the password:

```sh
cp .env.example .env
```

Start the ready-to-route server:

```sh
docker compose up --build -d
docker compose logs -f l2tp
```

The Compose service publishes UDP 1701, grants only `NET_ADMIN`, mounts
`/dev/net/tun`, enables IPv4 forwarding in the container namespace, and
masquerades the configured client subnet through the interface selected by the
container's IPv4 default route. `L2TP_NAT_INTERFACE` remains available as an
explicit override.

Stop and remove it with:

```sh
docker compose down
```

## Run with TUN routing

Build the server:

```sh
go build -o l2tp-go ./cmd/l2tp-go
```

All settings may be supplied through environment variables. Command-line flags
remain available and take precedence over environment defaults.

```sh
export L2TP_PASSWORD='replace-me'
export L2TP_USERNAME='vpn'
export L2TP_TUN_ENABLED='true'
```

Linux:

```sh
sudo -E ./l2tp-go \
  -tun-name l2tp0
```

macOS (`-tun-name` may be omitted to select an available `utun`):

```sh
sudo -E ./l2tp-go \
  -tun-name ''
```

The process creates the native interface, configures its address and MTU,
forwards client packets into it, reads return packets, and sends those packets
back through the matching PPP session. It brings the interface down during a
clean shutdown.

Native execution does not modify host IP forwarding or NAT. Configure those
with the host firewall/router policy appropriate for the machine. The Docker
entrypoint performs container-local NAT when `L2TP_NAT_ENABLED=true`.

## Configuration

| Environment variable | Default | Purpose |
|---|---:|---|
| `L2TP_PASSWORD` | required unless `L2TP_USERS` is set | Password for the legacy single user |
| `L2TP_USERNAME` | `vpn` | Username for the legacy single user |
| `L2TP_USERS` | empty | Comma-separated `username=password` credentials |
| `L2TP_AUTH` | `mschapv2` | PPP authentication: `mschapv2` or `pap` |
| `L2TP_DEBUG` | `false` | Enable sanitized protocol tracing |
| `L2TP_LISTEN` | `:1701` | UDP listen address |
| `L2TP_HOSTNAME` | `l2tp-go` | Advertised L2TP host name |
| `L2TP_CLIENT_SUBNET` | `10.0.0.0/24` | PPP client subnet and Docker NAT source |
| `L2TP_SERVER_IP` | `1` | Server address or host offset inside the client subnet |
| `L2TP_CLIENT_POOL_START` | `2` | First pool address or host offset |
| `L2TP_CLIENT_POOL_SIZE` | `50` | Number of addresses in the client pool |
| `L2TP_DNS` | `1.1.1.1` | DNS address offered through IPCP |
| `L2TP_TUN_ENABLED` | `false` | Enable native TUN routing |
| `L2TP_TUN_NAME` | automatic | Requested TUN interface name |
| `L2TP_MTU` | `1400` | TUN MTU |
| `L2TP_NAT_ENABLED` | `true` in Docker | Enable container NAT |
| `L2TP_NAT_INTERFACE` | automatic | Docker outbound-interface override |
| `L2TP_MAX_SESSIONS` | pool size | Global simultaneous-session limit |
| `L2TP_MAX_SESSIONS_PER_TUNNEL` | `1` | Simultaneous sessions in one L2TP tunnel |
| `L2TP_MAX_SESSIONS_PER_USER` | `1` | Authenticated sessions for one username |

Both address settings accept a full IPv4 address or a host offset. For example,
subnet `10.0.0.0/24`, server `1`, start `100`, and limit `50` produce server
`10.0.0.1` and leases `10.0.0.100` through `10.0.0.149`. `L2TP_CLIENT_IP` is
accepted as a deprecated single-client pool-start alias. The proposed
`L2TP_CLIENT_SUBNET_START` and `L2TP_CLIENT_SUBNET_LIMIT` names are also
accepted as compatibility aliases.

## Client settings

Configure a client for L2TP without IPsec, with MS-CHAPv2 authentication (or
PAP when `L2TP_AUTH=pap`), UDP port 1701, and the username/password from the environment. Many operating-system
VPN user interfaces require IPsec for L2TP and will not offer raw L2TP; use a
client such as `xl2tpd`/`pppd` that explicitly permits raw L2TP.

Successful startup does not prove that UDP 1701 is reachable from outside the
host. Verify host and cloud firewalls separately.

## Troubleshooting

If Compose restarts the container, inspect both its status and previous logs:

```sh
docker compose ps
docker compose logs --tail=200 l2tp
docker inspect --format '{{.State.ExitCode}} {{.State.Error}}' l2tp-go-l2tp-1
```

IPv6 and packets without an active PPP destination may appear on TUN. They are
dropped without stopping the server. A fatal listener or TUN error is logged
with the component name before the process exits.

For connection negotiation failures, enable tracing in `.env`:

```env
L2TP_DEBUG=true
```

Then recreate the container and follow its output:

```sh
docker compose up -d --force-recreate
docker compose logs -f --tail=200 l2tp
```

Debug mode records peer addresses, message types, tunnel/session identifiers,
sequence numbers, PPP protocols and phase transitions. It does not record
passwords, authentication responses, or packet payloads.

## Tests

```sh
go test ./...
go test -race ./...
```

Native TUN creation is an opt-in privileged integration test:

```sh
sudo go test -tags=integration ./tun -run TestOpenNativeDevice -v
```
