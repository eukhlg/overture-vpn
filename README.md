# l2tp-go

A lightweight Go L2TPv2 server under active development. The current server
supports raw (unencrypted) L2TP, PPP LCP, PAP authentication, IPCP, IPv4, and a
native TUN data path on Linux and macOS.

IPsec is not implemented yet. PAP credentials and all traffic are exposed on
the network when the server is used without IPsec. Use this release only on a
trusted test network or behind another secure transport.

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
masquerades the configured client subnet through `L2TP_NAT_INTERFACE`.

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
| `L2TP_PASSWORD` | required | PAP password |
| `L2TP_USERNAME` | `vpn` | PAP username |
| `L2TP_LISTEN` | `:1701` | UDP listen address |
| `L2TP_HOSTNAME` | `l2tp-go` | Advertised L2TP host name |
| `L2TP_SERVER_IP` | `10.0.0.1` | Server-side PPP address |
| `L2TP_CLIENT_IP` | `10.0.0.2` | Address assigned to the client |
| `L2TP_DNS` | `1.1.1.1` | DNS address offered through IPCP |
| `L2TP_TUN_ENABLED` | `false` | Enable native TUN routing |
| `L2TP_TUN_NAME` | automatic | Requested TUN interface name |
| `L2TP_TUN_PREFIX` | `10.0.0.1/24` | Address/prefix configured on TUN |
| `L2TP_MTU` | `1400` | TUN MTU |
| `L2TP_NAT_ENABLED` | `true` in Docker | Enable container NAT |
| `L2TP_CLIENT_SUBNET` | `10.0.0.0/24` | Docker NAT source subnet |
| `L2TP_NAT_INTERFACE` | `eth0` | Docker outbound interface |

## Client settings

Configure a client for L2TP without IPsec, with PAP authentication, UDP port
1701, and the username/password from the environment. Many operating-system
VPN user interfaces require IPsec for L2TP and will not offer raw L2TP; use a
client such as `xl2tpd`/`pppd` that explicitly permits raw L2TP and PAP.

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

## Tests

```sh
go test ./...
go test -race ./...
```

Native TUN creation is an opt-in privileged integration test:

```sh
sudo go test -tags=integration ./tun -run TestOpenNativeDevice -v
```
