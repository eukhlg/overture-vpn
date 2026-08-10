# l2tp-go

A lightweight Go L2TPv2 server under active development. The current server
supports raw (unencrypted) L2TP, PPP LCP, MS-CHAPv2 and PAP authentication,
IPCP, IPv4, and a native TUN data path on Linux and macOS.

Experimental IKEv1 PSK and raw ESP transport mode can now protect L2TP on
Linux. It includes Main Mode, Quick Mode, DH2/DH14, AES-CBC or 3DES-CBC,
HMAC-SHA1-96, anti-replay, and SA limits. It is disabled by default and is not
yet a production security boundary: NAT detection, IKE fragmentation, DPD,
rekeying, UDP/4500 migration, and external-client interoperability testing are
still pending. Raw L2TP remains available for controlled test networks.

The Main Mode responder uses PSK authentication, preserves the initiator's
exact SA bytes for `HASH_I`/`HASH_R`, accepts paired seconds/kilobytes lifetime
attributes, requires explicit AES key lengths, caches byte-identical replies
for retransmissions, and clears sensitive state after failure or expiry. It
recognizes common Microsoft, DPD, and NAT-T vendor IDs and implements RFC 3947
NAT-D calculations, but does not advertise or activate NAT-T migration yet.

The current release supports multiple users and automatically leases client
addresses from a configured IPv4 pool.

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

The default Compose service publishes UDP 1701, grants only `NET_ADMIN`, mounts
`/dev/net/tun`, enables IPv4 forwarding in the container namespace, and
masquerades the configured client subnet through the interface selected by the
container's IPv4 default route. `L2TP_NAT_INTERFACE` remains available as an
explicit override.

Experimental raw ESP requires Linux host networking because Docker cannot
publish IP protocol 50 through a UDP/TCP port mapping. Set a real public server
identity and PSK, then apply the IPsec override:

```sh
L2TP_IPSEC_PSK='replace-this' \
L2TP_IPSEC_SERVER_ID='203.0.113.10' \
docker compose -f docker-compose.yml -f docker-compose.ipsec.yml up --build -d
```

This override adds `NET_RAW` and removes published ports because host
networking binds UDP 500, UDP 1701, and raw ESP directly on the Linux host.
Docker Desktop cannot provide this raw-ESP path.

During a normal Compose restart or stop, the server sends `StopCCN` to every
active tunnel before closing UDP. Clients configured for automatic reconnect
can therefore start a fresh tunnel promptly. An ungraceful process kill, host
failure, or lost network cannot send this notification, so recovery time then
depends on the client's own dead-peer timeout.

Stop and remove it with:

```sh
docker compose down
```

To use a TOML file instead of `.env`, copy the complete example, edit the
passwords, protect the file, and start Compose with its override:

```sh
cp l2tp-go.toml.example l2tp-go.toml
chmod 600 l2tp-go.toml
docker compose -f docker-compose.yml -f docker-compose.toml.yml up --build -d
```

The override mounts `l2tp-go.toml` read-only at
`/etc/l2tp-go/server.toml`. Docker NAT uses the resolved `[network]` and
`[nat]` values from that same file.

## Run with TUN routing

Build the server:

```sh
go build -o l2tp-go ./cmd/l2tp-go
```

Settings may be supplied through TOML, environment variables, or command-line
flags. Precedence is: built-in defaults, TOML, environment, then flags.

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

The recommended starting point is [l2tp-go.toml.example](l2tp-go.toml.example).
Run it natively with:

```sh
sudo ./l2tp-go --config ./l2tp-go.toml
```

The configuration is strict: unknown TOML keys and invalid values stop startup
with a descriptive error. User credentials are ordinary TOML values for now:

```toml
[authentication]
method = "mschapv2"

[[authentication.users]]
username = "alice"
password = "replace-me"

[[authentication.users]]
username = "bob"
password = "replace-me-too"
```

Keep the real file out of source control and readable only by its owner. The
existing environment variables remain supported for compatibility and for
temporary overrides:

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
| `L2TP_NAT_ENABLED` | `true` | Enable container NAT |
| `L2TP_NAT_INTERFACE` | automatic | Docker outbound-interface override |
| `L2TP_MAX_SESSIONS` | `50` | Global simultaneous-session limit |
| `L2TP_MAX_SESSIONS_PER_TUNNEL` | `1` | Simultaneous sessions in one L2TP tunnel |
| `L2TP_MAX_SESSIONS_PER_USER` | `1` | Authenticated sessions for one username |
| `L2TP_IPSEC_ENABLED` | `false` | Enable experimental IKEv1 and raw ESP transport |
| `L2TP_IPSEC_IKE_LISTEN` | `:500` | IKEv1 UDP listen address |
| `L2TP_IPSEC_ESP_LISTEN` | `0.0.0.0` | Raw ESP local IPv4 address |
| `L2TP_IPSEC_PSK` | empty | IKEv1 pre-shared key |
| `L2TP_IPSEC_SERVER_ID` | empty | Public IPv4 identity used by IKE |
| `L2TP_IPSEC_MAX_SAS` | `1024` | Maximum simultaneous Phase 1 SAs |

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
