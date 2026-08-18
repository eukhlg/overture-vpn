# l2tp-go

A lightweight Go L2TPv2 server under active development. The current server
supports raw (unencrypted) L2TP, PPP LCP, MS-CHAPv2 and PAP authentication,
IPCP, IPv4, and a native TUN data path on Linux and macOS.

The protocol and server packages are also usable as a public Go module. Network
frontends can inject their own packet connections and consume authenticated
sessions as raw IPv4 packet streams without enabling TUN or host routing. See
[Embedding l2tp-go](EMBEDDING.md).

## IPsec status

The server includes an experimental IKEv1/IPsec implementation for protecting
L2TP traffic on Linux. It has been successfully tested with the built-in
L2TP/IPsec clients on Windows, Linux, and macOS using pre-shared-key
authentication.

The implementation is functional but has not undergone an independent security
audit or extensive production-scale testing. It is suitable for interoperability
testing and controlled deployments, but should not yet be treated as a
production security boundary.

<details>
<summary>IPsec capabilities and current limitations</summary>

### Supported capabilities

- IKEv1 Main Mode responder with pre-shared-key authentication
- IKEv1 Quick Mode
- AES-128/192/256-CBC and 3DES-CBC encryption
- SHA-1 and SHA-256 for IKE Phase 1
- Diffie-Hellman groups 2 and 14
- ESP transport mode with AES or 3DES
- HMAC-SHA1-96 ESP authentication
- RFC 3947/3948 NAT traversal over UDP port 4500
- IPv4 address, subnet, and range traffic selectors
- NAT Original Address payloads
- ESP anti-replay protection
- IKE and ESP lifetimes
- RFC 3706 Dead Peer Detection
- Authenticated IKE and ESP deletion
- Client-initiated Quick Mode rekeying with overlapping ESP associations
- Raw ESP transport for native Linux deployments
- Protected L2TP handoff restricted to authenticated UDP port 1701 traffic

The implementation intentionally rejects obsolete DH group 1 and MD5-based
transforms.

### Current limitations

- No Phase 2 Perfect Forward Secrecy
- No server-initiated IKE (Phase 1) rekeying
- No IKE fragmentation
- No IPsec tunnel mode
- No arbitrary protected protocols
- No L2TPv3 or EtherIP site-to-site operation
- No RADIUS, Active Directory, or NT-domain authentication
- No independently verified iOS or Android interoperability
- Limited long-duration, high-load, malformed-traffic, and denial-of-service
  testing
- No independent security audit

### Protocol behavior

Main Mode preserves the initiator's exact SA bytes for `HASH_I` and `HASH_R`,
validates proposal attributes, requires explicit AES key lengths, caches
byte-identical replies for retransmissions, and clears sensitive exchange state
after failure or expiry. It recognizes common Microsoft, DPD, and NAT-T vendor
identifiers. RFC 3947 NAT detection enables authenticated migration to UDP port
4500 when NAT is detected or NAT-T is explicitly preferred.

Quick Mode validates `HASH(1)` and `HASH(3)`, generates selector-bound `HASH(2)`,
derives independent inbound and outbound ESP key material, and installs an ESP
pair only after the initiator's final confirmation. Phase 2 proposals requesting
PFS are rejected until Quick Mode key exchange support is implemented.

Authenticated informational exchanges process Dead Peer Detection and IKE/ESP
deletion messages. Proactive DPD probes retire a peer after three missed
intervals. Client-initiated rekeys retain the previous ESP association during
transition and automatically move active L2TP flows to the replacement
association. Graceful server shutdown sends encrypted IKE deletion messages
before closing the IKE and NAT-T listeners.

</details>

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

The single Compose service publishes UDP 1701, UDP 500, and UDP 4500; grants
`NET_ADMIN` and `NET_RAW`; mounts
`/dev/net/tun`, enables IPv4 forwarding in the container namespace, and
masquerades the configured client subnet through the interface selected by the
container's IPv4 default route. `L2TP_NAT_INTERFACE` remains available as an
explicit override.

Docker cannot publish raw IP protocol 50 through a UDP/TCP port mapping. The
default container therefore uses forced NAT-T for interoperable IPsec. Native
Linux deployments may still use raw ESP. Set a real public server identity and
PSK in `.env`, then start the same Compose service:

```sh
L2TP_IPSEC_PSK='replace-this' \
L2TP_IPSEC_SERVER_ID='203.0.113.10' \
docker compose up --build -d
```

Docker Desktop cannot provide the raw-ESP path, but UDP/4500 NAT-T remains the
supported container path.

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
passwords, protect the file, and point the consolidated Compose service at it:

```sh
cp l2tp-go.toml.example l2tp-go.toml
chmod 600 l2tp-go.toml
L2TP_CONFIG_FILE=./l2tp-go.toml \
L2TP_CONFIG=/etc/l2tp-go/server.toml \
docker compose up --build -d
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
| `L2TP_DEBUG` | `0` | Debug level: `0` off, `1` protocol/lifecycle, `2` per-packet tracing |
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
| `L2TP_IPSEC_ENABLED` | `false` | Enable experimental IKEv1 with raw ESP and NAT-T transport |
| `L2TP_IPSEC_IKE_LISTEN` | `:500` | IKEv1 UDP listen address |
| `L2TP_IPSEC_NATT_LISTEN` | `:4500` | Shared NAT-T IKE/ESP listen address |
| `L2TP_IPSEC_ESP_LISTEN` | `0.0.0.0` | Raw ESP local IPv4 address |
| `L2TP_IPSEC_PSK` | empty | IKEv1 pre-shared key |
| `L2TP_IPSEC_SERVER_ID` | empty | Public IPv4 identity used by IKE |
| `L2TP_IPSEC_MAX_SAS` | `1024` | Maximum simultaneous Phase 1 SAs |
| `L2TP_IPSEC_FORCE_NATT` | `false` | Prefer UDP/4500 for NAT-T-capable clients even when NAT-D finds no NAT |
| `L2TP_IPSEC_IKE_LIFETIME` | `8h` | Server maximum Phase 1 lifetime |
| `L2TP_IPSEC_ESP_LIFETIME` | `1h` | Server maximum ESP lifetime |
| `L2TP_IPSEC_DPD_INTERVAL` | `20s` | Proactive DPD interval; `0s` disables probes |
| `L2TP_IPSEC_MAX_HALF_OPEN` | `128` | Maximum incomplete Main Mode exchanges |
| `L2TP_IPSEC_MAX_SA_PER_PEER` | `4` | Maximum Phase 1 SAs for one client IP |

Both address settings accept a full IPv4 address or a host offset. For example,
subnet `10.0.0.0/24`, server `1`, start `100`, and limit `50` produce server
`10.0.0.1` and leases `10.0.0.100` through `10.0.0.149`. `L2TP_CLIENT_IP` is
accepted as a deprecated single-client pool-start alias. The proposed
`L2TP_CLIENT_SUBNET_START` and `L2TP_CLIENT_SUBNET_LIMIT` names are also
accepted as compatibility aliases.

## Client settings

For protected operation, configure a client for L2TP/IPsec with a pre-shared
key, the server's public IPv4 address, and MS-CHAPv2 PPP authentication. Permit
UDP 500 and UDP 4500 through host and cloud firewalls; permit IP protocol 50
for clients that do not need NAT traversal.

For raw test operation, configure a client for L2TP without IPsec, with MS-CHAPv2 authentication (or
PAP when `L2TP_AUTH=pap`), UDP port 1701, and the username/password from the environment. Many operating-system
VPN user interfaces require IPsec for L2TP and will not offer raw L2TP; use a
client such as `xl2tpd`/`pppd` that explicitly permits raw L2TP.

Successful startup does not prove that UDP 1701 is reachable from outside the
host. Verify host and cloud firewalls separately.

## Interoperability test matrix

Run tests with `L2TP_DEBUG=1` and forced NAT-T first. Test the Windows
built-in L2TP/IPsec client, NetworkManager-l2tp on Linux, and the macOS built-in
L2TP over IPsec profile where available. Each client should be tested from a
different NATed network and, when possible, from a directly addressed host.

For every platform verify: Main Mode and Quick Mode completion, UDP/4500
migration, PPP authentication, assigned address and DNS, traffic through TUN,
DPD acknowledgement, an hour-bound client-initiated rekey, manual disconnect,
container restart/reconnect, and two simultaneous users. Capture the server
side with:

```sh
docker compose logs -f --since=5s --no-color l2tp 2>&1 | tee l2tp-ipsec.log
```

If negotiation stops, preserve the complete log from the first `ike rx` line
through the rejection. The trace deliberately omits PSKs, passwords, key
material, and decrypted traffic, so it is suitable for interoperability bug
reports after reviewing public IP addresses.

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
L2TP_DEBUG=1
```

Then recreate the container and follow its output:

```sh
docker compose up -d --force-recreate
docker compose logs -f --tail=200 l2tp
```

Debug level 1 records IKE cookies/exchanges and
state, proposal selection, NAT-D and migration decisions, Quick Mode SPIs and
lifetimes, authentication, DPD sequences, ESP rejection reasons, connections,
disconnections, and lifecycle events. Stable prefixes include `DEBUG ike`, `DEBUG natt`, `DEBUG quick`,
`DEBUG esp`, and `DEBUG ipsec lifecycle`. It does not record PSKs, passwords,
DH private values, derived keys, authentication responses, or plaintext packet
payloads. Level 2 additionally emits `TRACE` entries for every ESP, L2TP, PPP,
and IPv4 packet and should be enabled only for short captures because it can
produce logs faster than Docker can display them.

Successful PPP session events are always written to standard output at every
debug level. Each connect/disconnect line includes the authenticated username,
assigned VPN address, transport (`l2tp` or `l2tp/ipsec`), peer address, tunnel
ID, and session ID. Sessions that fail before authentication and IPCP open do
not produce a misleading connected/disconnected pair.

## Tests

```sh
go test ./...
go test -race ./...
```

Native TUN creation is an opt-in privileged integration test:

```sh
sudo go test -tags=integration ./tun -run TestOpenNativeDevice -v
```
