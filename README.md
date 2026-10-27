# Overture VPN

A lightweight Go L2TPv2 server. The current server
supports raw (unencrypted) L2TP, PPP LCP, MS-CHAPv2 and PAP authentication,
IPCP, IPv4, and a native TUN data path on Linux and macOS.

Overture uses three independent Go modules:

- [l2tp-go](https://github.com/eukhlg/l2tp-go): L2TPv2, PPP, and the embeddable session engine
- [ipsec-go](https://github.com/eukhlg/ipsec-go): IKEv1, ESP, NAT-T, and association lifecycle
- [netio](https://github.com/eukhlg/netio): pooled packet buffers and batched UDP I/O shared by both data paths

The application owns configuration, the protected L2TP adapter, native TUN
routing, and deployment. See [embedding and architecture](EMBEDDING.md) and the
[repository and registry migration](migration/README.md).

The server can be started with `overture-vpn server`; flag-only invocations are
also supported. Client mode is planned and is not implemented yet.

## IPsec status

The server includes an IKEv1/IPsec implementation that has been successfully
tested with the built-in L2TP/IPsec clients on Windows, Linux, and macOS using
pre-shared-key authentication.

The implementation is functional but has not undergone an independent security
audit or extensive production-scale testing. It is suitable for interoperability
testing and controlled deployments, but should not yet be treated as a
production security boundary.

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
- Client-initiated Phase 1 replacement with child-SA ownership transfer
- Raw ESP transport for native Linux deployments
- Protected L2TP handoff restricted to authenticated UDP port 1701 traffic

<details>
<summary>Current limitations and protocol behavior</summary>

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
intervals. Client-initiated Quick Mode rekeys retain the previous ESP
association during transition and automatically move active L2TP flows to the
replacement association. Server-initiated Quick Mode is limited to three
attempts with increasing delays; after that, the working child SA is retained
while still valid and the server waits for a peer-initiated rekey. An established
Phase 1 lifetime is a soft boundary:
the responder keeps the working IKE SA until the client opens a replacement Main
Mode SA. It transfers the existing child SA to the replacement without changing
its SPIs, keys, sequence state, or remaining lifetime. Later Quick Mode rekeying
remains independent of the Phase 1 switch. The server does not originate Main
Mode, so server-initiated Phase 1 rekeying remains a limitation. Graceful server
shutdown sends encrypted IKE deletion messages before closing the IKE and NAT-T
listeners.

</details>

## Configuration

The current release supports multiple users and automatically leases client
addresses from a configured IPv4 pool.

The recommended starting point is [overture-vpn.toml.example](overture-vpn.toml.example).
Run it natively with:

```sh
sudo ./overture-vpn server --config ./overture-vpn.toml
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

IPsec ESP receive workers default to `clamp(GOMAXPROCS/3, 1, 4)` when
`[ipsec].receive_workers` is omitted. This gives one worker on 1–5 CPUs, two
on 6–8, three on 9–11, and four on 12 or more. Set `receive_workers` or
`L2TP_IPSEC_RECEIVE_WORKERS` to choose an explicit value; the environment
variable overrides TOML. Values 0 and 1 select serial processing, and values
through 64 are accepted. Startup logs the effective count and its source.

`[ipsec].receive_buffer` (`L2TP_IPSEC_RECEIVE_BUFFER`) requests a receive
buffer in bytes for each NAT-T and raw ESP listener. The default is 1048576
(1 MiB; Linux reports 2 MiB effective); set `0` to keep the kernel setting. Values through 1073741823 bytes
are accepted. Positive values set `SO_RCVBUF`, then on Linux attempt
`SO_RCVBUFFORCE` with `CAP_NET_ADMIN`. Startup logs the requested and effective
bytes and `forced`; Linux reports twice the request. A cap warning suggests
granting `CAP_NET_ADMIN` or raising `net.core.rmem_max`. Send buffers are unchanged.
`[ipsec].udp_batch` (`L2TP_IPSEC_UDP_BATCH`) sets NAT-T receive
batches from 1 to 256, default 128. `[ipsec].udp_send_batch`
(`L2TP_IPSEC_UDP_SEND_BATCH`) independently sets the ESP sender batch, default 128.
Metadata is allocated once at startup.

`[ipsec].udp_gso` (`L2TP_IPSEC_UDP_GSO`, default true) enables Linux UDP
send segmentation for NAT-T. Unsupported sockets use ordinary batched sends;
a segmentation error disables GSO for that connection and retries unsent packets.
GRO remains disabled: the VPS comparison showed no gain beyond the trial spread.
Startup logs the active GSO/GRO state.

Plain L2TP uses a bounded, ordered receive/process/flush pipeline by default.
Set `[l2tp] pipeline = false` or `L2TP_PIPELINE=false` to use synchronous
receive and delivery. The effective setting is logged once at startup. Queues
hold at most two read batches each; a slow TUN write applies backpressure to
socket reads. Session identity and route bindings are checked again at flush.

The plain UDP/1701 listener has independent `[l2tp].receive_buffer`
(`L2TP_RECEIVE_BUFFER`) and `[l2tp].udp_batch` (`L2TP_UDP_BATCH`) settings,
with defaults 1048576 (1 MiB requested; Linux reports 2 MiB effective) and 128;
0 keeps the kernel receive buffer. With the receive pipeline, plain upload in the
`plain-pipeline-2026-10-27` VPS run rose from about 1.9 to 3.2 Gbit/s (P1) as
upload drops disappeared, while loaded upload ping p95 rose from 0.97 to 1.75 ms.
The same size limits and
startup logging apply. `[l2tp].udp_gso` (`L2TP_UDP_GSO`, default true) controls
send segmentation for reverse ACKs and download on this listener. These options also affect UDP/1701 when IPsec is enabled.

A larger receive buffer can improve throughput and reduce drops, but increases
queueing delay under saturation. In the socket-tuning VPS run at batch 128,
a 256 KiB request improved mean one-stream NAT-T upload from 592 to 791 Mbit/s,
while loaded p95 rose from 2.48 to 4.39 ms. With the faster receive path of
`download-path-2026-10-27`, 1 MiB instead of 256 KiB raised NAT-T upload from
1147 to 1213 Mbit/s (one stream, drops 621 to 0) and from 977 to 1157 Mbit/s
(four streams, drops 14,471 to 2,344); loaded upload ping p50 stayed at 0.6 ms
with one stream and rose from 2.3 to 6.8 ms with four. Choose 262144 or `0`
when lower loaded delay matters more. Batch 128 gained 3.3% in
geometric mean across the matrix; it retains more receive storage than 32.
These are short same-host VPS results, not a universal capacity guarantee.

Server and pool-start settings accept either a full IPv4 address or a host
offset within the subnet. For example, subnet `10.0.0.0/24`, server address
`1`, pool start `100`, and pool size `50` produce server `10.0.0.1` and leases
`10.0.0.100` through `10.0.0.149`.

```toml
[network]
subnet = "10.0.0.0/24"
server_address = "1"
client_pool_start = "2"
client_pool_size = 50
dns = "1.1.1.1"
mtu = 1400

[limits]
# Per source IP; set the rate to 0 to disable new-tunnel throttling.
new_tunnels_per_second = 5
new_tunnel_burst = 10
```

New L2TP tunnel requests are limited with a per-source-IP token bucket. The
default permits a burst of 10 new tunnels and refills at 5 tunnels per second;
retransmissions belonging to an existing half-open tunnel do not consume
additional capacity. Limiter source bookkeeping is bounded to resist spoofed
source-address churn.

Keep the real file out of source control and readable only by its owner. `OVERTURE_CONFIG` selects a configuration file; `L2TP_CONFIG` is its legacy
fallback, and an explicit `--config` takes precedence. Legacy
environment-variable overrides remain available for compatibility, but TOML is
the primary and recommended configuration source.

## Docker Compose

Docker deployment is intended for a Linux Docker host with `/dev/net/tun`.
Docker Desktop on macOS does not expose a macOS `utun` device to Linux
containers; use the native macOS instructions below instead.

Multi-platform images for `linux/amd64` and `linux/arm64` are published to both
registries:

- `eukhlg/overture-vpn` on Docker Hub
- `ghcr.io/eukhlg/overture-vpn` on GitHub Container Registry

During the naming transition, the same compatible builds are also published as
`eukhlg/l2tp-go` and `ghcr.io/eukhlg/l2tp-go`. Existing `L2TP_CONFIG`,
`L2TP_IMAGE`, `L2TP_CONFIG_FILE`, and `/etc/l2tp-go/server.toml` mounts remain
supported. The new Compose variables take precedence when set. Existing
versioned image tags are retained.

Use `latest` for releases and `testing` for the newest feature-branch build.
Copy the example configuration, set the PSK, server identity, and user
passwords, then start the released image:

```sh
cp overture-vpn.toml.example overture-vpn.toml
chmod 600 overture-vpn.toml
docker compose pull
docker compose up -d
docker compose logs -f l2tp
```

To test the newest feature-branch image or use GHCR instead, select the image
before pulling:

```sh
export OVERTURE_IMAGE=eukhlg/overture-vpn:testing
# Or: export OVERTURE_IMAGE=ghcr.io/eukhlg/overture-vpn:testing
docker compose pull
docker compose up -d
```

For a local source build, bypass the registry with:

```sh
docker compose build
docker compose up -d
```

To keep the configuration at another path, set the Compose-only
`OVERTURE_CONFIG_FILE` variable:

```sh
OVERTURE_CONFIG_FILE=/srv/l2tp/server.toml docker compose up -d
```

Compose publishes UDP ports 1701, 500, and 4500, grants `NET_ADMIN` and
`NET_RAW`, mounts `/dev/net/tun`, and enables container-local forwarding and
NAT. Docker port publishing cannot expose raw IP protocol 50, so containers use
UDP/4500 NAT-T; native Linux deployments may use raw ESP. A graceful stop sends
`StopCCN` to active tunnels before shutdown.

Stop and remove the service with `docker compose down`.

## Run with TUN routing

Build the server (after the library releases are published, or with the local
workspace described in the migration guide):

```sh
go build -o overture-vpn ./cmd/overture-vpn
```

Set `[tun].enabled = true` in the TOML configuration. Command-line flags can
override TOML when needed.

```sh
sudo ./overture-vpn server --config ./overture-vpn.toml
```

macOS (`-tun-name` may be omitted to select an available `utun`):

```sh
sudo ./overture-vpn server --config ./overture-vpn.toml \
  -tun-name ''
```

The process creates the native interface, configures its address and MTU,
forwards client packets into it, reads return packets, and sends those packets
back through the matching PPP session. It brings the interface down during a
clean shutdown.

`[tun].tx_queue_length` (`L2TP_TUN_TX_QUEUE_LENGTH`, Linux) sets the
interface transmit queue, which the TUN driver uses as its ring of packets
waiting for the server to read. `0` (default) selects 64 when offload is
active and keeps the kernel setting (usually 500) otherwise. With offload each
entry can hold a 64 KB super-packet, and the driver drops at a full ring rather
than pushing back into the qdisc, so a long ring holds TCP's excess window as
download delay that no qdisc can manage. In the `download-path-2026-10-27` VPS
run, 64 entries cut loaded download ping p50 from 9.6 to 5.2 ms (one stream)
and from 37.8 to 4.0 ms (four streams) at unchanged throughput. Startup logs
the effective length.

Native execution does not modify host IP forwarding or NAT. Configure those
with the host firewall/router policy appropriate for the machine. The Docker
entrypoint performs container-local NAT when `[nat].enabled = true`.

## Client settings

For protected operation, configure a client for L2TP/IPsec with a pre-shared
key, the server's public IPv4 address, and MS-CHAPv2 PPP authentication. Permit
UDP 500 and UDP 4500 through host and cloud firewalls; permit IP protocol 50
for clients that do not need NAT traversal.

For raw test operation, configure a client for L2TP without IPsec, with
MS-CHAPv2 authentication (or PAP when `[authentication].method = "pap"`), UDP
port 1701, and the configured username and password. Many operating-system VPN
interfaces require IPsec for L2TP and will not offer raw L2TP; use a client
such as `xl2tpd`/`pppd` that explicitly permits raw L2TP.

Successful startup does not prove that UDP 1701 is reachable from outside the
host. Verify host and cloud firewalls separately.

## Interoperability test matrix

Run tests with `[server].debug = 1` and `[ipsec].force_natt = true` first. Test
the Windows built-in L2TP/IPsec client, NetworkManager-l2tp on Linux, and the
macOS built-in L2TP over IPsec profile where available. Each client should be
tested from a different NATed network and, when possible, from a directly
addressed host.

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
docker inspect --format '{{.State.ExitCode}} {{.State.Error}}' overture-vpn-l2tp-1
```

IPv6 and packets without an active PPP destination may appear on TUN. They are
dropped without stopping the server. A fatal listener or TUN error is logged
with the component name before the process exits.

For connection negotiation failures, enable tracing in the TOML configuration:

```toml
[server]
debug = 1
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
