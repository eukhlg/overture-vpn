# UDP message batching — 20 October 2026

Implemented in the app and ipsec-go on `codex/udp-batching`, based on app
`4577364a60409185ee926b40aab0b24b2458161e` and ipsec-go
`feee1956200eb146d490ff53eb254cf94b8c7735`. l2tp-go is unchanged.
No merge or dependency publication was performed. Standalone app builds require
the matching local ipsec-go checkout until its new APIs are released.

## Behavior and ownership

The UDP API uses Linux x/net ipv4/ipv6 ReadBatch/WriteBatch, following
[wireguard-go's socket approach](https://github.com/WireGuard/wireguard-go/blob/master/conn/bind_std.go).
Maximum batch size is **32**, selected as a bounded initial size below the
existing 64-entry sender queue; it is not claimed to be an optimal size.
Unconnected concrete UDP sockets use recvmmsg/sendmmsg. IPv4, IPv6 and dual-stack
listeners work. Other platforms, connected sockets and injected/wrapped
PacketConns use single-message operations. Unsupported syscall errors
ENOSYS/EOPNOTSUPP with zero progress disable that operation and immediately fall
back. Other socket errors retain the existing terminal-error policy.

The single sender takes one queued datagram and drains only immediately
available entries, up to 32, without a timer or waiting for a full batch. It
submits adjacent NAT-T datagrams together, with their individual destinations,
and keeps raw ESP writes on the existing transport. Global FIFO order, including
per-SA ciphertext order, is preserved. Before every write attempt, unsent SAs
are checked again. Partial success advances past the transmitted prefix; the
remaining eligible packets are submitted in order. Any accompanying error
terminally rejects the remainder rather than retransmitting uncertain data.
Zero progress fails once. A local batch adds at most 32 retained ciphertext
buffers to the default 64-entry queue. Successful enqueue still transfers
ownership; failed enqueue leaves ownership with the producer. Sent, revoked,
cancelled, failed and queued packets are each released once by the sender.

The NAT-T receiver keeps separate pooled maximum-packet buffers for each slot
(about 2 MiB per Linux listener; one buffer on fallback). It processes only the
returned prefix and valid lengths, drops truncated messages, and borrows storage
through the synchronous handler/Dispatch before erasing and reusing it. All
storage is released on exit. MSG_TRUNC is checked on batch and UDP fallback
reads; generic PacketConn has no flags, so full-buffer reads are conservatively
rejected. x/net's negative count on deadline errors is normalized to zero while
preserving the error. Existing one-second deadline/maintenance behavior remains.

NAT-T keepalive/ESP/IKE demultiplexing and Non-ESP Marker handling are unchanged.
Control replies and synchronous handler replies remain compatible single writes.
Cancellation, closure, queue backpressure, SA lifetime/rekey/teardown checks and
raw ESP remain in their existing ownership model. Encryption and protocol
processing stay in userspace. No GSO/GRO, TUN, crypto or worker changes were made.

## Validation

All three modules passed normal tests and race detection on macOS ARM64, Go
1.25.4. Static checks passed. Native Linux ARM64 Docker tests passed for the UDP
package, server and app IPsec integration. Windows AMD64 UDP tests cross-compiled;
Windows runtime tests and Linux race detection were not run.

Coverage includes single/multiple messages, mixed destinations, per-SA FIFO,
partial sends, successful-prefix-plus-error, zero progress, truncation, invalid
lengths/unreturned slots, close/deadline errors, unsupported syscall fallback,
IPv6/dual stack, NAT-T demultiplexing, buffer borrowing/erasure, cancellation,
queue shutdown and revoked queued SAs. Existing rekey/lifetime/replay/control
and raw transport tests remain in the passing suites.

A first end-to-end attempt exposed a Linux negative-count timeout handling bug;
that interrupted attempt was excluded from results. The fix and Linux deadline
regression test passed before restarting the full matched comparison.

Reproduce checks from the workspace root:

```
GOCACHE=/tmp/overture-go-cache go test ./ipsec-go/... ./app/... ./l2tp-go/...
GOCACHE=/tmp/overture-go-cache go test -race ./ipsec-go/... ./app/... ./l2tp-go/...
GOCACHE=/tmp/overture-go-cache go vet ./ipsec-go/... ./app/... ./l2tp-go/...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o udp.test ./ipsec-go/udptransport
```

## Transport measurement method

Linux ARM64 in the existing `l2tp-bench:local` Docker image on the same Apple M1
Max host, Go 1.25.4, GOMAXPROCS 10. Loopback sender plus concurrent draining
receiver, payloads 64 and 1,400 bytes. Baseline uses the previous direct
PacketConn WriteTo/ReadFrom operations; batched uses the new API, up to 32
messages. Each case ran sequentially, three repetitions of one second, without
other test/build/benchmark work during final measurements. Reported rates are
medians of accepted sends to the kernel, **not delivered receive throughput**:
the receiver is not acknowledged, UDP may drop, and it stops when sending ends.
No encryption, queue draining, TUN or end-to-end protocol work is measured.
Allocation counters include the concurrent receiver. CPU percentages are whole
process user+system time divided by wall time (100% is one core), including
calibration and all repetitions; they are not CPU cost per delivered packet.

The syscall experiment is separate: strace 6.9, 100,000 timed sends per case
plus one calibration send, all threads, only socket syscalls. Traced timing is
excluded from throughput results. Receiver syscall counts cannot establish a
reduction per delivered packet because loss and receiver scheduling differ.

Reproduce the transport run in the same image with the cross-compiled test:

```
./udp.test -test.run='^$' -test.bench='BenchmarkUDPTransport/bytes=64/batch=false$' -test.benchmem -test.benchtime=1s -test.count=3
```

Repeat with `batch=true` and `bytes=1400`. Wrap with `/usr/bin/time -v` for CPU.
For syscall counts use `strace -f -c -e trace=sendto,recvfrom,sendmsg,recvmsg,sendmmsg,recvmmsg`
and `-test.benchtime=100000x` (one repetition).

## Transport results

| Payload bytes | Mode | Accepted sends/sec | ns/send | B/send | allocs/send | Process CPU |
|---:|---|---:|---:|---:|---:|---:|
| 64 | Before: single | 626,566 | 1,596 | 53 | 1 | 194% |
| 64 | After: batch | 841,043 | 1,189 | 53 | 1 | 193% |
| 1,400 | Before: single | 621,891 | 1,608 | 52 | 2 | 196% |
| 1,400 | After: batch | 763,942 | 1,309 | 54 | 2 | 197% |

These are medians; raw allocation counts fluctuate with receiver scheduling and
loss. No consistent allocation reduction is demonstrated. Accepted-send rates
increased 34.2% and 22.8% in this isolated transport test. The production queue
may form smaller batches than the full batches used here.

| Payload bytes | Single sendto calls | Batch sendmmsg calls | Single recvfrom calls | Batch recvmmsg calls |
|---:|---:|---:|---:|---:|
| 64 | 100,001 | 3,126 | 19,828 | 3,831 |
| 1,400 | 100,001 | 3,126 | 21,571 | 3,811 |

Sender counts demonstrate up to 32 datagrams per send syscall. Receive counts
include EAGAIN/poll retries (40/270 for 64 bytes, 9/226 for 1,400 bytes) and are
not normalized to delivered messages. Substantial receive loss is possible in
this unacknowledged traced experiment; it is unsuitable as a receive throughput
benchmark. Actual receive batching/boundaries/destinations are verified by the
lossless small loopback tests.

Raw transport results, process CPU reports, strace reports and parsed medians
are stored beside this document. These microbenchmarks do not imply end-to-end
VPN throughput gains.

## Application benchmark method

The existing isolated Docker strongSwan/xl2tpd/pppd comparison harness was reused.
Baseline source snapshots came from the revisions above; the same Go toolchain
cross-built baseline and modified app binaries for Linux ARM64. Binary hashes
are in `environment.json`. Both ran in the same existing Linux VM/image, followed
by the strongSwan reference, for each transport. No tests, builds or transport
benchmarks ran during these final timed trials. There is no CPU pinning or
physical NIC; this is a short single-client endpoint test on a shared VM.

AES-128-CBC/HMAC-SHA1-96, IKEv1 PSK, MTU 1400, inbound replay windows 1024 at both
ends, one TCP stream, two trials per direction, `iperf3 -t 10 -O 2 -J`; download
adds `-R`. Endpoint is 10.77.0.1 from PPP client 10.77.0.2. NAT-T is forced UDP
encapsulation without a NAT gateway. Each case validates cipher, encapsulation,
PPP connectivity and installed kernel replay windows. Saved XFRM state redacts
disposable test keys. The userspace replay window remains 1024.

To reproduce, build baseline and modified binaries with
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o before-vpn ./app/cmd/overture-vpn`
(and `after-vpn` from the modified workspace). Put both beside the saved
`run-throughput.py` and `interop-harness.py` in a scratch directory, with the
existing `l2tp-bench:local` image available, and run `python3 run-throughput.py`.
The runner creates/removes only its `overture-buffer-bench-*` containers/network.
Do not run concurrent builds or benchmarks during timing.

## Application results

Receiver goodput, arithmetic mean of two trials, Mbit/s:

| Transport | Stack | Upload | Download |
|---|---|---:|---:|
| esp | before | 623.4 | 756.5 |
| esp | after | 613.1 | 841.9 |
| esp | reference | 1513.6 | 1482.8 |
| natt | before | 640.4 | 715.4 |
| natt | after | 707.1 | 1192.6 |
| natt | reference | 1416.1 | 1445.4 |

esp: measured upload change -1.7%; download +11.3%.

natt: measured upload change +10.4%; download +66.7%.

These are endpoint results from two short trials per direction, not statistical
significance or production capacity claims. Raw ESP changes despite unchanged
socket operations illustrate sensitivity to host load/scheduling and the changed
queue drain pattern. Full paired trials are in `throughput-summary.json`.
All six cases verified AES-128-CBC/HMAC-SHA1-96, intended encapsulation and
replay-window settings. Saved kernel XfrmInStateSeqError counters were zero for
all NAT-T cases and both app raw ESP cases. **The strongSwan raw ESP reference
server recorded 58 replay-sequence errors**; the client recorded zero. No cause
was established; treat that raw reference comparison with this caveat. Kernel
counters do not measure the app's separate userspace replay checks.

No app CPU profile or app syscall tracing was collected during timed iperf
trials; only the separate transport experiment measures process CPU and syscall
counts. Physical-host/WAN performance, long-duration rekey under load, every
cipher end-to-end, Windows runtime and Linux race execution remain unmeasured.
Existing rekey/lifetime tests passed under race detection on macOS.
