# Owned userspace packet buffers — 20 October 2026

The protected steady-state path now copies each TUN packet once into owned
storage. PPP, L2TP, UDP and ESP headers use reserved headroom; CBC padding,
trailer and ICV use tailroom. Encryption runs in place on the producer and the
existing single bounded sender preserves FIFO sequence order. Receive processing
authenticates before in-place decryption and borrows bounded views through
synchronous routing/Dispatch. No device read/write, MTU, encryption worker,
batching, offload or synchronization redesign was introduced. The user explicitly
approved replacing the router's allocation with owned pooled storage.

Design references: WireGuard's [packet pools](https://github.com/WireGuard/wireguard-go/blob/master/device/pools.go)
and [reserved packet space](https://github.com/WireGuard/wireguard-go/blob/master/device/send.go).
This is an independent implementation for PPP/L2TP/UDP/CBC ESP, not copied
WireGuard protocol or queue code.

## Storage and ownership

- `ipsec-go/packetbuf` pools 2,048-byte and 65,631-byte backing arrays. Sixty-four
  bytes of headroom cover PPP (4), sequenced L2TP (10), UDP (8), ESP (8) and AES
  IV (16); 32 bytes of tailroom cover padding (15), trailer (2), ICV (12).
  Outbound L2TP remains unsequenced, as before; inbound optional L2TP length,
  sequence, offset, PPP ACFC and PFC formats retain their existing parsing.
- Acquisition accepts up to 65,535 bytes. Sealing rejects output exceeding
  65,507 bytes, the common IPv4 UDP payload ceiling; oversized input cannot
  wrap a UDP length or consume sequence/lifetime state. A maximal inner IPv4
  packet cannot fit after encapsulation and is rejected. The raw ESP path uses
  the same conservative ceiling. This does not introduce fragmentation.
- A Buffer is exclusively owned and must not be copied, concurrently used, or
  accessed after transfer/release. Successful `Enqueue` transfers ownership;
  failed enqueue retains producer ownership. `SendIPv4Buffer` consumes its
  argument on every outcome. The sender releases after successful/failed/short
  writes, revocation, cancellation, and backlog shutdown. Production producers
  release on framing, sealing, missing-flow and enqueue failure.
- Receive storage belongs to one transport loop until it exits. An in-place
  handler and its Dispatch borrow it until synchronous Dispatch finishes;
  storage is erased before the next read and released on every exit. Views
  constrain capacity to their validated boundaries. Async consumers must copy
  before returning; the legacy public APIs continue returning independent data.
- Release erases the entire backing array, including consumed plaintext and
  failed decryptions. Double release before reacquisition panics. Pools retain
  packet storage, never keys. `sync.Pool` may discard buffers during GC; pool
  misses still allocate. The sender remains bounded at 64 entries.

Five payload copies after the old TUN copy are removed outbound: PPP framing,
L2TP body staging, L2TP output framing, UDP wrapping and ESP staging. Inbound,
the ciphertext parse copy, decryption output, plaintext extraction, UDP/L2TP/PPP
payload extraction and PPP IPv4 result copy are removed. CBC and HMAC still
read/process payload bytes. Socket/kernel/TUN copies remain unchanged.

Necessary copies remain at the TUN-to-owned-buffer boundary; independent-storage
compatibility wrappers; control exchanges and lifecycle state; legacy router
writers that can retain slices; and any asynchronous external consumer unable
to take ownership. Native TUN implementation/framing is unchanged.

## Allocation benchmarks

Apple M1 Max, macOS ARM64, Go 1.25.4, default GOMAXPROCS (10). AES-128-CBC,
HMAC-SHA1-96, real crypto/rand IVs, same packet sizes and benchmark duration:
500 ms, three repetitions, medians below. Baseline sources are recorded in
[baseline-revisions.json](baseline-revisions.json); they were snapshotted from
Git before implementation, with the same legacy benchmark added to the snapshot.
Timed benchmarks ran sequentially before Docker throughput trials.

Outbound includes all PPP/L2TP/UDP framing and ESP sealing. The old benchmark
starts at protocol framing (its extra pre-existing TUN copy is excluded); the
owned benchmark includes the single copy into its pool and release/erasure.
Inbound includes ESP opening and UDP/L2TP/PPP decapsulation. Both exclude
socket receive and fresh receiver-SA setup; receivers are prepared in groups of
256 outside timing, permitting real replay checks without replaying a packet
through a single SA. Owned receive storage is prepared outside timing, as a
socket would provide it; release/erasure is timed. Neither measures queues,
engine session lookup/PPP policy validation, TUN syscalls, or kernel networking.

| Inner bytes | Direction | Before allocs/op | After allocs/op | Before B/op | After B/op | Before ns/op | After ns/op |
|---:|---|---:|---:|---:|---:|---:|---:|
| 64 | Outbound | 12 | 8 | 1,464 | 1,000 | 1,082 | 1,152 |
| 64 | Inbound | 15 | 7 | 1,528 | 991 | 856.6 | 799.2 |
| 1,400 | Outbound | 12 | 8 | 8,408 | 1,000 | 3,718 | 2,962 |
| 1,400 | Inbound | 15 | 7 | 9,976 | 991 | 3,099 | 2,088 |
| 65,000 | Outbound | 12 | 8 | 328,665 | 1,000 | 119,525 | 93,430 |
| 65,000 | Inbound | 15 | 7 | 394,234 | 986 | 98,621 | 64,592 |

Fixed-size crypto/rand IV, CBC and HMAC objects still allocate. Grouped inbound
setup changes GC cadence, so B/op can vary slightly with packet size despite
fixed crypto allocations; the raw outputs are authoritative. Small-packet
outbound latency regressed in this local microbenchmark. These measurements
establish allocation reduction, not VPN throughput improvement.

Reproduce from the matching before/after workspace:

```
GOCACHE=/tmp/overture-go-cache go test ./app/internal/l2tpipsec -run '^$' -bench BenchmarkLegacyDataPath -benchmem -benchtime=500ms -count=3
GOCACHE=/tmp/overture-go-cache go test ./app/internal/l2tpipsec -run '^$' -bench BenchmarkOwnedDataPath -benchmem -benchtime=500ms -count=3
```

The legacy harness belongs on the baseline snapshot when reproducing the before
measurement: compatibility helper implementations evolve with the new path.
See [before](allocations-before.txt) and [after](allocations-after.txt) raw results.

## Matched application throughput

The existing isolated Docker harness was run with the baseline app, updated app
and strongSwan/xl2tpd/pppd reference. AES-128-CBC/HMAC-SHA1-96, MTU 1400, receive
replay windows 1024 at both endpoints, raw ESP and forced NAT-T, one TCP stream,
two trials/direction, `iperf3 -t 10 -O 2 -J` (download adds `-R`). No builds,
tests or other benchmarks ran during timed trials. Containers use the same
local ARM64 helper image in the same Docker Desktop Linux VM. The endpoint is
10.77.0.1; this measures endpoints on one VM, not WAN forwarding capacity.

| Transport | Stack | Upload mean, Mbit/s | Download mean, Mbit/s |
|---|---|---:|---:|
| Raw ESP | Baseline app | 522.1 | 771.0 |
| Raw ESP | Updated app | 603.5 | 756.3 |
| Raw ESP | strongSwan reference | 1,507.9 | 1,513.1 |
| NAT-T | Baseline app | 557.1 | 775.0 |
| NAT-T | Updated app | 661.2 | 729.8 |
| NAT-T | strongSwan reference | 1,497.2 | 1,494.6 |

Upload increased 15.6% (raw) / 18.7% (NAT-T), while download decreased
1.9% / 5.8%. Thus this run does **not** demonstrate a general throughput gain.
The direction-dependent regression remains a limitation requiring separate
profiling; allocation savings alone cannot explain end-to-end scheduling and
network performance. Short sequential trials on a shared VM are sensitive to
host load, ordering and scheduling. No statistical significance or production
capacity claim is made. Other ciphers were covered by unit tests, not this
end-to-end subset.

All six cases verified negotiated AES-128/HMAC-SHA1-96 and encapsulation. Kernel
extended inbound replay-window state was 1024; its separate legacy/outbound
`replay-window 0` field is not the installed inbound extended window. The Go
server's unchanged configuration uses 1024. All saved XFRM
`XfrmInStateSeqError` counters were zero; the userspace server's inbound checks
remain enabled independently of kernel counters. Disposable test SA keys are
redacted from saved XFRM state. Trailing whitespace is normalized in saved
command outputs; measurement values are unchanged.

[Trial data and status](throughput/), [summary with individual trials](throughput-summary.json),
[runner](run-throughput.py), [original harness snapshot](interop-harness.py),
[binary hashes and settings](environment.json), [console log](throughput.log).
To reproduce, place sibling baseline and modified workspace snapshots in a
scratch directory, cross-build their app binaries with
`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o before-vpn ./app/cmd/overture-vpn`
and the equivalent `after-vpn` command in the modified workspace. Copy both
binaries, runner and harness into one fresh scratch directory, and execute
`python3 run-throughput.py` there with the existing `l2tp-bench:local` image.
The runner creates/removes only its `overture-buffer-bench-*` resources.

## Validation and limitations

All three module suites and race detection passed, including loopback transports
(with sandbox permission for socket binds). Focused coverage includes owned
buffer isolation/erasure/bounds/double release, all supported AES key lengths and
3DES CBC padding boundaries, random-IV failure, unpredictable IVs, authentication
failure before mutation, malformed/truncated ESP/UDP/L2TP/PPP, accounting/replay
preservation, compatibility storage, sender FIFO/shutdown/parent cancellation,
short/error writes, failed/blocked enqueue, revoked queued SAs, and receive
storage through Dispatch and on Dispatch failure. Existing rekey/lifetime/
teardown tests remain in the passing suites. Fifty repeated race-enabled
ownership/shutdown/replacement runs also passed. PPP and L2TP view fuzzing ran
for ten seconds each (964,579 and 1,095,275 executions); ESP codec fuzzing also
passed for ten seconds with one worker (508,897 executions), and a separate
100,000-input run passed. The first ESP run with two workers ended with
`context deadline exceeded` at its ten-second cutoff, without a failing input;
that unsuccessful run is retained in `fuzz-esp-initial-deadline.txt`, rather than
counted as a pass. `go vet` passed. See [validation commands](VALIDATION.md)
and the saved test outputs beside this report.

No privileged native macOS TUN creation test or physical-host/WAN benchmark was
run. Long-duration rekey under load and every supported cipher's end-to-end
throughput remain outside this run. The coordinated workspace uses the new
library APIs; standalone app builds need corresponding library releases or
local replacements. [Exact library commits](implementation-libraries.json) are
recorded for workspace reproduction. No dependency version was invented or
published.
