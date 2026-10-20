# Validation commands

From the workspace root, with Go 1.25.4:

```
GOCACHE=/tmp/overture-go-cache go test ./app/... ./l2tp-go/... ./ipsec-go/...
GOCACHE=/tmp/overture-go-cache go test -race ./app/... ./l2tp-go/... ./ipsec-go/...
GOCACHE=/tmp/overture-go-cache go test -race ./app/internal/l2tpipsec -run 'TestSender|TestOwnedBridge|TestFraming' -count=50
GOCACHE=/tmp/overture-go-cache go test ./l2tp-go/protocol/l2tp -run '^$' -fuzz '^FuzzDecodePacketView$' -fuzztime=10s -parallel=2
GOCACHE=/tmp/overture-go-cache go test ./l2tp-go/protocol/ppp -run '^$' -fuzz '^FuzzDecodeFrameView$' -fuzztime=10s -parallel=2
GOCACHE=/tmp/overture-go-cache go test ./ipsec-go/protocol/esp -run '^$' -fuzz '^FuzzDecodePacket$' -fuzztime=10s -parallel=1
GOCACHE=/tmp/overture-go-cache go vet ./app/... ./l2tp-go/... ./ipsec-go/...
```

Local loopback tests require socket access outside the restricted sandbox. No
external network access is required by the unit/race suites. Fuzzing uses the
existing strict codecs plus borrowed-view ownership/bounds assertions.

The native TUN integration test was not run. The unchanged TUN implementation
retains its existing integration-test requirements.
