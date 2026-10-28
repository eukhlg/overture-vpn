//go:build integration && linux

package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
)

// Run explicitly with: go test -tags=integration ./tun -run TestNativeDeviceWriters
// Writers duplicate the descriptor and must close with the device.
func TestNativeDeviceWriters(t *testing.T) {
	device, err := Open(Config{})
	if err != nil {
		t.Fatal(err)
	}
	source, ok := device.(WriterSource)
	if !ok {
		device.Close()
		t.Fatal("native device has no parallel writers")
	}
	r, _ := NewRouter(device)
	if n, err := r.SetWriteShards(3); err != nil || n != 3 {
		device.Close()
		t.Fatalf("SetWriteShards=%d, %v", n, err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	for _, shard := range r.shards {
		if _, err := shard.writer.Write([][]byte{make([]byte, 64)}, 16); err == nil {
			t.Fatal("writer usable after device close")
		}
	}
	if _, err := source.NewWriter(); err == nil {
		t.Fatal("NewWriter succeeded after close")
	}
}

// TestNativeDeviceShardedUploadReachesKernel writes TCP segments to a closed
// local port through four write shards from four flushing goroutines and
// expects the kernel's reset for every flow back through Run.
func TestNativeDeviceShardedUploadReachesKernel(t *testing.T) {
	// The resets arrive as one burst; a ring of the default 32 drops some.
	device, err := Open(Config{TxQueueLength: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	cleanup, err := Configure(context.Background(), device, LinkConfig{Address: netip.MustParsePrefix("198.51.100.1/24")}, nil)
	if err != nil {
		t.Skip(err)
	}
	defer cleanup(context.Background())
	r, _ := NewRouter(device)
	if n, err := r.SetWriteShards(4); err != nil || n != 4 {
		t.Fatalf("SetWriteShards=%d, %v", n, err)
	}
	client := netip.MustParseAddr("198.51.100.2")
	const workers, flowsPerWorker = 4, 16
	resets := make(chan uint16, workers*flowsPerWorker*4)
	r.BindOwned(client, func(b *packetbuf.Buffer) error {
		p := b.Bytes()
		if len(p) >= 40 && p[9] == 6 && p[33]&0x04 != 0 {
			resets <- binary.BigEndian.Uint16(p[22:24])
		}
		b.Release()
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go r.Run(ctx)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch, flush := r.NewRouteBatch(context.Background())
			for f := 0; f < flowsPerWorker; f++ {
				buffer, err := packetbuf.Copy(closedPortSegment(uint16(20000 + w*flowsPerWorker + f)))
				if err != nil {
					t.Error(err)
					return
				}
				defer buffer.Release()
				if err := r.RouteIPv4Owned(batch, server.DataFrame{IPv4: buffer.Bytes(), Buffer: buffer}, func([]byte) error { return nil }); err != nil {
					t.Error(err)
				}
			}
			if err := flush(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	seen := map[uint16]bool{}
	for len(seen) < workers*flowsPerWorker {
		select {
		case port := <-resets:
			seen[port] = true
		case <-ctx.Done():
			t.Fatalf("resets for %d of %d flows", len(seen), workers*flowsPerWorker)
		}
	}
}

// closedPortSegment is a TCP ACK from 198.51.100.2:port to 198.51.100.1:9, which
// the kernel answers with a reset.
func closedPortSegment(port uint16) []byte {
	p := make([]byte, 40+16)
	p[0], p[8], p[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], []byte{198, 51, 100, 2})
	copy(p[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], 9)
	binary.BigEndian.PutUint32(p[24:], 1)
	binary.BigEndian.PutUint32(p[28:], 1)
	p[32], p[33] = 0x50, 0x10
	binary.BigEndian.PutUint16(p[34:], 0xffff)
	binary.BigEndian.PutUint16(p[10:], ^checksum(p[:20], 0))
	binary.BigEndian.PutUint16(p[36:], ^checksum(p[20:], pseudoHeaderChecksumNoFold(6, p[12:16], p[16:20], uint16(len(p)-20))))
	return p
}
