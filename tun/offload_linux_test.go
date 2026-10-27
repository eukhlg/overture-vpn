//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func tcpTestPacket(seq uint32, payload int, port uint16) []byte {
	b := make([]byte, 16+40+payload, 65535+16)
	p := b[16:]
	p[0] = 0x45
	p[8] = 64
	p[9] = 6
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[20:], port)
	binary.BigEndian.PutUint16(p[22:], 443)
	binary.BigEndian.PutUint32(p[24:], seq)
	binary.BigEndian.PutUint32(p[28:], 77)
	p[32] = 0x50
	p[33] = 0x10
	p[34] = 0xff
	for i := 40; i < len(p); i++ {
		p[i] = byte(int(seq) + i)
	}
	binary.BigEndian.PutUint16(p[10:], ^checksum(p[:20], 0))
	binary.BigEndian.PutUint16(p[36:], ^checksum(p[20:], pseudoHeaderChecksumNoFold(6, p[12:16], p[16:20], uint16(len(p)-20))))
	return b
}
func groTest(t *testing.T, bufs [][]byte) []int {
	t.Helper()
	tcp, udp := newTCPGROTable(), newUDPGROTable()
	var indices []int
	if err := handleGRO(bufs, 16, tcp, udp, false, &indices); err != nil {
		t.Fatal(err)
	}
	return indices
}
func TestGROMixedFlowsAndChecksums(t *testing.T) {
	bufs := [][]byte{tcpTestPacket(0, 100, 1), tcpTestPacket(0, 100, 2), tcpTestPacket(100, 100, 1), tcpTestPacket(100, 100, 2)}
	indices := groTest(t, bufs)
	if len(indices) != 2 {
		t.Fatalf("writes=%d", len(indices))
	}
	for _, i := range indices {
		p := bufs[i][16:]
		var h virtioNetHdr
		if err := h.decode(bufs[i][6:16]); err != nil {
			t.Fatal(err)
		}
		if h.gsoSize != 100 || h.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 || len(p) != 240 {
			t.Fatalf("bad coalescing: %+v len=%d", h, len(p))
		}
		out := [][]byte{make([]byte, 1024), make([]byte, 1024)}
		sizes := make([]int, 2)
		n, err := handleVirtioRead(bufs[i][6:], out, sizes, 16)
		if err != nil || n != 2 {
			t.Fatalf("split=%d %v", n, err)
		}
		for j := 0; j < n; j++ {
			p := out[j][16 : 16+sizes[j]]
			if checksum(p[:20], 0) != 0xffff || checksum(p[20:], pseudoHeaderChecksumNoFold(6, p[12:16], p[16:20], uint16(len(p)-20))) != 0xffff {
				t.Fatal("bad reconstructed checksum")
			}
		}
	}
}
func TestGROExcludesNonTCPFragmentsAndBadChecksum(t *testing.T) {
	for _, kind := range []string{"udp", "fragment", "checksum", "order"} {
		t.Run(kind, func(t *testing.T) {
			a, b := tcpTestPacket(0, 100, 1), tcpTestPacket(100, 100, 1)
			switch kind {
			case "udp":
				a[16+9] = 17
				b[16+9] = 17
			case "fragment":
				a[16+6] = 0x20
				b[16+6] = 0x20
			case "checksum":
				b[len(b)-1] ^= 1
			case "order":
				binary.BigEndian.PutUint32(b[16+24:], 999)
			}
			if got := groTest(t, [][]byte{a, b}); len(got) != 2 {
				t.Fatalf("unexpected merge %s", kind)
			}
		})
	}
}
func TestReverseSplitAliasesInputWithoutLosingFlags(t *testing.T) {
	p := tcpTestPacket(123, 300, 1)
	p[16+33] |= 9 // final PSH and FIN
	var h virtioNetHdr
	h.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
	h.gsoSize = 100
	h.csumStart = 20
	h.csumOffset = 16
	if err := h.encode(p[6:16]); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), p[16+40:]...)
	bufs := [][]byte{p[:cap(p)], make([]byte, 2048), make([]byte, 2048)}
	sizes := make([]int, 3)
	n, err := handleVirtioRead(p[6:], bufs, sizes, 16)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if !bytes.Equal(p[16+sizes[0]:], make([]byte, len(p)-16-sizes[0])) {
		t.Fatal("original super-packet tail not erased")
	}
	for i := 0; i < n; i++ {
		packet := bufs[i][16 : 16+sizes[i]]
		if !bytes.Equal(packet[40:], original[i*100:(i+1)*100]) {
			t.Fatal("split payload moved incorrectly")
		}
		flags := packet[33] & 9
		if (i == 2 && flags != 9) || (i < 2 && flags != 0) {
			t.Fatalf("segment %d flags %x", i, flags)
		}
		if binary.BigEndian.Uint32(packet[24:]) != 123+uint32(i*100) {
			t.Fatal("sequence order")
		}
	}
}
func TestVirtioOrdinaryPacketUsesOriginalStorage(t *testing.T) {
	p := tcpTestPacket(0, 100, 1)
	clear(p[6:16])
	before := append([]byte(nil), p...)
	sizes := make([]int, 1)
	n, err := handleVirtioRead(p[6:], [][]byte{p[:cap(p)]}, sizes, 16)
	if err != nil || n != 1 || sizes[0] != len(p)-16 || !bytes.Equal(before, p) {
		t.Fatalf("ordinary read changed storage: n=%d err=%v", n, err)
	}
}
func TestOffloadFallbackAndKillSwitch(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		var calls []bool
		_, err := openWithFallback(Config{DisableOffload: disabled}, func(_ Config, on bool) (Device, error) {
			calls = append(calls, on)
			if on {
				return nil, unix.EINVAL
			}
			return newMemoryDevice(), nil
		})
		if err != nil || len(calls) != map[bool]int{true: 1, false: 2}[disabled] || calls[len(calls)-1] {
			t.Fatalf("calls=%v err=%v", calls, err)
		}
	}
	_, err := openWithFallback(Config{}, func(_ Config, _ bool) (Device, error) { return nil, unix.EPERM })
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("unexpected permission fallback")
	}
}
