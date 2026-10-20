package l2tpipsec

import (
	"encoding/binary"
	"fmt"
	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"testing"
)

func prependBenchmarkHeaders(b *testing.B, p *packetbuf.Buffer) {
	b.Helper()
	if err := ppp.PrependFrame(p, ppp.ProtocolIPv4); err != nil {
		b.Fatal(err)
	}
	if err := l2tp.PrependData(p, 1, 1); err != nil {
		b.Fatal(err)
	}
	h, err := p.Prepend(8)
	if err != nil {
		b.Fatal(err)
	}
	binary.BigEndian.PutUint16(h[:2], 1701)
	binary.BigEndian.PutUint16(h[2:4], 1701)
	binary.BigEndian.PutUint16(h[4:6], uint16(p.Len()))
	clear(h[6:8])
}

func BenchmarkOwnedDataPath(b *testing.B) {
	for _, size := range []int{64, 1400, 65000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.Run("Outbound", func(b *testing.B) {
				s := benchmarkSA(b)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					p, err := packetbuf.Copy(payload)
					if err != nil {
						b.Fatal(err)
					}
					prependBenchmarkHeaders(b, p)
					if err = s.SealBuffer(p, 17); err != nil {
						b.Fatal(err)
					}
					p.Release()
				}
			})
			b.Run("Inbound", func(b *testing.B) {
				s := benchmarkSA(b)
				p, _ := packetbuf.Copy(payload)
				prependBenchmarkHeaders(b, p)
				if err := s.SealBuffer(p, 17); err != nil {
					b.Fatal(err)
				}
				wire := append([]byte(nil), p.Bytes()...)
				p.Release()
				receivers := make([]*esp.SA, 256)
				buffers := make([]*packetbuf.Buffer, 256)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					j := i % len(receivers)
					if j == 0 {
						b.StopTimer()
						for k := range receivers {
							receivers[k] = benchmarkSA(b)
							buffers[k], _ = packetbuf.Copy(wire)
						}
						b.StartTimer()
					}
					udp, _, err := receivers[j].OpenInPlace(buffers[j].Bytes())
					if err != nil {
						b.Fatal(err)
					}
					_, _, wire, err := decodeUDP(udp)
					if err != nil {
						b.Fatal(err)
					}
					packet, err := l2tp.DecodePacketView(wire)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := ppp.DecodeFrameView(packet.Payload); err != nil {
						b.Fatal(err)
					}
					buffers[j].Release()
					buffers[j] = nil
				}
				b.StopTimer()
				for _, buffer := range buffers {
					if buffer != nil {
						buffer.Release()
					}
				}
			})
		})
	}
}
