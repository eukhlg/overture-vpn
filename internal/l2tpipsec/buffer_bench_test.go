package l2tpipsec

import (
	"fmt"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
	"github.com/eukhlg/l2tp-go/protocol/ppp"
	"testing"
)

func benchmarkSA(b *testing.B) *esp.SA {
	b.Helper()
	s, err := esp.NewSA(esp.SAConfig{SPI: 42, Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196}, EncryptionKey: make([]byte, 16), AuthenticationKey: make([]byte, 20)})
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// The legacy benchmark remains unchanged for reproducible before/after comparison.
func BenchmarkLegacyDataPath(b *testing.B) {
	for _, size := range []int{64, 1400, 65000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			payload := make([]byte, size)
			b.Run("Outbound", func(b *testing.B) {
				s := benchmarkSA(b)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					p, _ := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: payload}).MarshalBinary()
					l, _ := (l2tp.Packet{TunnelID: 1, SessionID: 1, Payload: p}).MarshalBinary()
					if _, err := s.Seal(encodeUDP(1701, 1701, l), 17); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Inbound", func(b *testing.B) {
				s := benchmarkSA(b)
				p, _ := (ppp.Frame{Protocol: ppp.ProtocolIPv4, Payload: payload}).MarshalBinary()
				l, _ := (l2tp.Packet{TunnelID: 1, SessionID: 1, Payload: p}).MarshalBinary()
				wire, err := s.Seal(encodeUDP(1701, 1701, l), 17)
				if err != nil {
					b.Fatal(err)
				}
				// A fresh receiver is prepared outside timing per operation to allow the same
				// authenticated packet without bypassing production replay checking.
				receivers := make([]*esp.SA, 256)
				for i := range receivers {
					receivers[i] = benchmarkSA(b)
				}
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					j := i % len(receivers)
					if j == 0 {
						b.StopTimer()
						for k := range receivers {
							receivers[k] = benchmarkSA(b)
						}
						b.StartTimer()
					}
					udp, _, err := receivers[j].Open(wire)
					if err != nil {
						b.Fatal(err)
					}
					_, _, l, err := decodeUDP(udp)
					if err != nil {
						b.Fatal(err)
					}
					p, err := l2tp.DecodePacket(l)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := ppp.DecodeFrame(p.Payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
