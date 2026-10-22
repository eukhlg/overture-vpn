package l2tpipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/netio/udptransport"
)

type batchWriteFunc func([]udptransport.Message) (int, error)

func (f batchWriteFunc) Write(m []udptransport.Message) (int, error) { return f(m) }
func TestSenderBatchesPartialAndTerminal(t *testing.T) {
	for _, batchSize := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			for _, mode := range []string{"partial", "error", "zero", "cancel", "revoke"} {
				t.Run(mode, func(t *testing.T) {
					r := ipsec.NewESPRegistry()
					defer r.Close()
					peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
					pair := testESPPair(2)
					if err := r.Install(peer, pair); err != nil {
						t.Fatal(err)
					}
					sa := openTestAssociation(t, r, peer, pair)
					raw, natt := newSenderConn(), newSenderConn()
					started, unblock := make(chan struct{}), make(chan struct{})
					calls := make(chan []byte, 10)
					attempt := 0
					writer := batchWriteFunc(func(m []udptransport.Message) (int, error) {
						attempt++
						if attempt == 1 {
							close(started)
							select {
							case <-unblock:
							case <-natt.closed:
								return 0, net.ErrClosed
							}
						}
						values := []byte{}
						for _, v := range m {
							values = append(values, v.Payload[0])
							if v.Peer != peer {
								t.Error("destination lost")
							}
						}
						calls <- values
						if attempt == 2 {
							switch mode {
							case "error":
								return 1, io.ErrClosedPipe
							case "zero":
								return 0, nil
							}
						}
						return 1, nil
					})
					s, err := newESPSender(context.Background(), raw, natt, 8, writer, batchSize)
					if err != nil {
						t.Fatal(err)
					}
					views := [][]byte{}
					for i := byte(1); i <= 4; i++ {
						d, v := ownedDatagram(t, peer, i)
						d.NATT = true
						views = append(views, v)
						if err := s.Enqueue(sa, d); err != nil {
							t.Fatal(err)
						}
						if i == 1 {
							waitSignal(t, started)
						}
					}
					if mode == "cancel" {
						s.Close()
						assertErased(t, views...)
						return
					}
					if mode == "revoke" {
						r.Remove(sa.InboundSPI())
					}
					close(unblock)
					first := <-calls
					if len(first) != 1 || first[0] != 1 {
						t.Fatal(first)
					}
					if mode == "revoke" {
						s.Close()
						assertErased(t, views...)
						return
					}
					second := <-calls
					if len(second) != min(3, batchSize) || second[0] != 2 || second[len(second)-1] != byte(1+len(second)) {
						t.Fatalf("did not drain queued datagrams: %v", second)
					}
					if mode == "partial" {
						third, fourth := <-calls, <-calls
						if len(third) != min(2, batchSize) || third[0] != 3 || len(fourth) != 1 || fourth[0] != 4 {
							t.Fatalf("retry duplicated or reordered: %v %v", third, fourth)
						}
					} else {
						select {
						case err := <-s.Done():
							if err == nil {
								t.Fatal("missing terminal error")
							}
							if mode == "error" && !errors.Is(err, io.ErrClosedPipe) {
								t.Fatal(err)
							}
						case <-time.After(3 * time.Second):
							t.Fatal("busy loop or stuck")
						}
					}
					s.Close()
					assertErased(t, views...)
				})
			}
		})
	}
}
