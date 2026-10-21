package l2tpipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/ipsec-go/udptransport"
)

// SenderQueueCapacity bounds ciphertext retained between encryption and writes.
const SenderQueueCapacity = 64

type encryptedPacket struct {
	association *ipsec.Association
	datagram    ipsec.ESPDatagram
}

// ESPSender owns the data sockets until Close. Enqueue transfers ownership of
// an independently sealed datagram; callers must not mutate it after acceptance.
// Producers must serialize sealing and enqueueing for each SA (as ESPBridge does).
// One worker preserves FIFO order, while encryption proceeds on the producer.
type ESPSender struct {
	ctx            context.Context
	cancel         context.CancelFunc
	raw, natt      net.PacketConn
	queue          chan encryptedPacket
	done           chan error
	stopped        chan struct{}
	watcherStopped chan struct{}
	mu             sync.Mutex
	err            error
	submitMu       sync.Mutex
	closeOnce      sync.Once
}

type datagramWriter interface {
	Write([]udptransport.Message) (int, error)
}

func NewESPSender(ctx context.Context, raw, natt net.PacketConn, capacity int) (*ESPSender, error) {
	return newESPSender(ctx, raw, natt, capacity, udptransport.New(natt))
}

func newESPSender(ctx context.Context, raw, natt net.PacketConn, capacity int, udp datagramWriter) (*ESPSender, error) {
	if raw == nil || natt == nil || capacity < 1 {
		return nil, errors.New("esp sender: sockets and positive capacity required")
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &ESPSender{ctx: ctx, cancel: cancel, raw: raw, natt: natt, queue: make(chan encryptedPacket, capacity), done: make(chan error, 1), stopped: make(chan struct{}), watcherStopped: make(chan struct{})}
	go func() {
		defer close(s.watcherStopped)
		<-ctx.Done()
		_ = raw.Close()
		_ = natt.Close()
	}()
	go s.run(udp)
	return s, nil
}

// Done publishes the first write error even if no producer calls Enqueue again.
// Normal shutdown publishes nil. The result channel is deliberately buffered.
func (s *ESPSender) Done() <-chan error { return s.done }

func (s *ESPSender) terminalError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.ctx.Err()
}

// Enqueue transfers datagram ownership only on success. On error the producer
// must release pooled storage; accepted datagrams are released by the sender.
func (s *ESPSender) Enqueue(association *ipsec.Association, datagram ipsec.ESPDatagram) error {
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if err := s.terminalError(); err != nil {
		return err
	}
	if association == nil || !association.Active() {
		return ipsec.ErrUnknownESP
	}
	select {
	case <-s.ctx.Done():
		return s.terminalError()
	case s.queue <- encryptedPacket{association, datagram}:
		return nil
	}
}

func (s *ESPSender) run(udp datagramWriter) {
	var failure error
	defer func() {
		if failure != nil {
			s.mu.Lock()
			s.err = failure
			s.mu.Unlock()
		}
		s.cancel() // interrupts a socket write and all blocked producers
		<-s.watcherStopped
		// After cancellation, no producer can retain a reference in the queue.
		s.submitMu.Lock()
		for len(s.queue) > 0 {
			packet := <-s.queue
			packet.datagram.Release()
		}
		s.submitMu.Unlock()
		s.done <- failure
		close(s.stopped)
	}()
	var packets [udptransport.BatchSize]encryptedPacket
	var messages [udptransport.BatchSize]udptransport.Message
	var indices [udptransport.BatchSize]int
	for {
		var count int
		select {
		case <-s.ctx.Done():
			return
		case packets[0] = <-s.queue:
			count = 1
		}
	drain:
		for count < len(packets) {
			select {
			case packets[count] = <-s.queue:
				count++
			default:
				break drain
			}
		}
		// The local batch owns these buffers even if cancellation or a write fails.
		err := func() error {
			defer func() {
				for i := 0; i < count; i++ {
					packets[i].datagram.Release()
					packets[i] = encryptedPacket{}
					messages[i] = udptransport.Message{}
				}
			}()
			for start := 0; start < count; {
				if s.ctx.Err() != nil {
					return s.ctx.Err()
				}
				if !packets[start].association.Active() {
					start++
					continue
				}
				if !packets[start].datagram.NATT {
					d := packets[start].datagram
					peer := d.Peer
					if addr, ok := peer.(*net.UDPAddr); ok {
						peer = &net.IPAddr{IP: addr.IP, Zone: addr.Zone}
					}
					n, err := s.raw.WriteTo(d.Payload, peer)
					if err != nil {
						return err
					}
					if n != len(d.Payload) {
						return io.ErrShortWrite
					}
					start++
					continue
				}
				// Group only adjacent UDP messages, preserving queue order across transports.
				end := start
				for end < count && packets[end].datagram.NATT {
					end++
				}
				for start < end {
					if s.ctx.Err() != nil {
						return s.ctx.Err()
					}
					// Recheck every unsent SA on each attempt, including after partial writes.
					nmsg := 0
					for i := start; i < end; i++ {
						if !packets[i].association.Active() {
							continue
						}
						d := packets[i].datagram
						messages[nmsg] = udptransport.Message{Payload: d.Payload, Peer: d.Peer}
						indices[nmsg] = i
						nmsg++
					}
					if nmsg == 0 {
						break
					}
					n, err := udp.Write(messages[:nmsg])
					if err != nil {
						return err
					}
					if n == 0 {
						return io.ErrNoProgress
					}
					start = indices[n-1] + 1
				}
				start = end
			}
			return nil
		}()
		if err != nil {
			if s.ctx.Err() == nil {
				failure = fmt.Errorf("esp sender write: %w", err)
			}
			return
		}
	}

}

// Close discards the backlog, interrupts an active write, and joins both workers.
// The queue is never closed, so racing producers cannot panic.
func (s *ESPSender) Close() {
	s.closeOnce.Do(s.cancel)
	<-s.stopped
}
