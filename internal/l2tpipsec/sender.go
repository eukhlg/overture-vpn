package l2tpipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	ipsec "github.com/eukhlg/ipsec-go/server"
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

func NewESPSender(ctx context.Context, raw, natt net.PacketConn, capacity int) (*ESPSender, error) {
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
	go s.run()
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

func (s *ESPSender) Enqueue(association *ipsec.Association, datagram ipsec.ESPDatagram) error {
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if err := s.terminalError(); err != nil {
		return err
	}
	if !association.Active() {
		return ipsec.ErrUnknownESP
	}
	select {
	case <-s.ctx.Done():
		return s.terminalError()
	case s.queue <- encryptedPacket{association, datagram}:
		return nil
	}
}

func (s *ESPSender) run() {
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
			<-s.queue
		}
		s.submitMu.Unlock()
		s.done <- failure
		close(s.stopped)
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-s.queue:
			if s.ctx.Err() != nil {
				return
			}
			if !packet.association.Active() {
				continue
			}
			datagram := packet.datagram
			conn, peer := s.raw, datagram.Peer
			if datagram.NATT {
				conn = s.natt
			} else if udp, ok := peer.(*net.UDPAddr); ok {
				peer = &net.IPAddr{IP: udp.IP, Zone: udp.Zone}
			}
			n, err := conn.WriteTo(datagram.Payload, peer)
			if err == nil && n != len(datagram.Payload) {
				err = io.ErrShortWrite
			}
			if err != nil {
				if s.ctx.Err() == nil {
					failure = fmt.Errorf("esp sender write: %w", err)
				}
				return
			}
		}
	}
}

// Close discards the backlog, interrupts an active write, and joins both workers.
// The queue is never closed, so racing producers cannot panic.
func (s *ESPSender) Close() {
	s.closeOnce.Do(s.cancel)
	<-s.stopped
}
