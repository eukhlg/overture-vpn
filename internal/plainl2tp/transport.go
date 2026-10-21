// Package plainl2tp adapts the independent L2TP server to the shared UDP batch
// transport and exclusively owned packet buffers. It never handles inner delivery.
package plainl2tp

import (
	"context"
	"errors"
	"net"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// Compile-time checks: l2tp-go discovers these optional capabilities by type
// assertion, so a signature drift would otherwise silently disable batching.
var (
	_ server.BatchPacketConn        = (*Transport)(nil)
	_ server.ReceiveBufferAllocator = (*Transport)(nil)
	_ server.OwnedPacketWriter      = (*Transport)(nil)
	_ server.SessionDatagramWriter  = (*Transport)(nil)
)

type Transport struct {
	net.PacketConn
	receiver *udptransport.Conn
	sender   *udptransport.Sender
	messages [udptransport.BatchSize]udptransport.Message
}

func New(conn net.PacketConn) (*Transport, error) {
	// One batch socket serves both directions: udptransport.Conn keeps separate
	// rx/tx scratch and fallback state, so a single reader (Serve) and a single
	// writer (the sender worker) may use it concurrently.
	udp := udptransport.New(conn)
	// Serve owns cancellation/deadlines so StopCCN can be sent before Close.
	sender, err := udptransport.NewSenderWithWriter(context.Background(), conn, udp, udptransport.SenderQueueCapacity)
	if err != nil {
		return nil, err
	}
	return &Transport{PacketConn: conn, receiver: udp, sender: sender}, nil
}

func (t *Transport) BatchSize() int { return t.receiver.BatchSize() }
func (t *Transport) AcquireReceiveBuffer() (server.ReceiveBuffer, error) {
	return packetbuf.Acquire(packetbuf.MaxPacket)
}
func (t *Transport) ReadBatch(messages []server.ReceivedDatagram) (int, error) {
	if len(messages) > len(t.messages) {
		messages = messages[:len(t.messages)]
	}
	for i := range messages {
		t.messages[i] = udptransport.Message{Payload: messages[i].Payload}
	}
	n, err := t.receiver.Read(t.messages[:len(messages)])
	for i := 0; i < n; i++ {
		m := t.messages[i]
		messages[i].N = m.N
		messages[i].Peer = m.Peer
		messages[i].Truncated = m.Truncated
	}
	for i := range messages {
		t.messages[i] = udptransport.Message{}
	}
	if err != nil {
		if failure := t.sender.Err(); failure != nil && !errors.Is(failure, context.Canceled) {
			return n, failure
		}
	}
	return n, err
}

// WriteTo is an ordered synchronous control/retransmission write: its barrier
// waits for actual socket completion, rather than reporting queue acceptance.
func (t *Transport) WriteTo(payload []byte, peer net.Addr) (int, error) {
	if err := t.WriteSessionPacket(payload, peer, nil); err != nil {
		return 0, err
	}
	if err := t.Flush(context.Background()); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// WritePacket always consumes the buffer, including after failed acceptance.
func (t *Transport) WritePacket(buffer server.OwnedPacketBuffer, peer net.Addr, eligible func() bool) error {
	err := t.sender.Enqueue(context.Background(), udptransport.Datagram{Payload: buffer.Bytes(), Peer: peer, Owner: buffer, Eligible: eligible})
	if err != nil {
		buffer.Release()
	}
	if errors.Is(err, udptransport.ErrIneligible) {
		return server.ErrSessionNotEstablished
	}
	return err
}
func (t *Transport) WriteSessionPacket(payload []byte, peer net.Addr, eligible func() bool) error {
	buffer, err := packetbuf.Copy(payload)
	if err != nil {
		return err
	}
	return t.WritePacket(buffer, peer, eligible)
}
func (t *Transport) Flush(ctx context.Context) error { return t.sender.Flush(ctx) }

// Close stops the sender, which also closes the socket. Queued datagrams are
// discarded; callers needing delivery must Flush first. A prior write failure
// is reported, while the cancellation caused by Close itself is not.
func (t *Transport) Close() error {
	t.sender.Close()
	if err := t.sender.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
