package l2tpipsec

import (
	"context"
	"sync"

	ipsec "github.com/eukhlg/ipsec-go/server"
)

// SealCapacity bounds reserved packets between reservation and the sender,
// including packets sealed early and waiting behind a slower earlier one.
const SealCapacity = 64

type sealJob struct {
	ticket      uint64
	association *ipsec.Association
	seal        ipsec.ESPSeal
	datagram    ipsec.ESPDatagram
}

// sealPipeline encrypts outbound ESP on several workers and hands packets to
// the sender in reservation order. Reservation assigns each packet its SA
// sequence number under ESPBridge.outboundMu, so ticket order is sequence
// order for every SA and the wire order never leaves the peer's replay window.
// This mirrors the receive side's ticketed crypto with an ordered commit.
type sealPipeline struct {
	ctx       context.Context
	cancel    context.CancelFunc
	jobs      chan sealJob
	completed chan sealJob
	permits   chan struct{}
	next      uint64 // producers own it under ESPBridge.outboundMu
	submitMu  sync.Mutex
	enqueue   func(context.Context, *ipsec.Association, ipsec.ESPDatagram) error
	dropped   func(error)
	workers   sync.WaitGroup
	done      chan struct{}
}

func newSealPipeline(ctx context.Context, workers int, enqueue func(context.Context, *ipsec.Association, ipsec.ESPDatagram) error, dropped func(error)) *sealPipeline {
	ctx, cancel := context.WithCancel(ctx)
	p := &sealPipeline{ctx: ctx, cancel: cancel, jobs: make(chan sealJob, SealCapacity), completed: make(chan sealJob, SealCapacity), permits: make(chan struct{}, SealCapacity), enqueue: enqueue, dropped: dropped, done: make(chan struct{})}
	p.workers.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer p.workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-p.jobs:
					job.datagram = job.seal.Seal()
					job.seal = ipsec.ESPSeal{}
					select {
					case p.completed <- job:
					case <-ctx.Done():
						job.datagram.Release()
						return
					}
				}
			}
		}()
	}
	go p.commit()
	return p
}

// submit consumes seal on every outcome. Callers hold ESPBridge.outboundMu,
// which makes ticket order equal to sequence order.
func (p *sealPipeline) submit(association *ipsec.Association, seal ipsec.ESPSeal) error {
	select {
	case p.permits <- struct{}{}:
	case <-p.ctx.Done():
		seal.Release()
		return p.ctx.Err()
	}
	p.submitMu.Lock()
	defer p.submitMu.Unlock()
	if err := p.ctx.Err(); err != nil {
		<-p.permits
		seal.Release()
		return err
	}
	// A permit guarantees room: at most SealCapacity jobs exist in the pipeline.
	p.jobs <- sealJob{ticket: p.next, association: association, seal: seal}
	p.next++
	return nil
}

// commit enqueues completed packets in ticket order. Tickets in flight never
// exceed SealCapacity, so a ring indexed by ticket holds every early packet.
func (p *sealPipeline) commit() {
	defer close(p.done)
	var ring [SealCapacity]sealJob
	var present [SealCapacity]bool
	next := uint64(0)
	for {
		select {
		case <-p.ctx.Done():
			for i := range ring {
				if present[i] {
					ring[i].datagram.Release()
					ring[i], present[i] = sealJob{}, false
				}
			}
			return
		case job := <-p.completed:
			slot := job.ticket % SealCapacity
			ring[slot], present[slot] = job, true
			for present[next%SealCapacity] {
				slot := next % SealCapacity
				head := ring[slot]
				ring[slot], present[slot] = sealJob{}, false
				if err := p.enqueue(p.ctx, head.association, head.datagram); err != nil {
					head.datagram.Release()
					if p.dropped != nil {
						p.dropped(err)
					}
				}
				<-p.permits
				next++
			}
		}
	}
}

// close stops the pipeline and releases every packet still inside it.
func (p *sealPipeline) close() {
	p.cancel()
	p.workers.Wait()
	<-p.done
	p.submitMu.Lock()
	defer p.submitMu.Unlock()
	for {
		select {
		case job := <-p.jobs:
			job.seal.Release()
		case job := <-p.completed:
			job.datagram.Release()
		default:
			return
		}
	}
}
