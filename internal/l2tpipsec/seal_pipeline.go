package l2tpipsec

import (
	"context"

	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/netio/ordered"
)

// SealCapacity bounds reserved packets between reservation and the sender,
// including packets sealed early and waiting behind a slower earlier one.
const SealCapacity = 64

type sealJob struct {
	association *ipsec.Association
	seal        ipsec.ESPSeal
	datagram    ipsec.ESPDatagram
}

// sealPipeline encrypts outbound ESP on several workers and hands packets to
// the sender in reservation order, on netio's ordered pool. Reservation
// assigns each packet its SA sequence number under ESPBridge.outboundMu, so
// submission order is sequence order for every SA and the wire order never
// leaves the peer's replay window. It mirrors the receive side's ticketed
// crypto and ordered commit, which runs on the same pool.
type sealPipeline struct {
	pool    *ordered.Pool[sealJob]
	enqueue func(context.Context, *ipsec.Association, ipsec.ESPDatagram) error
	dropped func(error)
}

func newSealPipeline(ctx context.Context, workers int, enqueue func(context.Context, *ipsec.Association, ipsec.ESPDatagram) error, dropped func(error)) *sealPipeline {
	p := &sealPipeline{enqueue: enqueue, dropped: dropped}
	p.pool = ordered.New(ctx, workers, SealCapacity, sealWork, p.complete, discardSealJob)
	return p
}

func sealWork(job sealJob) sealJob {
	job.datagram = job.seal.Seal()
	job.seal = ipsec.ESPSeal{}
	return job
}

func (p *sealPipeline) complete(ctx context.Context, job sealJob) {
	if err := p.enqueue(ctx, job.association, job.datagram); err != nil {
		job.datagram.Release()
		if p.dropped != nil {
			p.dropped(err)
		}
	}
}

// discardSealJob releases a reservation (before sealing) or its datagram.
func discardSealJob(job sealJob) {
	job.seal.Release()
	job.datagram.Release()
}

// submit consumes seal on every outcome. Callers hold ESPBridge.outboundMu,
// which makes submission order equal to sequence order.
func (p *sealPipeline) submit(association *ipsec.Association, seal ipsec.ESPSeal) error {
	if err := p.pool.Submit(sealJob{association: association, seal: seal}); err != nil {
		seal.Release()
		return err
	}
	return nil
}

// close stops the pipeline and releases every packet still inside it.
func (p *sealPipeline) close() { p.pool.Close() }
