package l2tpipsec

import (
	"context"

	"github.com/eukhlg/l2tp-go/server"
)

// espDispatch is one packet's delivery state, from decryption until its
// delivery batch has flushed: Dispatch hands HandleResult the data frame and
// WithActive, and the router may keep WithActive as the packet's binding guard
// until the flush. Batches made with WithDeliveryBatch recycle it after the
// flush, so a packet allocates nothing; elsewhere it is garbage collected.
type espDispatch struct {
	bridge          *ESPBridge
	result          ESPBridgeResult
	frame           server.DataFrame
	sessionEligible func() bool
	// Bound once per object, so handing them out allocates nothing.
	run        func(context.Context) error
	withActive func(func()) bool
}

func (b *ESPBridge) newDispatch() *espDispatch {
	if d, ok := b.dispatches.Get().(*espDispatch); ok {
		return d
	}
	d := &espDispatch{bridge: b}
	d.run, d.withActive = d.dispatch, d.active
	return d
}

// recycle returns d once nothing refers to its result or frame.
func (d *espDispatch) recycle() {
	b, run, withActive := d.bridge, d.run, d.withActive
	*d = espDispatch{bridge: b, run: run, withActive: withActive}
	b.dispatches.Put(d)
}

// dispatch delivers the result unless its flow, SA or session was retired
// after decryption.
func (d *espDispatch) dispatch(ctx context.Context) error {
	b, result := d.bridge, d.result
	b.mu.RLock()
	flow, exists := b.flows[result.logicalKey]
	b.mu.RUnlock()
	eligible, reason := true, DropReason(0)
	switch {
	case !exists:
		eligible, reason = false, DropUpFlowMissing
	case flow.session != result.association:
		eligible, reason = false, DropUpFlowMismatch
	case !result.association.Active():
		eligible, reason = false, DropUpSAInactive
	case !d.sessionEligible():
		eligible, reason = false, DropUpSessionIneligible
	}
	// Never hold b.mu while invoking callbacks: they may send, acquiring
	// outboundMu and then b.mu. Never acquire outboundMu with b.mu held;
	// recursive RLock can deadlock when a writer is waiting.
	result.WithActive = d.withActive
	if !eligible {
		if tunnelID, sessionID, ok := resultSession(result.L2TP); ok {
			b.Drops.Record(tunnelID, sessionID, reason, result.logicalKey, nil)
		}
		result.L2TP.Opened = nil
		result.L2TP.Data = nil
	}
	err := b.HandleResult(ctx, result)
	if batch, ok := ctx.Value(dispatchBatchKey{}).(*dispatchBatch); ok {
		batch.done = append(batch.done, d)
	}
	return err
}

// active runs f while the result's flow, SA and session are all still the
// ones it was decrypted for, excluding teardown meanwhile.
func (d *espDispatch) active(f func()) bool {
	b, result := d.bridge, d.result
	b.deliveryMu.RLock()
	defer b.deliveryMu.RUnlock()
	b.mu.RLock()
	flow, exists := b.flows[result.logicalKey]
	active := exists && flow.session == result.association && result.association.Active()
	b.mu.RUnlock()
	if !active || !d.sessionEligible() {
		return false
	}
	f()
	return true
}

type dispatchBatch struct{ done []*espDispatch }
type dispatchBatchKey struct{}

// WithDeliveryBatch wraps a delivery batch (the context and flush from an
// ipsec.ESPTransportServer NewDeliveryBatch) so the packets it dispatches
// return their delivery state to the bridge once flush has returned.
func (b *ESPBridge) WithDeliveryBatch(ctx context.Context, flush func() error) (context.Context, func() error) {
	batch := &dispatchBatch{}
	return context.WithValue(ctx, dispatchBatchKey{}, batch), func() error {
		err := flush()
		for i, d := range batch.done {
			d.recycle()
			batch.done[i] = nil
		}
		batch.done = batch.done[:0]
		return err
	}
}
