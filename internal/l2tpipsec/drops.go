package l2tpipsec

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DropReason classifies packets the protected data path discards on purpose.
// Upload reasons come from delivery-time checks of decrypted client packets;
// download reasons come from sending TUN packets to a client.
type DropReason uint8

const (
	// DropUpFlowMissing: no bridge flow exists for the client's logical peer.
	DropUpFlowMissing DropReason = iota
	// DropUpFlowMismatch: the flow now points at a different SA than the one
	// that decrypted the packet (for example after a peer address change).
	DropUpFlowMismatch
	// DropUpSAInactive: the decrypting SA was revoked or expired before delivery.
	DropUpSAInactive
	// DropUpSessionIneligible: the L2TP/PPP session is closed or not established.
	DropUpSessionIneligible
	// DropDownUnknownSA: the flow's SA is gone and no replacement exists.
	DropDownUnknownSA
	// DropDownNoFlow: no bridge flow exists for the session's peer.
	DropDownNoFlow
	// DropDownSALifetime: sealing hit a negotiated SA lifetime limit.
	DropDownSALifetime
	dropReasonCount
)

func (r DropReason) String() string {
	switch r {
	case DropUpFlowMissing:
		return "up-flow-missing"
	case DropUpFlowMismatch:
		return "up-flow-sa-mismatch"
	case DropUpSAInactive:
		return "up-sa-inactive"
	case DropUpSessionIneligible:
		return "up-session-ineligible"
	case DropDownUnknownSA:
		return "down-unknown-sa"
	case DropDownNoFlow:
		return "down-no-flow"
	case DropDownSALifetime:
		return "down-sa-lifetime"
	default:
		return "unknown"
	}
}

// DropLogInterval bounds repeated drop logs per session and reason.
const DropLogInterval = 5 * time.Second

type dropSessionKey struct{ tunnel, session uint16 }

type sessionDrops struct {
	counts [dropReasonCount]atomic.Uint64
	mu     sync.Mutex
	logged [dropReasonCount]time.Time
	seen   [dropReasonCount]uint64 // count at the previous logged line
}

// DropCounters counts intentional drops per L2TP session and, when Debugf is
// set, logs them: the first drop per session and reason immediately, then at
// most once per DropLogInterval with the number suppressed in between.
// Counting is lock-free; the zero value is ready to use.
type DropCounters struct {
	Debugf   func(string, ...any)
	sessions sync.Map         // dropSessionKey -> *sessionDrops
	now      func() time.Time // tests only
}

func NewDropCounters(debugf func(string, ...any)) *DropCounters {
	return &DropCounters{Debugf: debugf}
}

// Record counts one dropped packet. peer (any printable address) and err are
// only formatted when a line is actually logged. A nil receiver ignores the call.
func (d *DropCounters) Record(tunnelID, sessionID uint16, reason DropReason, peer any, err error) {
	if d == nil || reason >= dropReasonCount {
		return
	}
	key := dropSessionKey{tunnel: tunnelID, session: sessionID}
	value, ok := d.sessions.Load(key)
	if !ok {
		value, _ = d.sessions.LoadOrStore(key, &sessionDrops{})
	}
	drops := value.(*sessionDrops)
	count := drops.counts[reason].Add(1)
	if d.Debugf == nil {
		return
	}
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	drops.mu.Lock()
	last := drops.logged[reason]
	if !last.IsZero() && now.Sub(last) < DropLogInterval {
		drops.mu.Unlock()
		return
	}
	suppressed := count - drops.seen[reason] - 1
	if last.IsZero() {
		suppressed = 0
	}
	drops.logged[reason], drops.seen[reason] = now, count
	drops.mu.Unlock()
	format := "ipsec drop tunnel=%d session=%d reason=%s peer=%v error=%v count=%d"
	args := []any{tunnelID, sessionID, reason, peer, err, count}
	if suppressed > 0 {
		format += " suppressed=%d"
		args = append(args, suppressed)
	}
	d.Debugf(format, args...)
}

// Count reports the drops recorded so far for one session and reason.
func (d *DropCounters) Count(tunnelID, sessionID uint16, reason DropReason) uint64 {
	if d == nil || reason >= dropReasonCount {
		return 0
	}
	value, ok := d.sessions.Load(dropSessionKey{tunnel: tunnelID, session: sessionID})
	if !ok {
		return 0
	}
	return value.(*sessionDrops).counts[reason].Load()
}

// Take removes a session's counters and returns them as
// "reason:count,reason:count", or "" when nothing was dropped. Call it when
// the session closes, so reused tunnel and session IDs start from zero.
func (d *DropCounters) Take(tunnelID, sessionID uint16) string {
	if d == nil {
		return ""
	}
	value, ok := d.sessions.LoadAndDelete(dropSessionKey{tunnel: tunnelID, session: sessionID})
	if !ok {
		return ""
	}
	drops := value.(*sessionDrops)
	var parts []string
	for reason := DropReason(0); reason < dropReasonCount; reason++ {
		if n := drops.counts[reason].Load(); n != 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", reason, n))
		}
	}
	return strings.Join(parts, ",")
}
