package main

import (
	"context"

	"github.com/eukhlg/l2tp-go/server"
	"github.com/eukhlg/overture-vpn/tun"
)

// Capture the actual Engine identity before transferring a packet to flush.
// WithBindingGuard preserves the protected transport's additional guard too.
func plainRouteContext(ctx context.Context, engine *server.Engine, frame server.DataFrame) context.Context {
	return tun.WithBindingGuard(ctx, engine.SessionBindingGuard(frame.TunnelID, frame.Session.LocalID))
}
