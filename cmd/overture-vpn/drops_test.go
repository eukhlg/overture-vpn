package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/overture-vpn/internal/l2tpipsec"
)

func TestDownloadDropClassification(t *testing.T) {
	lifetime := &esp.LifetimeError{Reason: esp.LifetimeBytes, Bytes: 9, Limit: 10}
	cases := []struct {
		err     error
		reason  l2tpipsec.DropReason
		dropped bool
	}{
		{nil, 0, false},
		{errors.New("socket closed"), 0, false},
		{ipsec.ErrUnknownESP, l2tpipsec.DropDownUnknownSA, true},
		{fmt.Errorf("send: %w", ipsec.ErrESPPeer), l2tpipsec.DropDownNoFlow, true},
		{esp.ErrSALifetime, l2tpipsec.DropDownSALifetime, true},
		{lifetime, l2tpipsec.DropDownSALifetime, true},
	}
	for _, tc := range cases {
		reason, dropped := downloadDrop(tc.err)
		if dropped != tc.dropped || (dropped && reason != tc.reason) {
			t.Fatalf("err=%v: got %s/%t, want %s/%t", tc.err, reason, dropped, tc.reason, tc.dropped)
		}
	}
}
