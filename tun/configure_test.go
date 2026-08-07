package tun

import (
	"context"
	"net/netip"
	"testing"
)

type fakeRunner struct{ calls int }

func (r *fakeRunner) Run(context.Context, string, ...string) error { r.calls++; return nil }

func TestConfigureAndCleanup(t *testing.T) {
	device := newMemoryDevice()
	runner := &fakeRunner{}
	cleanup, err := Configure(context.Background(), device, LinkConfig{Address: netip.MustParsePrefix("10.0.0.1/24"), MTU: 1400}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls == 0 {
		t.Fatal("configuration command was not run")
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRejectsInvalidInput(t *testing.T) {
	if _, err := Configure(context.Background(), nil, LinkConfig{}, nil); err == nil {
		t.Fatal("nil device accepted")
	}
	device := newMemoryDevice()
	if _, err := Configure(context.Background(), device, LinkConfig{Address: netip.MustParsePrefix("2001:db8::/64")}, &fakeRunner{}); err == nil {
		t.Fatal("IPv6 prefix accepted")
	}
	if _, err := Configure(context.Background(), device, LinkConfig{Address: netip.MustParsePrefix("10.0.0.1/24"), MTU: 100}, &fakeRunner{}); err == nil {
		t.Fatal("small MTU accepted")
	}
}
