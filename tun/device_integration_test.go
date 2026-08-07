//go:build integration && (linux || darwin)

package tun

import "testing"

// Run explicitly with: go test -tags=integration ./tun -run TestOpenNativeDevice
// Linux generally requires CAP_NET_ADMIN; macOS may prompt for permission.
func TestOpenNativeDevice(t *testing.T) {
	device, err := Open(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if device.Name() == "" {
		t.Fatal("native device has an empty name")
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
}
