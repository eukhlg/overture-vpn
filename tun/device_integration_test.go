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

// Linux only: the queue length is applied after the device is created.
func TestOpenNativeDeviceTxQueueLength(t *testing.T) {
	device, err := Open(Config{TxQueueLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	q, ok := device.(interface{ TxQueueLength() (int, error) })
	if !ok {
		t.Skip("device does not report its queue length")
	}
	if n, err := q.TxQueueLength(); err != nil || n != 32 {
		t.Fatalf("tx queue length %d, %v", n, err)
	}
	automatic, err := Open(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer automatic.Close()
	offload, _ := automatic.(interface{ OffloadEnabled() bool })
	if offload == nil || !offload.OffloadEnabled() {
		t.Skip("offload unavailable")
	}
	if n, err := automatic.(interface{ TxQueueLength() (int, error) }).TxQueueLength(); err != nil || n != DefaultOffloadTxQueueLength {
		t.Fatalf("automatic tx queue length %d, %v", n, err)
	}
}
