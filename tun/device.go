// Package tun provides native Linux TUN and macOS utun devices plus a routing
// bridge for the L2TP server data plane.
package tun

import (
	"errors"
)

var ErrUnsupported = errors.New("tun: unsupported operating system")

// DefaultOffloadTxQueueLength bounds the TUN transmit ring when offload is
// active. Ring entries are then super-packets (~40 KB on average in
// download-path-2026-10-27), so the kernel default of 500 lets TCP park
// megabytes of window there: download ping 9.6 ms (P1) / 37.8 ms (P4).
// The TUN driver drops at a full ring instead of pushing back into the
// qdisc, so a qdisc cannot bound this queue; 64 entries gave 5.2 / 4.0 ms at
// unchanged throughput.
const DefaultOffloadTxQueueLength = 64

type Config struct {
	MTU            int
	DisableOffload bool
	Backend        string

	// TxQueueLength sets the Linux interface transmit queue (txqueuelen),
	// which the TUN driver uses as its packet ring toward the reader. Zero
	// selects DefaultOffloadTxQueueLength when offload is active and keeps the
	// kernel setting otherwise. Ignored on macOS.
	TxQueueLength int

	// Name requests an interface name. Linux accepts names such as "l2tp0".
	// macOS accepts an explicit "utunN" or an empty name for automatic choice.
	Name string
}

type Device interface {
	// Read fills packet buffers starting at offset and reports packet lengths.
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	// Write consumes packets beginning at offset; buffers remain caller-owned.
	// With write offload, GRO may grow entries in place into spare capacity and
	// swap entries; Router zeroes the grown bytes after Write returns.
	Write(bufs [][]byte, offset int) (int, error)
	BatchSize() int
	MTU() (int, error)
	Close() error
	Name() string
}

func validateBackend(config Config) error {
	if config.Backend != "" && config.Backend != "system" {
		return errors.New("tun: unsupported backend: " + config.Backend)
	}
	return nil
}
