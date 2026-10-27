// Package tun provides native Linux TUN and macOS utun devices plus a routing
// bridge for the L2TP server data plane.
package tun

import (
	"errors"
)

var ErrUnsupported = errors.New("tun: unsupported operating system")

type Config struct {
	MTU            int
	DisableOffload bool
	Backend        string

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
