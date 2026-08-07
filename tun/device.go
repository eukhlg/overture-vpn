// Package tun provides native Linux TUN and macOS utun devices plus a routing
// bridge for the L2TP server data plane.
package tun

import (
	"errors"
	"io"
)

var ErrUnsupported = errors.New("tun: unsupported operating system")

type Config struct {
	// Name requests an interface name. Linux accepts names such as "l2tp0".
	// macOS accepts an explicit "utunN" or an empty name for automatic choice.
	Name string
}

type Device interface {
	io.ReadWriteCloser
	Name() string
}
