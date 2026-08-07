//go:build !linux && !darwin

package tun

import "context"

func configureNative(context.Context, string, LinkConfig, CommandRunner) (func(context.Context) error, error) {
	return nil, ErrUnsupported
}
