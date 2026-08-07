//go:build linux

package tun

import (
	"context"
	"strconv"
)

func configureNative(ctx context.Context, name string, config LinkConfig, runner CommandRunner) (func(context.Context) error, error) {
	if err := runner.Run(ctx, "ip", "address", "add", config.Address.String(), "dev", name); err != nil {
		return nil, err
	}
	if err := runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(config.MTU), "up"); err != nil {
		_ = runner.Run(ctx, "ip", "address", "del", config.Address.String(), "dev", name)
		return nil, err
	}
	return func(ctx context.Context) error {
		return runner.Run(ctx, "ip", "link", "set", "dev", name, "down")
	}, nil
}
