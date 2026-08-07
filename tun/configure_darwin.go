//go:build darwin

package tun

import (
	"context"
	"strconv"
)

func configureNative(ctx context.Context, name string, config LinkConfig, runner CommandRunner) (func(context.Context) error, error) {
	address := config.Address.Addr().String()
	if err := runner.Run(ctx, "ifconfig", name, "inet", address, address, "netmask", prefixMask(config.Address.Bits()), "mtu", strconv.Itoa(config.MTU), "up"); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return runner.Run(ctx, "ifconfig", name, "down") }, nil
}

func prefixMask(bits int) string {
	mask := uint32(0)
	if bits != 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	return strconv.Itoa(int(mask>>24)) + "." + strconv.Itoa(int(mask>>16)&255) + "." + strconv.Itoa(int(mask>>8)&255) + "." + strconv.Itoa(int(mask)&255)
}
