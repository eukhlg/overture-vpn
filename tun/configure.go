package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
)

type LinkConfig struct {
	Address netip.Prefix
	MTU     int
}

type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tun: %s: %w: %s", name, err, output)
	}
	return nil
}

// Configure assigns the server prefix and activates the interface. The
// returned cleanup function reverses the activation. It does not enable host
// forwarding or NAT.
func Configure(ctx context.Context, device Device, config LinkConfig, runner CommandRunner) (func(context.Context) error, error) {
	if device == nil {
		return nil, errors.New("tun: device is required")
	}
	if !config.Address.IsValid() || !config.Address.Addr().Is4() {
		return nil, errors.New("tun: an IPv4 prefix is required")
	}
	if config.MTU == 0 {
		config.MTU = 1400
	}
	if config.MTU < 576 || config.MTU > 65535 {
		return nil, errors.New("tun: MTU must be between 576 and 65535")
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return configureNative(ctx, device.Name(), config, runner)
}
