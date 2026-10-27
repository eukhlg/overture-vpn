//go:build linux

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type systemDevice struct {
	wgtun.Device
	name string
}

func (d *systemDevice) Name() string { return d.name }

// WireGuard reports bytes written. Our interface reports submitted packets.
func (d *systemDevice) Write(bufs [][]byte, offset int) (int, error) {
	_, err := d.Device.Write(bufs, offset)
	if err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func Open(config Config) (Device, error) {
	if err := validateBackend(config); err != nil {
		return nil, err
	}
	return openSystem(config)
}
func openSystem(config Config) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open: %w", err)
	}
	fail := func(err error) (Device, error) { unix.Close(fd); return nil, err }
	request, err := unix.NewIfreq(config.Name)
	if err != nil {
		return fail(err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		return fail(err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(fd), "tun")
	mtu := config.MTU
	if mtu == 0 {
		mtu = 1400
	}
	device, err := wgtun.CreateTUNFromFile(file, mtu)
	if err != nil {
		file.Close()
		return nil, err
	}
	name, err := device.Name()
	if err != nil {
		device.Close()
		return nil, err
	}
	go func() {
		for range device.Events() {
		}
	}()
	return &systemDevice{Device: device, name: name}, nil
}
