//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type systemDevice struct {
	wgtun.Device
	name    string
	offload bool
	writeMu sync.Mutex
}

func (d *systemDevice) Name() string { return d.name }

// WireGuard reports bytes written. Our interface reports submitted packets.
func (d *systemDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			return i, io.ErrShortBuffer
		}
	}
	if !d.offload {
		_, err := d.Device.Write(bufs, offset)
		if err != nil {
			return 0, err
		}
		return len(bufs), nil
	}
	if offset < 10 {
		return 0, io.ErrShortBuffer
	}
	// Leave non-TCP traffic uncoalesced, including UDP. Separate contiguous
	// TCP runs preserve the position of all excluded packets in the batch.
	for start := 0; start < len(bufs); {
		end := start + 1
		if tcpCandidate(bufs[start][offset:]) {
			for end < len(bufs) && tcpCandidate(bufs[end][offset:]) {
				end++
			}
		}
		if _, err := d.Device.Write(bufs[start:end], offset); err != nil {
			return start, err
		}
		start = end
	}
	return len(bufs), nil
}
func tcpCandidate(p []byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return false
	}
	return binary.BigEndian.Uint16(p[6:8])&0x3fff == 0
}
func (d *systemDevice) OffloadEnabled() bool { return d.offload }

func Open(config Config) (Device, error) {
	if err := validateBackend(config); err != nil {
		return nil, err
	}
	if !config.DisableOffload {
		device, err := openSystem(config, true)
		if err == nil {
			return device, nil
		}
		// Runtime rejection of VNET_HDR or TUNSETOFFLOAD falls back to a new
		// plain descriptor; never leave a half-enabled device on the data path.
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTTY) {
			return nil, err
		}
	}
	return openSystem(config, false)
}
func openSystem(config Config, offload bool) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open: %w", err)
	}
	fail := func(err error) (Device, error) { unix.Close(fd); return nil, err }
	request, err := unix.NewIfreq(config.Name)
	if err != nil {
		return fail(err)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if offload {
		flags |= unix.IFF_VNET_HDR
	}
	request.SetUint16(flags)
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
	return &systemDevice{Device: device, name: name, offload: offload}, nil
}

// Read uses caller storage directly even with VNET_HDR. Reverse segmentation
// allows the first output to alias the receive buffer without a staging copy.
func (d *systemDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	if !d.offload {
		return d.Device.Read(bufs, sizes, offset)
	}
	if offset < virtioNetHdrLen {
		return 0, io.ErrShortBuffer
	}
	in := bufs[0][offset-virtioNetHdrLen:]
	n, err := d.Device.File().Read(in)
	if err != nil {
		return 0, err
	}
	return handleVirtioRead(in[:n], bufs, sizes, offset)
}
