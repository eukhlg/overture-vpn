//go:build linux

package tun

import (
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
	name     string
	offload  bool
	writeMu  sync.Mutex
	tcpTable *tcpGROTable
	udpTable *udpGROTable
	toWrite  []int
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
		for i, b := range bufs {
			var prefix [10]byte
			if err := writeVector(d.Device.File(), [][]byte{prefix[:], b[offset:]}); err != nil {
				return i, err
			}
		}
		return len(bufs), nil
	}
	if d.tcpTable == nil {
		d.tcpTable = newTCPGROTable()
		d.udpTable = newUDPGROTable()
	}
	defer d.tcpTable.reset()
	defer d.udpTable.reset()
	d.toWrite = d.toWrite[:0]
	if err := handleGRO(bufs, offset, d.tcpTable, d.udpTable, false, &d.toWrite); err != nil {
		return 0, err
	}
	for _, i := range d.toWrite {
		b := bufs[i][offset-virtioNetHdrLen:]
		n, err := d.Device.File().Write(b)
		if err != nil {
			return 0, err
		}
		if n != len(b) {
			return 0, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}

func (d *systemDevice) OffloadEnabled() bool { return d.offload }

func Open(config Config) (Device, error) {
	if err := validateBackend(config); err != nil {
		return nil, err
	}
	return openWithFallback(config, openSystem)
}
func openWithFallback(config Config, open func(Config, bool) (Device, error)) (Device, error) {
	if !config.DisableOffload {
		device, err := open(config, true)
		if err == nil {
			return device, nil
		}
		// Runtime rejection of VNET_HDR or TUNSETOFFLOAD falls back to a new
		// plain descriptor; never leave a half-enabled device on the data path.
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTTY) {
			return nil, err
		}
	}
	return open(config, false)
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

func writeVector(file *os.File, bufs [][]byte) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Write(func(fd uintptr) bool {
		n, e := unix.Writev(int(fd), bufs)
		if e == unix.EAGAIN || e == unix.EWOULDBLOCK {
			return false
		}
		result = e
		want := 0
		for _, b := range bufs {
			want += len(b)
		}
		if e == nil && n != want {
			result = io.ErrShortWrite
		}
		return true
	})
	if err != nil {
		return err
	}
	return result
}
