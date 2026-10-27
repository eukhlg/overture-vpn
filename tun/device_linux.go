//go:build linux

package tun

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF  = 0x400454ca
	iffTUN     = 0x0001
	iffNoPI    = 0x1000
	ifNameSize = 16
)

type nativeDevice struct {
	*os.File
	name string
}

func Open(config Config) (Device, error) {
	if err := validateBackend(config); err != nil {
		return nil, err
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}
	var request [40]byte
	if len(config.Name) >= ifNameSize {
		file.Close()
		return nil, fmt.Errorf("tun: interface name is too long")
	}
	copy(request[:ifNameSize], config.Name)
	*(*uint16)(unsafe.Pointer(&request[ifNameSize])) = iffTUN | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}
	nameLength := 0
	for nameLength < ifNameSize && request[nameLength] != 0 {
		nameLength++
	}
	return &nativeDevice{File: file, name: string(request[:nameLength])}, nil
}

func (d *nativeDevice) Name() string { return d.name }

func (d *nativeDevice) BatchSize() int { return 1 }
func (d *nativeDevice) MTU() (int, error) {
	iface, err := net.InterfaceByName(d.name)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}
func (d *nativeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	n, err := d.File.Read(bufs[0][offset:])
	sizes[0] = n
	if n > 0 {
		return 1, err
	}
	return 0, err
}
func (d *nativeDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset > len(b) {
			return i, io.ErrShortBuffer
		}
		n, err := d.File.Write(b[offset:])
		if err != nil {
			return i, err
		}
		if n != len(b)-offset {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
