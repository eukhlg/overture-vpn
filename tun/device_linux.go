//go:build linux

package tun

import (
	"fmt"
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
