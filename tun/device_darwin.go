//go:build darwin

package tun

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	pfSystem      = 32
	afSystem      = 32
	afSysControl  = 2
	syspControl   = 2
	ctlIOCGInfo   = 0xc0644e03
	utunOptIfName = 2
)

type nativeDevice struct {
	file *os.File
	name string
}

type controlInfo struct {
	ID   uint32
	Name [96]byte
}

type rawSockaddrControl struct {
	Len      uint8
	Family   uint8
	SysAddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

func Open(config Config) (Device, error) {
	if err := validateBackend(config); err != nil {
		return nil, err
	}
	unit, err := utunUnit(config.Name)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(pfSystem, syscall.SOCK_DGRAM, syspControl)
	if err != nil {
		return nil, fmt.Errorf("tun: create utun socket: %w", err)
	}
	info := controlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ctlIOCGInfo, uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: find utun control: %w", errno)
	}
	address := rawSockaddrControl{Len: uint8(unsafe.Sizeof(rawSockaddrControl{})), Family: afSystem, SysAddr: afSysControl, ID: info.ID, Unit: unit}
	_, _, errno = syscall.RawSyscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&address)), unsafe.Sizeof(address))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("tun: connect utun: %w", errno)
	}
	name, err := socketOptionString(fd, syspControl, utunOptIfName)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &nativeDevice{file: os.NewFile(uintptr(fd), name), name: name}, nil
}

func utunUnit(name string) (uint32, error) {
	if name == "" {
		return 0, nil
	}
	if !strings.HasPrefix(name, "utun") {
		return 0, fmt.Errorf("tun: macOS interface name must be utunN")
	}
	index, err := strconv.ParseUint(strings.TrimPrefix(name, "utun"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("tun: invalid utun name %q", name)
	}
	return uint32(index) + 1, nil
}

func socketOptionString(fd, level, option int) (string, error) {
	buffer := make([]byte, 64)
	length := uint32(len(buffer))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(option), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)), 0)
	if errno != 0 {
		return "", fmt.Errorf("tun: get interface name: %w", errno)
	}
	if length != 0 && buffer[length-1] == 0 {
		length--
	}
	return string(buffer[:length]), nil
}

func (d *nativeDevice) Name() string { return d.name }
func (d *nativeDevice) Close() error { return d.file.Close() }

func (d *nativeDevice) BatchSize() int { return 1 }
func (d *nativeDevice) MTU() (int, error) {
	iface, err := net.InterfaceByName(d.name)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}
func (d *nativeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 4 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	b := bufs[0][offset-4:]
	n, err := d.file.Read(b)
	if n < 4 {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	if binary.BigEndian.Uint32(b[:4]) != syscall.AF_INET {
		return 0, fmt.Errorf("tun: non-IPv4 utun packet")
	}
	sizes[0] = n - 4
	return 1, err
}
func (d *nativeDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 4 || offset > len(b) {
			return i, io.ErrShortBuffer
		}
		binary.BigEndian.PutUint32(b[offset-4:offset], syscall.AF_INET)
		n, err := d.file.Write(b[offset-4:])
		if err != nil {
			return i, err
		}
		if n != len(b)-offset+4 {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
