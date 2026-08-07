//go:build !linux && !darwin

package tun

func Open(Config) (Device, error) { return nil, ErrUnsupported }
