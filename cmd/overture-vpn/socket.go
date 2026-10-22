package main

import (
	"fmt"
	"net"
	"runtime"
)

type receiveBufferSetter func(net.PacketConn, int) (int, bool, error)

func configureReceiveBuffer(listener string, conn net.PacketConn, requested int, set receiveBufferSetter, logf func(string, ...any)) error {
	effective, forced, err := set(conn, requested)
	if err != nil {
		return fmt.Errorf("configure %s receive buffer: %w", listener, err)
	}
	logf("listener=%q receive_buffer requested=%d effective=%d forced=%t", listener, requested, effective, forced)
	target := int64(requested)
	if runtime.GOOS == "linux" {
		target *= 2
	}
	if requested > 0 && int64(effective) < target {
		logf("WARNING listener=%q receive buffer capped: requested=%d effective=%d; grant CAP_NET_ADMIN or raise net.core.rmem_max on Linux", listener, requested, effective)
	}
	return nil
}
