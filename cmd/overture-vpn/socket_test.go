package main

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
)

type socketTestConn struct{ net.PacketConn }

func TestListenerReceiveBufferWiring(t *testing.T) {
	c := defaultConfig()
	c.IPsec.ReceiveBuffer = 1048576
	for _, listener := range []string{"raw ESP", "NAT-T"} {
		conn := &socketTestConn{}
		for _, effective := range []int{212992, 2 * 1048576} {
			var logs []string
			calls := 0
			err := configureReceiveBuffer(listener, conn, c.IPsec.ReceiveBuffer, func(got net.PacketConn, requested int) (int, bool, error) {
				calls++
				if got != conn || requested != c.IPsec.ReceiveBuffer {
					t.Fatal("listener settings lost")
				}
				return effective, false, nil
			}, func(f string, args ...any) { logs = append(logs, fmt.Sprintf(f, args...)) })
			if err != nil || calls != 1 || !strings.Contains(logs[0], "requested=1048576") || !strings.Contains(logs[0], fmt.Sprint("effective=", effective)) || !strings.Contains(logs[0], "forced=false") {
				t.Fatalf("%v %v", err, logs)
			}
			if effective == 212992 && (len(logs) != 2 || !strings.Contains(logs[1], "CAP_NET_ADMIN") || !strings.Contains(logs[1], "net.core.rmem_max")) {
				t.Fatal(logs)
			}
			if effective == 2*1048576 && len(logs) != 1 {
				t.Fatal(logs)
			}
		}
	}
}

func TestReceiveBufferWarningThresholdAndErrors(t *testing.T) {
	for _, request := range []int{0, 1000} {
		warnings := 0
		_ = configureReceiveBuffer("test", &socketTestConn{}, request, func(net.PacketConn, int) (int, bool, error) { return 1500, true, nil }, func(f string, args ...any) {
			if strings.Contains(f, "WARNING") {
				warnings++
			}
		})
		want := 0
		if runtime.GOOS == "linux" && request > 0 {
			want = 1
		}
		if warnings != want {
			t.Fatalf("warnings=%d want=%d", warnings, want)
		}
	}
	failure := errors.New("socket option failure")
	err := configureReceiveBuffer("test", &socketTestConn{}, 10, func(net.PacketConn, int) (int, bool, error) { return 0, false, failure }, func(string, ...any) { t.Fatal("success logged after failure") })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
}
