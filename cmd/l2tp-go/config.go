package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type networkConfig struct {
	Subnet, TUNPrefix          netip.Prefix
	Server, PoolStart, PoolEnd netip.Addr
	PoolSize                   int
}

func loadNetworkConfig() (networkConfig, error) {
	subnet, err := netip.ParsePrefix(envString("L2TP_CLIENT_SUBNET", "10.0.0.0/24"))
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() > 30 {
		return networkConfig{}, fmt.Errorf("L2TP_CLIENT_SUBNET must be an IPv4 prefix of /30 or larger")
	}
	subnet = subnet.Masked()
	server, err := addressInSubnet(subnet, envString("L2TP_SERVER_IP", "1"))
	if err != nil {
		return networkConfig{}, fmt.Errorf("L2TP_SERVER_IP: %w", err)
	}
	startValue := envString("L2TP_CLIENT_POOL_START", envString("L2TP_CLIENT_SUBNET_START", "2"))
	if legacy, ok := lookupNonempty("L2TP_CLIENT_IP"); ok {
		_, poolStartSet := lookupNonempty("L2TP_CLIENT_POOL_START")
		_, subnetStartSet := lookupNonempty("L2TP_CLIENT_SUBNET_START")
		if !poolStartSet && !subnetStartSet {
			startValue = legacy
		}
	}
	start, err := addressInSubnet(subnet, startValue)
	if err != nil {
		return networkConfig{}, fmt.Errorf("L2TP_CLIENT_SUBNET_START: %w", err)
	}
	size := envInt("L2TP_CLIENT_POOL_SIZE", envInt("L2TP_CLIENT_SUBNET_LIMIT", 50))
	if size <= 0 {
		return networkConfig{}, fmt.Errorf("L2TP_CLIENT_SUBNET_LIMIT must be positive")
	}
	endValue := uint64(ipv4Uint32(start)) + uint64(size) - 1
	if endValue > uint64(ipv4Broadcast(subnet))-1 || start == server || (ipv4Uint32(server) >= ipv4Uint32(start) && uint64(ipv4Uint32(server)) <= endValue) {
		return networkConfig{}, fmt.Errorf("client pool does not fit subnet or includes server address")
	}
	end := uint32IPv4(uint32(endValue))
	return networkConfig{Subnet: subnet, TUNPrefix: netip.PrefixFrom(server, subnet.Bits()), Server: server, PoolStart: start, PoolEnd: end, PoolSize: size}, nil
}

func addressInSubnet(prefix netip.Prefix, value string) (netip.Addr, error) {
	if offset, err := strconv.ParseUint(value, 10, 32); err == nil {
		candidate := uint64(ipv4Uint32(prefix.Masked().Addr())) + offset
		if candidate > uint64(ipv4Broadcast(prefix)) {
			return netip.Addr{}, fmt.Errorf("host offset %d is outside %s", offset, prefix)
		}
		address := uint32IPv4(uint32(candidate))
		if address == prefix.Masked().Addr() || ipv4Uint32(address) == ipv4Broadcast(prefix) {
			return netip.Addr{}, fmt.Errorf("%s is not a usable host address", address)
		}
		return address, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !prefix.Contains(address) {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address inside %s", value, prefix)
	}
	if address == prefix.Masked().Addr() || ipv4Uint32(address) == ipv4Broadcast(prefix) {
		return netip.Addr{}, fmt.Errorf("%s is not a usable host address", address)
	}
	return address, nil
}

func parseUsers(value string) (map[string]string, error) {
	users := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, password, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || password == "" {
			return nil, fmt.Errorf("L2TP_USERS entries must use username=password")
		}
		if _, exists := users[name]; exists {
			return nil, fmt.Errorf("duplicate L2TP_USERS username %q", name)
		}
		users[name] = password
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("at least one user is required")
	}
	return users, nil
}

func lookupNonempty(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	return value, ok && value != ""
}

func ipv4Uint32(address netip.Addr) uint32 {
	b := address.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func uint32IPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
func ipv4Broadcast(prefix netip.Prefix) uint32 {
	return ipv4Uint32(prefix.Masked().Addr()) | ^(uint32(0xffffffff) << (32 - prefix.Bits()))
}
