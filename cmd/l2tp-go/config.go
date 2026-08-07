package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

type userConfig struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}
type appConfig struct {
	Server struct {
		Listen   string `toml:"listen"`
		Hostname string `toml:"hostname"`
		Debug    bool   `toml:"debug"`
	} `toml:"server"`
	Authentication struct {
		Method string       `toml:"method"`
		Users  []userConfig `toml:"users"`
	} `toml:"authentication"`
	Network struct {
		Subnet          string `toml:"subnet"`
		ServerAddress   string `toml:"server_address"`
		ClientPoolStart string `toml:"client_pool_start"`
		ClientPoolSize  int    `toml:"client_pool_size"`
		DNS             string `toml:"dns"`
		MTU             int    `toml:"mtu"`
	} `toml:"network"`
	TUN struct {
		Enabled bool   `toml:"enabled"`
		Name    string `toml:"name"`
	} `toml:"tun"`
	NAT struct {
		Enabled   bool   `toml:"enabled"`
		Interface string `toml:"interface"`
	} `toml:"nat"`
	Limits struct {
		Sessions          int `toml:"sessions"`
		SessionsPerTunnel int `toml:"sessions_per_tunnel"`
		SessionsPerUser   int `toml:"sessions_per_user"`
	} `toml:"limits"`
}

type networkConfig struct {
	Subnet, TUNPrefix          netip.Prefix
	Server, PoolStart, PoolEnd netip.Addr
	PoolSize                   int
}

func defaultConfig() appConfig {
	var c appConfig
	c.Server.Listen, c.Server.Hostname = ":1701", "l2tp-go"
	c.Authentication.Method = "mschapv2"
	c.Network.Subnet, c.Network.ServerAddress, c.Network.ClientPoolStart = "10.0.0.0/24", "1", "2"
	c.Network.ClientPoolSize, c.Network.DNS, c.Network.MTU = 50, "1.1.1.1", 1400
	c.TUN.Name = ""
	c.NAT.Enabled = true
	c.Limits.Sessions, c.Limits.SessionsPerTunnel, c.Limits.SessionsPerUser = 50, 1, 1
	return c
}

func loadConfig(path string) (appConfig, error) {
	c := defaultConfig()
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return c, fmt.Errorf("open config %q: %w", path, err)
		}
		defer file.Close()
		if err := toml.NewDecoder(file).DisallowUnknownFields().Decode(&c); err != nil {
			return c, fmt.Errorf("decode config %q: %w", path, err)
		}
	}
	if err := applyEnvironment(&c); err != nil {
		return c, err
	}
	return c, nil
}

func applyEnvironment(c *appConfig) error {
	overrideString("L2TP_LISTEN", &c.Server.Listen)
	overrideString("L2TP_HOSTNAME", &c.Server.Hostname)
	if err := overrideBool("L2TP_DEBUG", &c.Server.Debug); err != nil {
		return err
	}
	overrideString("L2TP_AUTH", &c.Authentication.Method)
	if value, ok := lookupNonempty("L2TP_USERS"); ok {
		users, err := parseUsers(value)
		if err != nil {
			return err
		}
		c.Authentication.Users = userMapConfigs(users)
	}
	if len(c.Authentication.Users) == 0 {
		if password, ok := lookupNonempty("L2TP_PASSWORD"); ok {
			username := envString("L2TP_USERNAME", "vpn")
			c.Authentication.Users = []userConfig{{Username: username, Password: password}}
		}
	}
	overrideString("L2TP_CLIENT_SUBNET", &c.Network.Subnet)
	overrideString("L2TP_SERVER_IP", &c.Network.ServerAddress)
	overrideString("L2TP_CLIENT_POOL_START", &c.Network.ClientPoolStart)
	if _, ok := lookupNonempty("L2TP_CLIENT_POOL_START"); !ok {
		overrideString("L2TP_CLIENT_SUBNET_START", &c.Network.ClientPoolStart)
		overrideString("L2TP_CLIENT_IP", &c.Network.ClientPoolStart)
	}
	if err := overrideInt("L2TP_CLIENT_POOL_SIZE", &c.Network.ClientPoolSize); err != nil {
		return err
	}
	if _, ok := lookupNonempty("L2TP_CLIENT_POOL_SIZE"); !ok {
		if err := overrideInt("L2TP_CLIENT_SUBNET_LIMIT", &c.Network.ClientPoolSize); err != nil {
			return err
		}
	}
	overrideString("L2TP_DNS", &c.Network.DNS)
	if err := overrideInt("L2TP_MTU", &c.Network.MTU); err != nil {
		return err
	}
	if err := overrideBool("L2TP_TUN_ENABLED", &c.TUN.Enabled); err != nil {
		return err
	}
	overrideString("L2TP_TUN_NAME", &c.TUN.Name)
	if err := overrideBool("L2TP_NAT_ENABLED", &c.NAT.Enabled); err != nil {
		return err
	}
	overrideString("L2TP_NAT_INTERFACE", &c.NAT.Interface)
	if err := overrideInt("L2TP_MAX_SESSIONS", &c.Limits.Sessions); err != nil {
		return err
	}
	if err := overrideInt("L2TP_MAX_SESSIONS_PER_TUNNEL", &c.Limits.SessionsPerTunnel); err != nil {
		return err
	}
	if err := overrideInt("L2TP_MAX_SESSIONS_PER_USER", &c.Limits.SessionsPerUser); err != nil {
		return err
	}
	return nil
}

func (c appConfig) validate() (networkConfig, map[string]string, error) {
	users := make(map[string]string)
	for _, user := range c.Authentication.Users {
		if user.Username == "" || user.Password == "" {
			return networkConfig{}, nil, fmt.Errorf("authentication users require username and password")
		}
		if _, exists := users[user.Username]; exists {
			return networkConfig{}, nil, fmt.Errorf("duplicate username %q", user.Username)
		}
		users[user.Username] = user.Password
	}
	if len(users) == 0 {
		return networkConfig{}, nil, fmt.Errorf("at least one authentication user is required")
	}
	if c.Network.MTU <= 0 || c.Limits.Sessions < 0 || c.Limits.SessionsPerTunnel < 0 || c.Limits.SessionsPerUser < 0 {
		return networkConfig{}, nil, fmt.Errorf("MTU must be positive and session limits cannot be negative")
	}
	network, err := resolveNetwork(c.Network.Subnet, c.Network.ServerAddress, c.Network.ClientPoolStart, c.Network.ClientPoolSize)
	return network, users, err
}

func resolveNetwork(subnetValue, serverValue, startValue string, size int) (networkConfig, error) {
	subnet, err := netip.ParsePrefix(subnetValue)
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() > 30 {
		return networkConfig{}, fmt.Errorf("network.subnet must be an IPv4 prefix of /30 or larger")
	}
	subnet = subnet.Masked()
	server, err := addressInSubnet(subnet, serverValue)
	if err != nil {
		return networkConfig{}, fmt.Errorf("network.server_address: %w", err)
	}
	start, err := addressInSubnet(subnet, startValue)
	if err != nil {
		return networkConfig{}, fmt.Errorf("network.client_pool_start: %w", err)
	}
	if size <= 0 {
		return networkConfig{}, fmt.Errorf("network.client_pool_size must be positive")
	}
	endValue := uint64(ipv4Uint32(start)) + uint64(size) - 1
	if endValue > uint64(ipv4Broadcast(subnet))-1 || start == server || (ipv4Uint32(server) >= ipv4Uint32(start) && uint64(ipv4Uint32(server)) <= endValue) {
		return networkConfig{}, fmt.Errorf("client pool does not fit subnet or includes server address")
	}
	return networkConfig{Subnet: subnet, TUNPrefix: netip.PrefixFrom(server, subnet.Bits()), Server: server, PoolStart: start, PoolEnd: uint32IPv4(uint32(endValue)), PoolSize: size}, nil
}

func configPathFromArgs(args []string) string {
	path := os.Getenv("L2TP_CONFIG")
	for i, arg := range args {
		if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			_, path, _ = strings.Cut(arg, "=")
		} else if (arg == "--config" || arg == "-config") && i+1 < len(args) {
			path = args[i+1]
		}
	}
	return path
}
func printResolvedValue(name string, c appConfig, network networkConfig) error {
	switch name {
	case "network.subnet":
		fmt.Println(network.Subnet)
	case "nat.enabled":
		fmt.Println(c.NAT.Enabled)
	case "nat.interface":
		fmt.Println(c.NAT.Interface)
	default:
		return fmt.Errorf("unknown config value %q", name)
	}
	return nil
}
func parseUsers(value string) (map[string]string, error) {
	users := map[string]string{}
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
func userMapConfigs(users map[string]string) []userConfig {
	out := make([]userConfig, 0, len(users))
	for name, password := range users {
		out = append(out, userConfig{Username: name, Password: password})
	}
	return out
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
	return address, nil
}
func lookupNonempty(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	return value, ok && value != ""
}
func overrideString(name string, target *string) {
	if value, ok := lookupNonempty(name); ok {
		*target = value
	}
}
func overrideBool(name string, target *bool) error {
	if value, ok := lookupNonempty(name); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s must be a boolean: %w", name, err)
		}
		*target = parsed
	}
	return nil
}
func overrideInt(name string, target *int) error {
	if value, ok := lookupNonempty(name); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", name, err)
		}
		*target = parsed
	}
	return nil
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
