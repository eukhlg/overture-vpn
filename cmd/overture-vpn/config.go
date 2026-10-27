package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	ipsec "github.com/eukhlg/ipsec-go/server"
	"github.com/eukhlg/netio/udptransport"
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
		Debug    int    `toml:"debug"`
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
		Backend string `toml:"backend"`
		Offload bool   `toml:"offload"`
		Enabled bool   `toml:"enabled"`
		Name    string `toml:"name"`
	} `toml:"tun"`
	NAT struct {
		Enabled   bool   `toml:"enabled"`
		Interface string `toml:"interface"`
	} `toml:"nat"`
	L2TP struct {
		Pipeline      bool `toml:"pipeline"`
		ReceiveBuffer int  `toml:"receive_buffer"`
		UDPBatch      int  `toml:"udp_batch"`
		UDPGSO        bool `toml:"udp_gso"`
	} `toml:"l2tp"`
	IPsec struct {
		Enabled          bool   `toml:"enabled"`
		ReceiveBuffer    int    `toml:"receive_buffer"`
		UDPBatch         int    `toml:"udp_batch"`
		UDPGSO           bool   `toml:"udp_gso"`
		UDPSendBatch     int    `toml:"udp_send_batch"`
		IKEListen        string `toml:"ike_listen"`
		NATTListen       string `toml:"natt_listen"`
		ESPListen        string `toml:"esp_listen"`
		PreSharedKey     string `toml:"pre_shared_key"`
		ServerID         string `toml:"server_id"`
		MaxSAs           int    `toml:"max_sas"`
		ForceNATT        bool   `toml:"force_natt"`
		ReceiveWorkers   int    `toml:"receive_workers"`
		ReplayWindowSize int    `toml:"replay_window_size"`
		IKELifetime      string `toml:"ike_lifetime"`
		ESPLifetime      string `toml:"esp_lifetime"`
		DPDInterval      string `toml:"dpd_interval"`
		MaxHalfOpen      int    `toml:"max_half_open"`
		MaxSAsPerPeer    int    `toml:"max_sa_per_peer"`
	} `toml:"ipsec"`
	Limits struct {
		Sessions            int     `toml:"sessions"`
		SessionsPerTunnel   int     `toml:"sessions_per_tunnel"`
		SessionsPerUser     int     `toml:"sessions_per_user"`
		NewTunnelsPerSecond float64 `toml:"new_tunnels_per_second"`
		NewTunnelBurst      int     `toml:"new_tunnel_burst"`
	} `toml:"limits"`
	receiveWorkersSource string
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
	c.TUN.Backend = "system"
	c.TUN.Offload = true
	c.NAT.Enabled = true
	c.IPsec.IKEListen, c.IPsec.NATTListen, c.IPsec.ESPListen, c.IPsec.MaxSAs = ":500", ":4500", "0.0.0.0", 1024
	c.IPsec.IKELifetime, c.IPsec.ESPLifetime, c.IPsec.DPDInterval = "8h", "1h", "20s"
	c.IPsec.MaxHalfOpen, c.IPsec.MaxSAsPerPeer = 128, 4
	c.IPsec.ReceiveWorkers = defaultReceiveWorkers(runtime.GOMAXPROCS(0))
	c.receiveWorkersSource = "automatic default"
	c.L2TP.Pipeline = true
	c.L2TP.UDPGSO = true
	c.L2TP.UDPBatch = udptransport.DefaultBatchSize
	c.IPsec.UDPGSO = true
	c.IPsec.UDPSendBatch = 128
	c.IPsec.ReceiveBuffer, c.IPsec.UDPBatch = 256*1024, 128
	c.IPsec.ReplayWindowSize = ipsec.DefaultInboundReplayWindowSize
	c.Limits.Sessions, c.Limits.SessionsPerTunnel, c.Limits.SessionsPerUser = 50, 1, 1
	c.Limits.NewTunnelsPerSecond, c.Limits.NewTunnelBurst = 5, 10
	return c
}

func loadConfig(path string) (appConfig, error) {
	c := defaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("open config %q: %w", path, err)
		}
		if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&c); err != nil {
			return c, fmt.Errorf("decode config %q: %w", path, err)
		}
		var explicit struct {
			IPsec struct {
				ReceiveWorkers *int `toml:"receive_workers"`
			} `toml:"ipsec"`
		}
		if err := toml.NewDecoder(bytes.NewReader(data)).Decode(&explicit); err != nil {
			return c, fmt.Errorf("decode config %q: %w", path, err)
		}
		if explicit.IPsec.ReceiveWorkers != nil {
			c.receiveWorkersSource = "config"
		}
	}
	if err := applyEnvironment(&c); err != nil {
		return c, err
	}
	return c, nil
}

func defaultReceiveWorkers(maxProcs int) int {
	workers := maxProcs / 3
	if workers < 1 {
		return 1
	}
	if workers > 4 {
		return 4
	}
	return workers
}

func applyEnvironment(c *appConfig) error {
	if err := overrideBool("L2TP_PIPELINE", &c.L2TP.Pipeline); err != nil {
		return err
	}
	if err := overrideBool("L2TP_UDP_GSO", &c.L2TP.UDPGSO); err != nil {
		return err
	}
	if err := overrideInt("L2TP_RECEIVE_BUFFER", &c.L2TP.ReceiveBuffer); err != nil {
		return err
	}
	if err := overrideInt("L2TP_UDP_BATCH", &c.L2TP.UDPBatch); err != nil {
		return err
	}
	overrideString("L2TP_LISTEN", &c.Server.Listen)
	overrideString("L2TP_HOSTNAME", &c.Server.Hostname)
	if err := overrideInt("L2TP_DEBUG", &c.Server.Debug); err != nil {
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
	overrideString("L2TP_TUN_BACKEND", &c.TUN.Backend)
	if err := overrideBool("L2TP_TUN_OFFLOAD", &c.TUN.Offload); err != nil {
		return err
	}
	if err := overrideBool("L2TP_NAT_ENABLED", &c.NAT.Enabled); err != nil {
		return err
	}
	overrideString("L2TP_NAT_INTERFACE", &c.NAT.Interface)
	if err := overrideBool("L2TP_IPSEC_ENABLED", &c.IPsec.Enabled); err != nil {
		return err
	}
	if err := overrideInt("L2TP_IPSEC_RECEIVE_BUFFER", &c.IPsec.ReceiveBuffer); err != nil {
		return err
	}
	if err := overrideInt("L2TP_IPSEC_UDP_BATCH", &c.IPsec.UDPBatch); err != nil {
		return err
	}
	if err := overrideBool("L2TP_IPSEC_UDP_GSO", &c.IPsec.UDPGSO); err != nil {
		return err
	}
	if err := overrideInt("L2TP_IPSEC_UDP_SEND_BATCH", &c.IPsec.UDPSendBatch); err != nil {
		return err
	}
	overrideString("L2TP_IPSEC_IKE_LISTEN", &c.IPsec.IKEListen)
	overrideString("L2TP_IPSEC_NATT_LISTEN", &c.IPsec.NATTListen)
	overrideString("L2TP_IPSEC_ESP_LISTEN", &c.IPsec.ESPListen)
	overrideString("L2TP_IPSEC_PSK", &c.IPsec.PreSharedKey)
	overrideString("L2TP_IPSEC_SERVER_ID", &c.IPsec.ServerID)
	if err := overrideInt("L2TP_IPSEC_MAX_SAS", &c.IPsec.MaxSAs); err != nil {
		return err
	}
	if err := overrideBool("L2TP_IPSEC_FORCE_NATT", &c.IPsec.ForceNATT); err != nil {
		return err
	}
	if _, ok := lookupNonempty("L2TP_IPSEC_RECEIVE_WORKERS"); ok {
		if err := overrideInt("L2TP_IPSEC_RECEIVE_WORKERS", &c.IPsec.ReceiveWorkers); err != nil {
			return err
		}
		c.receiveWorkersSource = "environment"
	}
	if err := overrideInt("L2TP_IPSEC_REPLAY_WINDOW_SIZE", &c.IPsec.ReplayWindowSize); err != nil {
		return err
	}
	overrideString("L2TP_IPSEC_IKE_LIFETIME", &c.IPsec.IKELifetime)
	overrideString("L2TP_IPSEC_ESP_LIFETIME", &c.IPsec.ESPLifetime)
	overrideString("L2TP_IPSEC_DPD_INTERVAL", &c.IPsec.DPDInterval)
	if err := overrideInt("L2TP_IPSEC_MAX_HALF_OPEN", &c.IPsec.MaxHalfOpen); err != nil {
		return err
	}
	if err := overrideInt("L2TP_IPSEC_MAX_SA_PER_PEER", &c.IPsec.MaxSAsPerPeer); err != nil {
		return err
	}
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
	if c.TUN.Backend != "system" {
		return networkConfig{}, nil, fmt.Errorf("unsupported TUN backend %q (want system)", c.TUN.Backend)
	}
	if c.L2TP.ReceiveBuffer < 0 || int64(c.L2TP.ReceiveBuffer) > (1<<31-1)/2 {
		return networkConfig{}, nil, fmt.Errorf("l2tp.receive_buffer must be between 0 and 1073741823 bytes")
	}
	if err := udptransport.ValidateBatchSize(c.L2TP.UDPBatch); err != nil {
		return networkConfig{}, nil, fmt.Errorf("l2tp.udp_batch: %w", err)
	}
	if err := udptransport.ValidateBatchSize(c.IPsec.UDPSendBatch); err != nil {
		return networkConfig{}, nil, fmt.Errorf("ipsec.udp_send_batch: %w", err)
	}
	if c.IPsec.ReceiveBuffer < 0 || int64(c.IPsec.ReceiveBuffer) > (1<<31-1)/2 {
		return networkConfig{}, nil, fmt.Errorf("ipsec.receive_buffer must be between 0 and 1073741823 bytes")
	}
	if err := udptransport.ValidateBatchSize(c.IPsec.UDPBatch); err != nil {
		return networkConfig{}, nil, fmt.Errorf("ipsec.udp_batch: %w", err)
	}
	if c.Server.Debug < 0 || c.Server.Debug > 2 {
		return networkConfig{}, nil, fmt.Errorf("server.debug must be 0, 1, or 2")
	}
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
	if c.Limits.NewTunnelsPerSecond < 0 || c.Limits.NewTunnelBurst < 0 {
		return networkConfig{}, nil, fmt.Errorf("new tunnel rate limits cannot be negative")
	}
	if c.IPsec.MaxSAs < 0 || c.IPsec.MaxHalfOpen < 0 || c.IPsec.MaxSAsPerPeer < 0 {
		return networkConfig{}, nil, fmt.Errorf("IPsec SA limits cannot be negative")
	}
	if c.IPsec.ReceiveWorkers < 0 || c.IPsec.ReceiveWorkers > ipsec.ESPReceiveCapacity {
		return networkConfig{}, nil, fmt.Errorf("ipsec.receive_workers must be between 0 and %d", ipsec.ESPReceiveCapacity)
	}
	if size := c.IPsec.ReplayWindowSize; size < esp.ReplayWindowSize || size > esp.MaxReplayWindowSize || size%64 != 0 {
		return networkConfig{}, nil, fmt.Errorf("ipsec.replay_window_size must be a multiple of 64 between %d and %d", esp.ReplayWindowSize, esp.MaxReplayWindowSize)
	}
	for name, value := range map[string]string{"ike_lifetime": c.IPsec.IKELifetime, "esp_lifetime": c.IPsec.ESPLifetime, "dpd_interval": c.IPsec.DPDInterval} {
		duration, err := time.ParseDuration(value)
		if err != nil || duration < 0 || (name != "dpd_interval" && duration == 0) {
			return networkConfig{}, nil, fmt.Errorf("ipsec.%s must be a valid positive duration", name)
		}
	}
	if c.IPsec.Enabled {
		if c.IPsec.PreSharedKey == "" {
			return networkConfig{}, nil, fmt.Errorf("ipsec.pre_shared_key is required when IPsec is enabled")
		}
		if address, err := netip.ParseAddr(c.IPsec.ServerID); err != nil || !address.Is4() {
			return networkConfig{}, nil, fmt.Errorf("ipsec.server_id must be an IPv4 address when IPsec is enabled")
		}
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
	path := os.Getenv("OVERTURE_CONFIG")
	if path == "" {
		path = os.Getenv("L2TP_CONFIG")
	}
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
