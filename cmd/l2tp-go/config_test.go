package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"L2TP_CONFIG", "L2TP_LISTEN", "L2TP_HOSTNAME", "L2TP_DEBUG", "L2TP_AUTH",
		"L2TP_USERS", "L2TP_USERNAME", "L2TP_PASSWORD", "L2TP_CLIENT_SUBNET",
		"L2TP_SERVER_IP", "L2TP_CLIENT_POOL_START", "L2TP_CLIENT_POOL_SIZE",
		"L2TP_CLIENT_SUBNET_START", "L2TP_CLIENT_SUBNET_LIMIT", "L2TP_CLIENT_IP",
		"L2TP_DNS", "L2TP_MTU", "L2TP_TUN_ENABLED", "L2TP_TUN_NAME",
		"L2TP_NAT_ENABLED", "L2TP_NAT_INTERFACE", "L2TP_MAX_SESSIONS",
		"L2TP_MAX_SESSIONS_PER_TUNNEL", "L2TP_MAX_SESSIONS_PER_USER",
		"L2TP_IPSEC_ENABLED", "L2TP_IPSEC_IKE_LISTEN", "L2TP_IPSEC_NATT_LISTEN", "L2TP_IPSEC_ESP_LISTEN",
		"L2TP_IPSEC_PSK", "L2TP_IPSEC_SERVER_ID", "L2TP_IPSEC_MAX_SAS",
		"L2TP_IPSEC_FORCE_NATT", "L2TP_IPSEC_IKE_LIFETIME", "L2TP_IPSEC_ESP_LIFETIME", "L2TP_IPSEC_DPD_INTERVAL", "L2TP_IPSEC_MAX_HALF_OPEN", "L2TP_IPSEC_MAX_SA_PER_PEER",
	} {
		t.Setenv(name, "")
	}
}

func TestIPsecConfigRequiresPSKAndIPv4Identity(t *testing.T) {
	clearConfigEnvironment(t)
	c := defaultConfig()
	c.Authentication.Users = []userConfig{{Username: "vpn", Password: "secret"}}
	c.IPsec.Enabled = true
	if _, _, err := c.validate(); err == nil {
		t.Fatal("enabled IPsec accepted without PSK and identity")
	}
	c.IPsec.PreSharedKey, c.IPsec.ServerID = "ipsec-secret", "203.0.113.10"
	if _, _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.IPsec.NATTListen != ":4500" {
		t.Fatalf("NAT-T listen=%q", c.IPsec.NATTListen)
	}
	if c.IPsec.IKELifetime != "8h" || c.IPsec.ESPLifetime != "1h" || c.IPsec.DPDInterval != "20s" || c.IPsec.MaxHalfOpen != 128 || c.IPsec.MaxSAsPerPeer != 4 {
		t.Fatalf("IPsec defaults=%#v", c.IPsec)
	}
	if c.Limits.NewTunnelsPerSecond != 5 || c.Limits.NewTunnelBurst != 10 {
		t.Fatalf("new tunnel rate-limit defaults=%#v", c.Limits)
	}
}

func TestIPsecConfigRejectsInvalidLifecycleDuration(t *testing.T) {
	clearConfigEnvironment(t)
	c := defaultConfig()
	c.Authentication.Users = []userConfig{{Username: "vpn", Password: "secret"}}
	c.IPsec.DPDInterval = "often"
	if _, _, err := c.validate(); err == nil || !strings.Contains(err.Error(), "dpd_interval") {
		t.Fatalf("error=%v", err)
	}
}

func TestConfigRejectsInvalidNewTunnelRateLimit(t *testing.T) {
	clearConfigEnvironment(t)
	c := defaultConfig()
	c.Authentication.Users = []userConfig{{Username: "vpn", Password: "secret"}}
	c.Limits.NewTunnelsPerSecond = -1
	if _, _, err := c.validate(); err == nil || !strings.Contains(err.Error(), "new tunnel rate") {
		t.Fatalf("error=%v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigFileAndResolveOffsets(t *testing.T) {
	clearConfigEnvironment(t)
	path := writeConfig(t, `
[server]
hostname = "from-file"

[authentication]
method = "mschapv2"

[[authentication.users]]
username = "alice"
password = "one"

[network]
subnet = "10.20.0.0/24"
server_address = "1"
client_pool_start = "100"
client_pool_size = 50

[nat]
enabled = false
interface = "ens3"

[limits]
new_tunnels_per_second = 2.5
new_tunnel_burst = 7
`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	network, users, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Hostname != "from-file" || c.NAT.Enabled || c.NAT.Interface != "ens3" || users["alice"] != "one" || c.Limits.NewTunnelsPerSecond != 2.5 || c.Limits.NewTunnelBurst != 7 {
		t.Fatalf("config=%#v users=%#v", c, users)
	}
	if network.Server.String() != "10.20.0.1" || network.PoolStart.String() != "10.20.0.100" || network.PoolEnd.String() != "10.20.0.149" || network.TUNPrefix.String() != "10.20.0.1/24" {
		t.Fatalf("network=%#v", network)
	}
}

func TestEnvironmentOverridesConfigFile(t *testing.T) {
	clearConfigEnvironment(t)
	path := writeConfig(t, `
[[authentication.users]]
username = "file-user"
password = "file-password"
`)
	t.Setenv("L2TP_HOSTNAME", "from-env")
	t.Setenv("L2TP_USERS", "env-user=env-password")
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	_, users, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Hostname != "from-env" || users["env-user"] != "env-password" || len(users) != 1 {
		t.Fatalf("config=%#v users=%#v", c, users)
	}
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	clearConfigEnvironment(t)
	_, err := loadConfig(writeConfig(t, "[server]\nunknown = true\n"))
	if err == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadConfigRejectsInvalidEnvironment(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("L2TP_DEBUG", "perhaps")
	_, err := loadConfig("")
	if err == nil || !strings.Contains(err.Error(), "L2TP_DEBUG") {
		t.Fatalf("err=%v", err)
	}
}

func TestDebugLevels(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("L2TP_DEBUG", "2")
	c, err := loadConfig("")
	if err != nil || c.Server.Debug != 2 {
		t.Fatalf("debug=%d err=%v", c.Server.Debug, err)
	}
	c.Authentication.Users = []userConfig{{Username: "vpn", Password: "secret"}}
	c.Server.Debug = 3
	if _, _, err := c.validate(); err == nil || !strings.Contains(err.Error(), "server.debug") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseUsers(t *testing.T) {
	users, err := parseUsers("alice=one,bob=two:three")
	if err != nil || users["alice"] != "one" || users["bob"] != "two:three" {
		t.Fatalf("users=%#v err=%v", users, err)
	}
}
