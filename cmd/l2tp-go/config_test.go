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
	} {
		t.Setenv(name, "")
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
`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	network, users, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Hostname != "from-file" || c.NAT.Enabled || c.NAT.Interface != "ens3" || users["alice"] != "one" {
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

func TestParseUsers(t *testing.T) {
	users, err := parseUsers("alice=one,bob=two:three")
	if err != nil || users["alice"] != "one" || users["bob"] != "two:three" {
		t.Fatalf("users=%#v err=%v", users, err)
	}
}
