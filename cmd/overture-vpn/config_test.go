package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"L2TP_PIPELINE", "L2TP_UDP_GSO", "L2TP_SEND_SHARDS", "L2TP_IPSEC_UDP_GSO", "L2TP_IPSEC_UDP_SEND_BATCH", "L2TP_RECEIVE_BUFFER", "L2TP_UDP_BATCH", "L2TP_IPSEC_RECEIVE_BUFFER", "L2TP_IPSEC_UDP_BATCH", "OVERTURE_CONFIG", "L2TP_CONFIG", "L2TP_LISTEN", "L2TP_HOSTNAME", "L2TP_DEBUG", "L2TP_AUTH",
		"L2TP_USERS", "L2TP_USERNAME", "L2TP_PASSWORD", "L2TP_CLIENT_SUBNET",
		"L2TP_SERVER_IP", "L2TP_CLIENT_POOL_START", "L2TP_CLIENT_POOL_SIZE",
		"L2TP_CLIENT_SUBNET_START", "L2TP_CLIENT_SUBNET_LIMIT", "L2TP_CLIENT_IP",
		"L2TP_DNS", "L2TP_MTU", "L2TP_TUN_ENABLED", "L2TP_TUN_NAME", "L2TP_TUN_OFFLOAD", "L2TP_TUN_TX_QUEUE_LENGTH", "L2TP_TUN_WRITE_SHARDS", "L2TP_IPSEC_DELIVERY_WORKERS",
		"L2TP_NAT_ENABLED", "L2TP_NAT_INTERFACE", "L2TP_MAX_SESSIONS",
		"L2TP_MAX_SESSIONS_PER_TUNNEL", "L2TP_MAX_SESSIONS_PER_USER",
		"L2TP_IPSEC_ENABLED", "L2TP_IPSEC_IKE_LISTEN", "L2TP_IPSEC_NATT_LISTEN", "L2TP_IPSEC_ESP_LISTEN",
		"L2TP_IPSEC_PSK", "L2TP_IPSEC_SERVER_ID", "L2TP_IPSEC_MAX_SAS",
		"L2TP_IPSEC_FORCE_NATT", "L2TP_IPSEC_RECEIVE_WORKERS", "L2TP_IPSEC_SEAL_WORKERS", "L2TP_IPSEC_IKE_LIFETIME", "L2TP_IPSEC_ESP_LIFETIME", "L2TP_IPSEC_DPD_INTERVAL", "L2TP_IPSEC_MAX_HALF_OPEN", "L2TP_IPSEC_MAX_SA_PER_PEER",
	} {
		t.Setenv(name, "")
	}
}

func TestDefaultReceiveWorkersByCPUCount(t *testing.T) {
	for _, test := range []struct{ cpus, want int }{
		{1, 1}, {2, 1}, {5, 1}, {6, 2}, {8, 2}, {9, 3}, {11, 3}, {12, 4}, {64, 4},
	} {
		if got := defaultReceiveWorkers(test.cpus); got != test.want {
			t.Errorf("defaultReceiveWorkers(%d)=%d, want %d", test.cpus, got, test.want)
		}
	}
}

func TestReceiveWorkersAutomaticAndExplicitOverrides(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if want := defaultReceiveWorkers(runtime.GOMAXPROCS(0)); c.IPsec.ReceiveWorkers != want || c.receiveWorkersSource != "automatic default" {
		t.Fatalf("automatic workers=%d source=%q, want %d automatic default", c.IPsec.ReceiveWorkers, c.receiveWorkersSource, want)
	}

	path := writeConfig(t, "[[authentication.users]]\nusername = \"vpn\"\npassword = \"secret\"\n\n[ipsec]\nreceive_workers = 0\n")
	c, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPsec.ReceiveWorkers != 0 || c.receiveWorkersSource != "config" {
		t.Fatalf("config workers=%d source=%q", c.IPsec.ReceiveWorkers, c.receiveWorkersSource)
	}
	if _, _, err := c.validate(); err != nil {
		t.Fatalf("explicit serial config rejected: %v", err)
	}

	t.Setenv("L2TP_IPSEC_RECEIVE_WORKERS", "1")
	c, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPsec.ReceiveWorkers != 1 || c.receiveWorkersSource != "environment" {
		t.Fatalf("environment workers=%d source=%q", c.IPsec.ReceiveWorkers, c.receiveWorkersSource)
	}
	if _, _, err := c.validate(); err != nil {
		t.Fatalf("explicit serial environment value rejected: %v", err)
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

func TestConfigPathPrecedence(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("L2TP_CONFIG", "legacy.toml")
	if got := configPathFromArgs(nil); got != "legacy.toml" {
		t.Fatal(got)
	}
	t.Setenv("OVERTURE_CONFIG", "overture.toml")
	if got := configPathFromArgs(nil); got != "overture.toml" {
		t.Fatal(got)
	}
	for _, args := range [][]string{{"--config", "explicit.toml"}, {"--config=explicit.toml"}} {
		if got := configPathFromArgs(args); got != "explicit.toml" {
			t.Fatal(got)
		}
	}
}

func TestIPsecSocketConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || c.IPsec.ReceiveBuffer != 524288 || c.IPsec.UDPBatch != 128 {
		t.Fatalf("defaults: %+v %v", c.IPsec, err)
	}
	path := writeConfig(t, "[ipsec]\nreceive_buffer=1048576\nudp_batch=128\n")
	c, err = loadConfig(path)
	if err != nil || c.IPsec.ReceiveBuffer != 1048576 || c.IPsec.UDPBatch != 128 {
		t.Fatalf("config: %+v %v", c.IPsec, err)
	}
	t.Setenv("L2TP_IPSEC_RECEIVE_BUFFER", "262144")
	t.Setenv("L2TP_IPSEC_UDP_BATCH", "1")
	c, err = loadConfig(path)
	if err != nil || c.IPsec.ReceiveBuffer != 262144 || c.IPsec.UDPBatch != 1 {
		t.Fatalf("env: %+v %v", c.IPsec, err)
	}
	t.Setenv("L2TP_IPSEC_RECEIVE_BUFFER", "0")
	c, err = loadConfig(path)
	if err != nil || c.IPsec.ReceiveBuffer != 0 {
		t.Fatalf("kernel default override: %+v %v", c.IPsec, err)
	}
	for _, key := range []string{"L2TP_IPSEC_RECEIVE_BUFFER", "L2TP_IPSEC_UDP_BATCH"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "bad")
			if _, err := loadConfig(path); err == nil {
				t.Fatal("invalid integer accepted")
			}
		})
	}
	for _, key := range []string{"receive_buffer", "udp_batch"} {
		for _, value := range []int{-1, 0, 1, 32, 128, 256, 257, 1 << 30} {
			c := defaultConfig()
			c.Authentication.Users = []userConfig{{Username: "test", Password: "test"}}
			valid := value >= 1 && value <= 256
			if key == "receive_buffer" {
				c.IPsec.ReceiveBuffer = value
				valid = value >= 0 && value <= (1<<31-1)/2
			} else {
				c.IPsec.UDPBatch = value
			}
			if _, _, err := c.validate(); (err == nil) != valid {
				t.Fatalf("%s=%d valid=%v err=%v", key, value, valid, err)
			}
		}
	}
}

func TestL2TPSocketConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || c.L2TP.ReceiveBuffer != 1048576 || c.L2TP.UDPBatch != 128 {
		t.Fatalf("defaults: %+v %v", c.L2TP, err)
	}
	path := writeConfig(t, "[l2tp]\nreceive_buffer=0\nudp_batch=32\n")
	c, err = loadConfig(path)
	if err != nil || c.L2TP.ReceiveBuffer != 0 || c.L2TP.UDPBatch != 32 {
		t.Fatalf("config: %+v %v", c.L2TP, err)
	}
	t.Setenv("L2TP_RECEIVE_BUFFER", "262144")
	t.Setenv("L2TP_UDP_BATCH", "1")
	c, err = loadConfig(path)
	if err != nil || c.L2TP.ReceiveBuffer != 262144 || c.L2TP.UDPBatch != 1 {
		t.Fatalf("env: %+v %v", c.L2TP, err)
	}
	for _, key := range []string{"L2TP_RECEIVE_BUFFER", "L2TP_UDP_BATCH"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "bad")
			if _, err := loadConfig(path); err == nil {
				t.Fatal("invalid integer accepted")
			}
		})
	}
	for _, key := range []string{"receive_buffer", "udp_batch"} {
		for _, value := range []int{-1, 0, 1, 32, 128, 256, 257, 1 << 30} {
			c := defaultConfig()
			c.Authentication.Users = []userConfig{{Username: "test", Password: "test"}}
			valid := value >= 1 && value <= 256
			if key == "receive_buffer" {
				c.L2TP.ReceiveBuffer = value
				valid = value >= 0 && value <= (1<<31-1)/2
			} else {
				c.L2TP.UDPBatch = value
			}
			if _, _, err := c.validate(); (err == nil) != valid {
				t.Fatalf("%s=%d valid=%v err=%v", key, value, valid, err)
			}
		}
	}
}

func TestIPsecUDPOffloadConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c := defaultConfig()
	if !c.IPsec.UDPGSO || c.IPsec.UDPSendBatch != 128 {
		t.Fatalf("defaults: %+v", c.IPsec)
	}
	path := writeConfig(t, "[ipsec]\nudp_gso=false\nudp_send_batch=128\n")
	c, err := loadConfig(path)
	if err != nil || c.IPsec.UDPGSO || c.IPsec.UDPSendBatch != 128 {
		t.Fatalf("file: %v %+v", err, c.IPsec)
	}
	t.Setenv("L2TP_IPSEC_UDP_GSO", "true")
	t.Setenv("L2TP_IPSEC_UDP_SEND_BATCH", "32")
	c, err = loadConfig(path)
	if err != nil || !c.IPsec.UDPGSO || c.IPsec.UDPSendBatch != 32 {
		t.Fatalf("env: %v %+v", err, c.IPsec)
	}
}

func TestPlainUDPOffloadConfig(t *testing.T) {
	clearConfigEnvironment(t)
	if !defaultConfig().L2TP.UDPGSO {
		t.Fatal("GSO should default on")
	}
	path := writeConfig(t, "[l2tp]\nudp_gso=false\n")
	c, err := loadConfig(path)
	if err != nil || c.L2TP.UDPGSO {
		t.Fatalf("file: %v %+v", err, c.L2TP)
	}
	t.Setenv("L2TP_UDP_GSO", "true")
	c, err = loadConfig(path)
	if err != nil || !c.L2TP.UDPGSO {
		t.Fatalf("env: %v %+v", err, c.L2TP)
	}
}

func TestTUNBackendAndOffloadEnvironment(t *testing.T) {
	c := defaultConfig()
	if c.TUN.Backend != "system" || !c.TUN.Offload {
		t.Fatal("TUN defaults")
	}
	t.Setenv("L2TP_TUN_BACKEND", "system")
	t.Setenv("L2TP_TUN_OFFLOAD", "false")
	if err := applyEnvironment(&c); err != nil || c.TUN.Offload {
		t.Fatalf("kill switch: %v", err)
	}
	c.TUN.Backend = "unknown"
	if _, _, err := c.validate(); err == nil {
		t.Fatal("invalid backend accepted")
	}
}

func TestTUNTxQueueLengthConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || c.TUN.TxQueueLength != 0 {
		t.Fatalf("default: %d %v", c.TUN.TxQueueLength, err)
	}
	path := writeConfig(t, "[tun]\ntx_queue_length = 128\n")
	c, err = loadConfig(path)
	if err != nil || c.TUN.TxQueueLength != 128 {
		t.Fatalf("file: %d %v", c.TUN.TxQueueLength, err)
	}
	t.Setenv("L2TP_TUN_TX_QUEUE_LENGTH", "32")
	c, err = loadConfig(path)
	if err != nil || c.TUN.TxQueueLength != 32 {
		t.Fatalf("environment: %d %v", c.TUN.TxQueueLength, err)
	}
	for _, value := range []int{-1, 0, 1, 64, 65535, 65536} {
		c := defaultConfig()
		c.Authentication.Users = []userConfig{{Username: "test", Password: "test"}}
		c.TUN.TxQueueLength = value
		valid := value >= 0 && value <= 65535
		if _, _, err := c.validate(); (err == nil) != valid {
			t.Fatalf("tx_queue_length=%d valid=%v err=%v", value, valid, err)
		}
	}
}

func TestPlainPipelineConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || !c.L2TP.Pipeline {
		t.Fatalf("default: %v %v", c.L2TP.Pipeline, err)
	}
	path := writeConfig(t, "[l2tp]\npipeline = false\n")
	c, err = loadConfig(path)
	if err != nil || c.L2TP.Pipeline {
		t.Fatalf("config: %v %v", c.L2TP.Pipeline, err)
	}
	t.Setenv("L2TP_PIPELINE", "true")
	c, err = loadConfig(path)
	if err != nil || !c.L2TP.Pipeline {
		t.Fatalf("env: %v %v", c.L2TP.Pipeline, err)
	}
	t.Setenv("L2TP_PIPELINE", "false")
	c, err = loadConfig("")
	if err != nil || c.L2TP.Pipeline {
		t.Fatalf("env disable: %v %v", c.L2TP.Pipeline, err)
	}
	t.Setenv("L2TP_PIPELINE", "invalid")
	if _, err = loadConfig(""); err == nil || !strings.Contains(err.Error(), "L2TP_PIPELINE") {
		t.Fatal(err)
	}
}

func TestPlainSendShardsConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || c.L2TP.SendShards != 0 || c.sendShards() != defaultReceiveWorkers(runtime.GOMAXPROCS(0)) {
		t.Fatalf("default: %d %v", c.L2TP.SendShards, err)
	}
	path := writeConfig(t, "[l2tp]\nsend_shards = 3\n")
	c, err = loadConfig(path)
	if err != nil || c.sendShards() != 3 {
		t.Fatalf("file: %d %v", c.L2TP.SendShards, err)
	}
	t.Setenv("L2TP_SEND_SHARDS", "1")
	c, err = loadConfig(path)
	if err != nil || c.sendShards() != 1 {
		t.Fatalf("environment: %d %v", c.L2TP.SendShards, err)
	}
	for _, value := range []int{-1, 0, 1, 16, 17} {
		c := defaultConfig()
		c.Authentication.Users = []userConfig{{Username: "test", Password: "test"}}
		c.L2TP.SendShards = value
		valid := value >= 0 && value <= 16
		if _, _, err := c.validate(); (err == nil) != valid {
			t.Fatalf("send_shards=%d valid=%v err=%v", value, valid, err)
		}
	}
}

func TestUploadEgressShardConfig(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil || c.writeShards() != defaultWriteShards(runtime.GOMAXPROCS(0)) || c.deliveryWorkers() != 1 {
		t.Fatalf("default: %d %d %v", c.writeShards(), c.deliveryWorkers(), err)
	}
	path := writeConfig(t, "[tun]\nwrite_shards = 3\n[ipsec]\ndelivery_workers = 2\n")
	c, err = loadConfig(path)
	if err != nil || c.writeShards() != 3 || c.deliveryWorkers() != 2 {
		t.Fatalf("file: %d %d %v", c.writeShards(), c.deliveryWorkers(), err)
	}
	t.Setenv("L2TP_TUN_WRITE_SHARDS", "1")
	t.Setenv("L2TP_IPSEC_DELIVERY_WORKERS", "4")
	c, err = loadConfig(path)
	if err != nil || c.writeShards() != 1 || c.deliveryWorkers() != 4 {
		t.Fatalf("environment: %d %d %v", c.writeShards(), c.deliveryWorkers(), err)
	}
	for _, value := range []int{-1, 0, 1, 16, 17} {
		valid := value >= 0 && value <= 16
		for _, set := range []func(*appConfig){func(c *appConfig) { c.TUN.WriteShards = value }, func(c *appConfig) { c.IPsec.DeliveryWorkers = value }} {
			c := defaultConfig()
			c.Authentication.Users = []userConfig{{Username: "test", Password: "test"}}
			set(&c)
			if _, _, err := c.validate(); (err == nil) != valid {
				t.Fatalf("value %d valid=%v err=%v", value, valid, err)
			}
		}
	}
}

func TestSealWorkersAutomaticAndExplicitOverrides(t *testing.T) {
	clearConfigEnvironment(t)
	c, err := loadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if want := defaultReceiveWorkers(runtime.GOMAXPROCS(0)); c.IPsec.SealWorkers != want || c.sealWorkersSource != "automatic default" {
		t.Fatalf("automatic seal workers=%d source=%q", c.IPsec.SealWorkers, c.sealWorkersSource)
	}
	path := writeConfig(t, "[[authentication.users]]\nusername = \"vpn\"\npassword = \"secret\"\n\n[ipsec]\nseal_workers = 0\n")
	c, err = loadConfig(path)
	if err != nil || c.IPsec.SealWorkers != 0 || c.sealWorkersSource != "config" {
		t.Fatalf("config seal workers=%d source=%q err=%v", c.IPsec.SealWorkers, c.sealWorkersSource, err)
	}
	if _, _, err := c.validate(); err != nil {
		t.Fatalf("serial config rejected: %v", err)
	}
	t.Setenv("L2TP_IPSEC_SEAL_WORKERS", "3")
	c, err = loadConfig(path)
	if err != nil || c.IPsec.SealWorkers != 3 || c.sealWorkersSource != "environment" {
		t.Fatalf("environment seal workers=%d source=%q err=%v", c.IPsec.SealWorkers, c.sealWorkersSource, err)
	}
	c.IPsec.SealWorkers = 65
	if _, _, err := c.validate(); err == nil {
		t.Fatal("65 seal workers accepted")
	}
}

func TestDefaultWriteShards(t *testing.T) {
	for procs, want := range map[int]int{0: 1, 1: 1, 2: 2, 3: 3, 4: 4, 6: 4, 64: 4} {
		if got := defaultWriteShards(procs); got != want {
			t.Fatalf("defaultWriteShards(%d)=%d, want %d", procs, got, want)
		}
	}
}
