package main

import "testing"

func TestLoadNetworkConfigOffsets(t *testing.T) {
	t.Setenv("L2TP_CLIENT_SUBNET", "10.20.0.0/24")
	t.Setenv("L2TP_SERVER_IP", "1")
	t.Setenv("L2TP_CLIENT_SUBNET_START", "100")
	t.Setenv("L2TP_CLIENT_SUBNET_LIMIT", "50")
	t.Setenv("L2TP_CLIENT_IP", "")
	config, err := loadNetworkConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Server.String() != "10.20.0.1" || config.PoolStart.String() != "10.20.0.100" || config.PoolEnd.String() != "10.20.0.149" || config.TUNPrefix.String() != "10.20.0.1/24" {
		t.Fatalf("config=%#v", config)
	}
}

func TestParseUsers(t *testing.T) {
	users, err := parseUsers("alice=one,bob=two:three")
	if err != nil || users["alice"] != "one" || users["bob"] != "two:three" {
		t.Fatalf("users=%#v err=%v", users, err)
	}
}
