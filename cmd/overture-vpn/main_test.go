package main

import (
	"reflect"
	"testing"
)

func TestEnvironmentDefaults(t *testing.T) {
	t.Setenv("TEST_STRING", "value")
	t.Setenv("TEST_BOOL", "true")
	t.Setenv("TEST_INT", "1701")
	if envString("TEST_STRING", "fallback") != "value" {
		t.Fatal("string environment ignored")
	}
	if !envBool("TEST_BOOL", false) {
		t.Fatal("boolean environment ignored")
	}
	if envInt("TEST_INT", 0) != 1701 {
		t.Fatal("integer environment ignored")
	}
	if envString("TEST_MISSING", "fallback") != "fallback" {
		t.Fatal("string fallback ignored")
	}
}

func TestServerCommandCompatibility(t *testing.T) {
	for _, tc := range []struct{ input, want []string }{
		{nil, nil},
		{[]string{"--config", "old.toml"}, []string{"--config", "old.toml"}},
		{[]string{"server", "--config", "new.toml"}, []string{"--config", "new.toml"}},
	} {
		got, err := serverArgs(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v: %v, %v", tc.input, got, err)
		}
	}
	for _, command := range []string{"client", "unknown"} {
		if _, err := serverArgs([]string{command}); err == nil {
			t.Fatalf("accepted %s", command)
		}
	}
}
