package main

import "testing"

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
