package main

import "testing"

func TestWildcardBind(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080"} {
		if !wildcardBind(addr) {
			t.Fatalf("%q should be a wildcard bind", addr)
		}
	}
	for _, addr := range []string{"192.168.1.10:8080", "127.0.0.1:8080", "garbage", ""} {
		if wildcardBind(addr) {
			t.Fatalf("%q should not be a wildcard bind", addr)
		}
	}
}
