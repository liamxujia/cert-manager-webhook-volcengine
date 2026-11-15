package main

import "testing"

func TestValidateGroup(t *testing.T) {
	for _, group := range []string{"acme.example.com", "dns.example.org"} {
		if err := validateGroup(group); err != nil {
			t.Fatalf("valid group %q rejected: %v", group, err)
		}
	}
	for _, group := range []string{"", "example", "ACME.example.com", "bad..example.com", "*.example.com"} {
		if err := validateGroup(group); err == nil {
			t.Fatalf("invalid group %q accepted", group)
		}
	}
}
