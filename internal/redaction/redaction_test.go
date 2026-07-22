package redaction

import (
	"strings"
	"testing"
)

func TestTextRedaction(t *testing.T) {
	r := New("session")
	input := "Authorization: Bearer abcdef token=supersecret https://x.test/?api_key=leak"
	got := r.Text(input)
	for _, secret := range []string{"abcdef", "supersecret", "leak"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked in %q", secret, got)
		}
	}
}
func TestHeaderRedaction(t *testing.T) {
	got := New().Headers(map[string][]string{"Cookie": {"sid=x"}, "Accept": {"json"}})
	if got["Cookie"][0] != "<redacted>" || got["Accept"][0] != "json" {
		t.Fatalf("unexpected headers: %#v", got)
	}
}
