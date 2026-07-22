package scope

import (
	"reflect"
	"testing"
)

func TestIncludeExcludeAndRedirect(t *testing.T) {
	s, err := Compile([]Rule{{Protocol: `^https$`, Host: `^(?:.*\.)?example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, []Rule{{Protocol: `^https$`, Host: `^admin\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows("https://api.example.com/v1") {
		t.Fatal("expected included URL")
	}
	if s.Allows("https://admin.example.com/") {
		t.Fatal("exclude must win")
	}
	if s.Allows("https://example.net/") {
		t.Fatal("unexpected out-of-scope URL")
	}
	if s.AllowsRedirect("https://api.example.com/", "https://evil.example.net/") {
		t.Fatal("out-of-scope redirect allowed")
	}
	if !s.AllowsRedirect("https://api.example.com/", "https://www.example.com/next") {
		t.Fatal("in-scope redirect rejected")
	}
}

func TestStableRuleIdentityDigestAndReasons(t *testing.T) {
	rule := Rule{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^443$`, File: `^/v1/.*`, Enabled: true}
	s1, err := Compile([]Rule{rule}, []Rule{{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^443$`, File: `^/v1/private`, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Compile([]Rule{rule}, []Rule{{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^443$`, File: `^/v1/private`, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if s1.Digest() == "" || s1.Digest() != s2.Digest() {
		t.Fatal("scope digest must be stable")
	}
	if !reflect.DeepEqual(s1.IncludeRules(), s2.IncludeRules()) {
		t.Fatal("rule IDs must be stable")
	}
	cases := map[string]Reason{
		"https://api.example.com/v1/private": ReasonExcluded,
		"http://api.example.com/v1/ok":       ReasonProtocolMismatch,
		"https://other.example.com/v1/ok":    ReasonHostMismatch,
		"https://api.example.com:8443/v1/ok": ReasonPortMismatch,
		"https://api.example.com/nope":       ReasonPathMismatch,
	}
	for target, want := range cases {
		if got := s1.Evaluate(target).Reason; got != want {
			t.Fatalf("%s: got %s want %s", target, got, want)
		}
	}
}
func TestRequiresInclude(t *testing.T) {
	if _, err := Compile(nil, nil); err == nil {
		t.Fatal("expected empty-scope rejection")
	}
}
