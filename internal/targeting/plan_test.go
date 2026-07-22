package targeting

import (
	"path/filepath"
	"reflect"
	"testing"

	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

func TestExactWildcardIPAmbiguousAndStablePlan(t *testing.T) {
	sc, err := platformscope.Compile([]platformscope.Rule{
		{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true},
		{Protocol: `^http$`, Host: `^.*\.dev\.example\.com$`, Port: `^8080$`, File: `^/.*`, Enabled: true},
		{Protocol: `^https$`, Host: `^192\.0\.2\.8$`, Port: `^8443$`, File: `^/health$`, Enabled: true},
		{Protocol: `^https$`, Host: `^(api|www)\.ambiguous\.example$`, Port: `^443$`, File: `^/.*`, Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Digest == "" || p1.Digest != p2.Digest {
		t.Fatal("plan digest must be stable")
	}
	if !reflect.DeepEqual(p1, p2) {
		t.Fatal("plans must be deterministic")
	}
	if contains(p1.ExactHosts(), "dev.example.com") {
		t.Fatal("wildcard base promoted to active")
	}
	if !contains(p1.DiscoveryDomains(), "dev.example.com") {
		t.Fatal("missing passive root")
	}
	if !contains(p1.ExactHosts(), "api.example.com") || !contains(p1.ExactHosts(), "192.0.2.8") {
		t.Fatalf("missing exact seed: %#v warnings=%#v", p1.ExactHosts(), p1.Warnings)
	}
	if len(p1.Warnings) == 0 {
		t.Fatal("expected ambiguous regex warning")
	}
}

func TestManualRootRequiresReasonAndIsNeverActive(t *testing.T) {
	sc, _ := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if _, err := Plan(sc, []ManualDiscoveryRoot{{Domain: "example.com"}}); err == nil {
		t.Fatal("expected reason error")
	}
	p, err := Plan(sc, []ManualDiscoveryRoot{{Domain: "example.com", Reason: "operator-approved passive enumeration"}})
	if err != nil {
		t.Fatal(err)
	}
	if contains(p.ExactHosts(), "example.com") {
		t.Fatal("manual root promoted to active")
	}
}

func TestEmptyExecutablePlanAndDuplicateRuleNormalization(t *testing.T) {
	rule := platformscope.Rule{Protocol: `^https$`, Host: `^(api|www)\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}
	sc, err := platformscope.Compile([]platformscope.Rule{rule, rule}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.IncludeRules()) != 1 {
		t.Fatalf("duplicate normalized rules retained: %d", len(sc.IncludeRules()))
	}
	p, err := Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.HasExecutableTargets() || len(p.Warnings) == 0 {
		t.Fatalf("ambiguous-only plan should be reviewable but not executable: %#v", p)
	}
}

func TestOptionalHTTPSProtocolAndNonDefaultPort(t *testing.T) {
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https?$`, Host: `^api\.example\.com$`, Port: `^(80|8443)$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := findSeed(p, "api.example.com")
	if seed == nil {
		t.Fatal("missing seed")
	}
	if !endpoint(seed.Endpoints, "https", 8443) {
		t.Fatalf("non-default endpoint missing: %#v", seed.Endpoints)
	}
	if !contains(p.InitialURLs(), "https://api.example.com:8443/") {
		t.Fatalf("non-default port omitted: %v", p.InitialURLs())
	}
}

func TestMixedFixtureAcceptance(t *testing.T) {
	sc, err := platformscope.LoadBurp(filepath.Join("testdata", "mixed_real_world_scope.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.life360.com", "www.life360.com", "tile.com"} {
		if !contains(p.ExactHosts(), host) {
			t.Fatalf("missing %s", host)
		}
	}
	for _, host := range []string{"life360.com", "dev.life360.com"} {
		if contains(p.ExactHosts(), host) {
			t.Fatalf("unexpected active seed %s", host)
		}
	}
	if !contains(p.DiscoveryDomains(), "dev.life360.com") {
		t.Fatal("missing wildcard discovery root")
	}
	filtered := FilterDiscoveredHosts(sc, []string{"authorized.dev.life360.com", "subdomain.tile.com", "snipeit.corp.tile.com", "bad host"})
	if !contains(filtered.Authorized, "authorized.dev.life360.com") || len(filtered.Filtered) != 3 {
		t.Fatalf("unexpected filter result: %#v", filtered)
	}
	seed := findSeed(p, "api.life360.com")
	if seed == nil || !endpoint(seed.Endpoints, "http", 80) || !endpoint(seed.Endpoints, "https", 443) {
		t.Fatal("protocol/port pairs not preserved")
	}
}

func TestURLFilteringIncludesPathProtocolPortAndExclusion(t *testing.T) {
	sc, _ := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^8443$`, File: `^/v1/.*`, Enabled: true}}, []platformscope.Rule{{Protocol: `^https$`, Host: `^api\.example\.com$`, Port: `^8443$`, File: `^/v1/private.*`, Enabled: true}})
	r := FilterURLs(sc, []string{"https://api.example.com:8443/v1/ok", "https://api.example.com:8443/v1/private", "http://api.example.com:8443/v1/ok", "malformed"})
	if len(r.Authorized) != 1 || len(r.Filtered) != 3 {
		t.Fatalf("unexpected result %#v", r)
	}
}

func contains(items []string, value string) bool {
	for _, v := range items {
		if v == value {
			return true
		}
	}
	return false
}
func findSeed(p TargetPlan, host string) *ActiveSeed {
	for i := range p.ExactActiveSeeds {
		if p.ExactActiveSeeds[i].Host == host {
			return &p.ExactActiveSeeds[i]
		}
	}
	return nil
}
func endpoint(items []Endpoint, protocol string, port int) bool {
	for _, v := range items {
		if v.Protocol == protocol && v.Port == port {
			return true
		}
	}
	return false
}
