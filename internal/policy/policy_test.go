package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRiskDecisions(t *testing.T) {
	p := Policy{AllowedCapabilities: []string{"passive", "low", "moderate", "high"}}
	cases := []struct {
		name     string
		risk     Risk
		approved bool
		want     Decision
	}{{"passive", Passive, false, Allow}, {"low", Low, false, Allow}, {"moderate", Moderate, false, RequireApproval}, {"moderate", Moderate, true, Allow}, {"high", High, false, RequireApproval}, {"high", High, true, Allow}, {"anything", Forbidden, true, Deny}}
	for _, tc := range cases {
		if got := Evaluate(p, tc.name, tc.risk, tc.approved).Decision; got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}
func TestDenyWins(t *testing.T) {
	p := Policy{AllowedCapabilities: []string{"scan"}, DeniedCapabilities: []string{"scan"}}
	if Evaluate(p, "scan", Low, true).Decision != Deny {
		t.Fatal("deny must win")
	}
}

func TestParallelSharePreservesProgramBudgets(t *testing.T) {
	p := Policy{RateLimit: 50, Concurrency: 10, ProviderConcurrency: 2, HostConcurrency: 1}
	shared := ParallelShare(p, 3)
	if shared.RateLimit != 16 || shared.Concurrency != 3 {
		t.Fatalf("unexpected parallel share: %#v", shared)
	}
	if shared.ProviderConcurrency != p.ProviderConcurrency || shared.HostConcurrency != p.HostConcurrency {
		t.Fatalf("parallel share changed execution slot budgets: %#v", shared)
	}
	if ProgramParallelism(Policy{RateLimit: 3, Concurrency: 10}) != 3 {
		t.Fatal("program parallelism exceeded its rate budget")
	}
}

func TestScanWindowsUseUTCAndSupportOvernightRanges(t *testing.T) {
	p := Policy{ScanWindows: []string{"Mon 22:00-02:00 UTC"}}
	for _, at := range []time.Time{
		time.Date(2026, 7, 20, 23, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 21, 1, 30, 0, 0, time.UTC),
	} {
		if got := EvaluateAt(p, "x", Low, false, Requirements{}, json.RawMessage(`{}`), at); got.Decision != Allow {
			t.Fatalf("%s: %#v", at, got)
		}
	}
	outside := EvaluateAt(p, "x", Low, false, Requirements{}, nil, time.Date(2026, 7, 21, 3, 0, 0, 0, time.UTC))
	if outside.Decision != Deny || !strings.Contains(outside.Reason, "outside") {
		t.Fatalf("outside=%#v", outside)
	}
}

func TestMalformedScanWindowFailsClosed(t *testing.T) {
	got := EvaluateAt(Policy{ScanWindows: []string{"weekends"}}, "x", Low, false, Requirements{}, nil, time.Now())
	if got.Decision != Deny || !strings.Contains(got.Reason, "invalid") {
		t.Fatalf("evaluation=%#v", got)
	}
}
