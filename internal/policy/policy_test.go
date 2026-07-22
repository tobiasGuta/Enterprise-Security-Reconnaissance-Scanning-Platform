package policy

import "testing"

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
