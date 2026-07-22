package policy

import (
	"fmt"
	"strings"
	"time"
)

type Risk string

const (
	Passive   Risk = "passive"
	Low       Risk = "low"
	Moderate  Risk = "moderate"
	High      Risk = "high"
	Forbidden Risk = "forbidden"
)

type Decision string

const (
	Allow           Decision = "allow"
	RequireApproval Decision = "require_approval"
	Deny            Decision = "deny"
)

type Policy struct {
	ID                   string        `json:"id"`
	AllowedCapabilities  []string      `json:"allowed_capabilities"`
	DeniedCapabilities   []string      `json:"denied_capabilities"`
	RateLimit            int           `json:"rate_limit"`
	Concurrency          int           `json:"concurrency"`
	ScanWindows          []string      `json:"scan_windows"`
	AllowedHTTPMethods   []string      `json:"allowed_http_methods"`
	AuthenticationUsage  bool          `json:"authentication_usage"`
	HeadlessBrowser      bool          `json:"headless_browser"`
	DirectoryFuzzing     bool          `json:"directory_fuzzing"`
	TemplateTags         []string      `json:"template_tags"`
	ExcludedTemplateTags []string      `json:"excluded_template_tags"`
	MaximumPayloadSize   int64         `json:"maximum_payload_size"`
	FollowRedirects      bool          `json:"follow_redirects"`
	CrossOrigin          bool          `json:"cross_origin"`
	IntrusiveChecks      bool          `json:"intrusive_checks"`
	ArtifactRetention    time.Duration `json:"artifact_retention"`
	ModerateApproved     bool          `json:"moderate_approved"`
}
type Evaluation struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

func Evaluate(p Policy, capability string, risk Risk, approved bool) Evaluation {
	if risk == Forbidden {
		return Evaluation{Deny, "forbidden risk level"}
	}
	if contains(p.DeniedCapabilities, capability) {
		return Evaluation{Deny, "capability denied by policy"}
	}
	if len(p.AllowedCapabilities) > 0 && !contains(p.AllowedCapabilities, capability) {
		return Evaluation{Deny, "capability is not allowlisted"}
	}
	switch risk {
	case Passive, Low:
		return Evaluation{Allow, "allowed within scope and limits"}
	case Moderate:
		if approved || p.ModerateApproved {
			return Evaluation{Allow, "moderate action approved"}
		}
		return Evaluation{RequireApproval, "moderate action requires workflow or action approval"}
	case High:
		if approved {
			return Evaluation{Allow, "high-risk action explicitly approved"}
		}
		return Evaluation{RequireApproval, "high-risk action requires explicit per-action approval"}
	default:
		return Evaluation{Deny, fmt.Sprintf("unknown risk %q", risk)}
	}
}
func ValidateHTTPMethod(p Policy, method string) error {
	method = strings.ToUpper(method)
	for _, m := range p.AllowedHTTPMethods {
		if strings.ToUpper(m) == method {
			return nil
		}
	}
	return fmt.Errorf("HTTP method %s denied by policy", method)
}
func contains(items []string, want string) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}
