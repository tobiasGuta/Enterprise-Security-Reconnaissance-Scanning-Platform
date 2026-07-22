package targeting

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type DetailedScope interface {
	Evaluate(string) platformscope.Evaluation
	IncludeRules() []platformscope.NormalizedRule
}

type FilterDecision struct {
	Target         string               `json:"target"`
	Accepted       bool                 `json:"accepted"`
	Reason         platformscope.Reason `json:"reason"`
	AuthorizedURLs []string             `json:"authorized_urls,omitempty"`
	SourceRuleIDs  []string             `json:"source_rule_ids,omitempty"`
}

type FilterResult struct {
	Authorized     []string         `json:"authorized"`
	AuthorizedURLs []string         `json:"authorized_urls"`
	Filtered       []FilterDecision `json:"filtered"`
	Decisions      []FilterDecision `json:"decisions"`
	AcceptedCount  int              `json:"accepted_count"`
	FilteredCount  int              `json:"filtered_count"`
}

func FilterDiscoveredHosts(sc DetailedScope, hosts []string) FilterResult {
	result := FilterResult{Authorized: []string{}, AuthorizedURLs: []string{}, Filtered: []FilterDecision{}, Decisions: []FilterDecision{}}
	seen := map[string]bool{}
	for _, raw := range hosts {
		host, err := normalizeHostname(raw)
		if err != nil {
			d := FilterDecision{Target: raw, Reason: platformscope.ReasonInvalidHostname}
			result.Filtered = append(result.Filtered, d)
			result.Decisions = append(result.Decisions, d)
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		d := authorizeHost(sc, host)
		result.Decisions = append(result.Decisions, d)
		if d.Accepted {
			result.Authorized = append(result.Authorized, host)
			result.AuthorizedURLs = append(result.AuthorizedURLs, d.AuthorizedURLs...)
		} else {
			result.Filtered = append(result.Filtered, d)
		}
	}
	result.Authorized = uniqueStrings(result.Authorized)
	result.AuthorizedURLs = uniqueStrings(result.AuthorizedURLs)
	result.AcceptedCount, result.FilteredCount = len(result.Authorized), len(result.Filtered)
	return result
}

func FilterURLs(sc DetailedScope, targets []string) FilterResult {
	result := FilterResult{Authorized: []string{}, AuthorizedURLs: []string{}, Filtered: []FilterDecision{}, Decisions: []FilterDecision{}}
	seen := map[string]bool{}
	for _, raw := range targets {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			d := FilterDecision{Target: raw, Reason: platformscope.ReasonInvalidTarget}
			result.Filtered = append(result.Filtered, d)
			result.Decisions = append(result.Decisions, d)
			continue
		}
		normalized := u.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		e := sc.Evaluate(normalized)
		d := FilterDecision{Target: normalized, Accepted: e.Allowed, Reason: e.Reason, SourceRuleIDs: e.MatchedIncludeIDs}
		result.Decisions = append(result.Decisions, d)
		if d.Accepted {
			result.Authorized = append(result.Authorized, normalized)
			result.AuthorizedURLs = append(result.AuthorizedURLs, normalized)
		} else {
			result.Filtered = append(result.Filtered, d)
		}
	}
	result.Authorized = uniqueStrings(result.Authorized)
	result.AuthorizedURLs = uniqueStrings(result.AuthorizedURLs)
	result.AcceptedCount, result.FilteredCount = len(result.Authorized), len(result.Filtered)
	return result
}

func authorizeHost(sc DetailedScope, host string) FilterDecision {
	d := FilterDecision{Target: host, Reason: platformscope.ReasonNoInclude}
	matchedHost := false
	matchedExclusion := false
	for _, r := range sc.IncludeRules() {
		hostRE, err := regexp.Compile(r.Host)
		if err != nil || !full(hostRE, host) {
			continue
		}
		matchedHost = true
		protocols, pok := finiteProtocols(r.Protocol)
		ports, ook := finitePorts(r.Port)
		path, pathOK := initialPath(r.File)
		if !pok || !ook || !pathOK {
			continue
		}
		for _, protocol := range protocols {
			for _, port := range ports {
				raw := endpointURL(protocol, host, port, path)
				e := sc.Evaluate(raw)
				if e.Allowed {
					d.AuthorizedURLs = appendUnique(d.AuthorizedURLs, raw)
					d.SourceRuleIDs = append(d.SourceRuleIDs, e.MatchedIncludeIDs...)
				} else if e.Reason == platformscope.ReasonExcluded {
					matchedExclusion = true
				}
			}
		}
	}
	if len(d.AuthorizedURLs) > 0 {
		d.Accepted = true
		d.Reason = platformscope.ReasonAllowed
		d.AuthorizedURLs = uniqueStrings(d.AuthorizedURLs)
		d.SourceRuleIDs = uniqueStrings(d.SourceRuleIDs)
		return d
	}
	if matchedExclusion {
		d.Reason = platformscope.ReasonExcluded
	} else if !matchedHost {
		d.Reason = platformscope.ReasonNoInclude
	}
	return d
}

func IsIPHost(raw string) bool { return net.ParseIP(strings.Trim(raw, "[]")) != nil }
func SortedUnique(items []string) []string {
	out := uniqueStrings(items)
	sort.Strings(out)
	return out
}
