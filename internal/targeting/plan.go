package targeting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type DiscoveryRoot struct {
	Domain        string   `json:"domain"`
	SourceRuleIDs []string `json:"source_rule_ids"`
	Source        string   `json:"source"`
	Reason        string   `json:"reason,omitempty"`
}

type Endpoint struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	URL      string `json:"url"`
}

type ActiveSeed struct {
	Host          string     `json:"host"`
	Endpoints     []Endpoint `json:"endpoints"`
	PathPattern   string     `json:"path_pattern"`
	SourceRuleIDs []string   `json:"source_rule_ids"`
}

type WildcardRule struct {
	HostPattern  string   `json:"host_pattern"`
	BaseDomain   string   `json:"base_domain"`
	Protocols    []string `json:"protocols"`
	Ports        []int    `json:"ports"`
	PathPattern  string   `json:"path_pattern"`
	SourceRuleID string   `json:"source_rule_id"`
}

type ScopeRuleSummary struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	File     string `json:"file"`
}

type Warning struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	SourceRuleID string `json:"source_rule_id,omitempty"`
}

type TargetPlan struct {
	ScopeDigest      string             `json:"scope_digest"`
	Digest           string             `json:"target_plan_digest"`
	DiscoveryRoots   []DiscoveryRoot    `json:"discovery_roots"`
	ExactActiveSeeds []ActiveSeed       `json:"exact_active_seeds"`
	WildcardRules    []WildcardRule     `json:"wildcard_rules"`
	Exclusions       []ScopeRuleSummary `json:"exclusions"`
	AllowedProtocols []string           `json:"allowed_protocols"`
	AllowedPorts     []int              `json:"allowed_ports"`
	Warnings         []Warning          `json:"warnings"`
}

type ManualDiscoveryRoot struct {
	Domain string
	Reason string
}

func Plan(sc platformscope.Scope, manual []ManualDiscoveryRoot) (TargetPlan, error) {
	p := TargetPlan{ScopeDigest: sc.Digest(), DiscoveryRoots: []DiscoveryRoot{}, ExactActiveSeeds: []ActiveSeed{}, WildcardRules: []WildcardRule{}, Exclusions: []ScopeRuleSummary{}, AllowedProtocols: []string{}, AllowedPorts: []int{}, Warnings: []Warning{}}
	protocolSet := map[string]bool{}
	portSet := map[int]bool{}
	rootMap := map[string]DiscoveryRoot{}
	seedMap := map[string]ActiveSeed{}

	for _, r := range sc.ExcludeRules() {
		p.Exclusions = append(p.Exclusions, summarize(r))
	}
	for _, r := range sc.IncludeRules() {
		protocols, protocolOK := finiteProtocols(r.Protocol)
		ports, portOK := finitePorts(r.Port)
		if !protocolOK {
			p.Warnings = append(p.Warnings, warn("ambiguous_protocol_regex", "protocol expression cannot be safely enumerated", r.ID))
		}
		if !portOK {
			p.Warnings = append(p.Warnings, warn("ambiguous_port_regex", "port expression cannot be safely enumerated; active port scanning is disabled for this rule", r.ID))
		}
		for _, v := range protocols {
			protocolSet[v] = true
		}
		for _, v := range ports {
			portSet[v] = true
		}

		if host, ok := exactHost(r.Host); ok {
			path, pathOK := initialPath(r.File)
			if !pathOK {
				p.Warnings = append(p.Warnings, warn("no_safe_initial_path", "path expression does not authorize / and has no single literal path", r.ID))
				continue
			}
			if !protocolOK || !portOK {
				continue
			}
			for _, protocol := range protocols {
				for _, port := range ports {
					raw := endpointURL(protocol, host, port, path)
					if !sc.Allows(raw) {
						continue
					}
					key := host + "\x00" + r.File
					seed := seedMap[key]
					seed.Host, seed.PathPattern = host, r.File
					seed.Endpoints = appendUniqueEndpoint(seed.Endpoints, Endpoint{Protocol: protocol, Port: port, URL: raw})
					seed.SourceRuleIDs = appendUnique(seed.SourceRuleIDs, r.ID)
					seedMap[key] = seed
				}
			}
			continue
		}
		if base, ok := narrowWildcardBase(r.Host); ok {
			w := WildcardRule{HostPattern: r.Host, BaseDomain: base, Protocols: protocols, Ports: ports, PathPattern: r.File, SourceRuleID: r.ID}
			p.WildcardRules = append(p.WildcardRules, w)
			existing := rootMap[base]
			existing.Domain, existing.Source = base, "derived"
			existing.SourceRuleIDs = appendUnique(existing.SourceRuleIDs, r.ID)
			rootMap[base] = existing
			continue
		}
		p.Warnings = append(p.Warnings, warn("ambiguous_host_regex", "host expression is enforced but cannot be safely converted to an exact target or discovery root", r.ID))
	}

	for _, m := range manual {
		domain, err := normalizeHostname(m.Domain)
		if err != nil {
			return TargetPlan{}, fmt.Errorf("manual discovery root %q: %w", m.Domain, err)
		}
		if strings.TrimSpace(m.Reason) == "" {
			return TargetPlan{}, fmt.Errorf("manual discovery root %q requires a reason", domain)
		}
		existing := rootMap[domain]
		existing.Domain, existing.Source, existing.Reason = domain, "manual", strings.TrimSpace(m.Reason)
		existing.SourceRuleIDs = appendUnique(existing.SourceRuleIDs, "manual-"+shortDigest(domain+"\x00"+existing.Reason))
		rootMap[domain] = existing
	}
	for _, v := range rootMap {
		sort.Strings(v.SourceRuleIDs)
		p.DiscoveryRoots = append(p.DiscoveryRoots, v)
	}
	for _, v := range seedMap {
		sort.Strings(v.SourceRuleIDs)
		sort.Slice(v.Endpoints, func(i, j int) bool { return v.Endpoints[i].URL < v.Endpoints[j].URL })
		p.ExactActiveSeeds = append(p.ExactActiveSeeds, v)
	}
	for v := range protocolSet {
		p.AllowedProtocols = append(p.AllowedProtocols, v)
	}
	for v := range portSet {
		p.AllowedPorts = append(p.AllowedPorts, v)
	}
	sortPlan(&p)
	p.Digest = planDigest(p)
	return p, nil
}

func (p TargetPlan) InitialURLs() []string {
	var out []string
	for _, seed := range p.ExactActiveSeeds {
		for _, endpoint := range seed.Endpoints {
			out = appendUnique(out, endpoint.URL)
		}
	}
	sort.Strings(out)
	return out
}

func (p TargetPlan) ExactHosts() []string {
	var out []string
	for _, seed := range p.ExactActiveSeeds {
		out = appendUnique(out, seed.Host)
	}
	sort.Strings(out)
	return out
}

func (p TargetPlan) DiscoveryDomains() []string {
	out := make([]string, len(p.DiscoveryRoots))
	for i := range p.DiscoveryRoots {
		out[i] = p.DiscoveryRoots[i].Domain
	}
	return out
}

func (p TargetPlan) HasExecutableTargets() bool {
	return len(p.ExactActiveSeeds) > 0 || len(p.DiscoveryRoots) > 0
}

func exactHost(pattern string) (string, bool) {
	values, ok := finiteLiterals(pattern, 2)
	if !ok || len(values) != 1 {
		return "", false
	}
	host, err := normalizeHostname(values[0])
	return host, err == nil
}

func narrowWildcardBase(pattern string) (string, bool) {
	body := strings.TrimPrefix(strings.TrimSuffix(pattern, "$"), "^")
	var rest string
	switch {
	case strings.HasPrefix(body, `.*\.`):
		rest = strings.TrimPrefix(body, `.*\.`)
	case strings.HasPrefix(body, `[^.]+\.`):
		rest = strings.TrimPrefix(body, `[^.]+\.`)
	default:
		return "", false
	}
	base, ok := exactHost("^" + rest + "$")
	if !ok || net.ParseIP(base) != nil {
		return "", false
	}
	return base, true
}

func finiteProtocols(pattern string) ([]string, bool) {
	values, ok := finiteLiterals(pattern, 8)
	if !ok || len(values) == 0 {
		return nil, false
	}
	for _, v := range values {
		if v != "http" && v != "https" {
			return nil, false
		}
	}
	sort.Strings(values)
	return values, true
}

func finitePorts(pattern string) ([]int, bool) {
	values, ok := finiteLiterals(pattern, 32)
	if !ok || len(values) == 0 {
		return nil, false
	}
	ports := make([]int, 0, len(values))
	for _, value := range values {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, false
		}
		if !containsInt(ports, port) {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports, true
}

func finiteLiterals(pattern string, limit int) ([]string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	return enumerate(re.Simplify(), limit)
}

func enumerate(re *syntax.Regexp, limit int) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginText, syntax.OpEndText:
		return []string{""}, true
	case syntax.OpLiteral:
		return []string{string(re.Rune)}, true
	case syntax.OpCapture:
		return enumerate(re.Sub[0], limit)
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			part, ok := enumerate(sub, limit)
			if !ok {
				return nil, false
			}
			var next []string
			for _, a := range out {
				for _, b := range part {
					next = append(next, a+b)
					if len(next) > limit {
						return nil, false
					}
				}
			}
			out = next
		}
		return uniqueStrings(out), true
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			part, ok := enumerate(sub, limit)
			if !ok {
				return nil, false
			}
			out = append(out, part...)
			if len(out) > limit {
				return nil, false
			}
		}
		return uniqueStrings(out), true
	case syntax.OpQuest:
		part, ok := enumerate(re.Sub[0], limit)
		if !ok || len(part)+1 > limit {
			return nil, false
		}
		return uniqueStrings(append(part, "")), true
	default:
		return nil, false
	}
}

func initialPath(pattern string) (string, bool) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false
	}
	if full(re, "/") {
		return "/", true
	}
	values, ok := finiteLiterals(pattern, 2)
	if !ok || len(values) != 1 || !strings.HasPrefix(values[0], "/") {
		return "", false
	}
	return values[0], true
}

func normalizeHostname(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if len(host) == 0 || len(host) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid hostname")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid hostname")
			}
		}
	}
	return host, nil
}

func endpointURL(protocol, host string, port int, path string) string {
	authority := host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if (protocol == "http" && port != 80) || (protocol == "https" && port != 443) {
		authority += ":" + strconv.Itoa(port)
	}
	u := url.URL{Scheme: protocol, Host: authority, Path: path}
	return u.String()
}

func summarize(r platformscope.NormalizedRule) ScopeRuleSummary {
	return ScopeRuleSummary{ID: r.ID, Digest: r.Digest, Protocol: r.Protocol, Host: r.Host, Port: r.Port, File: r.File}
}
func warn(code, message, ruleID string) Warning {
	return Warning{Code: code, Message: message, SourceRuleID: ruleID}
}
func shortDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}
func planDigest(p TargetPlan) string {
	p.Digest = ""
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func full(r *regexp.Regexp, v string) bool {
	loc := r.FindStringIndex(v)
	return loc != nil && loc[0] == 0 && loc[1] == len(v)
}
func containsInt(items []int, value int) bool {
	for _, v := range items {
		if v == value {
			return true
		}
	}
	return false
}
func appendUnique(items []string, value string) []string {
	for _, v := range items {
		if v == value {
			return items
		}
	}
	return append(items, value)
}
func appendUniqueEndpoint(items []Endpoint, value Endpoint) []Endpoint {
	for _, v := range items {
		if v.URL == value.URL {
			return items
		}
	}
	return append(items, value)
}
func uniqueStrings(items []string) []string {
	out := []string{}
	for _, v := range items {
		out = appendUnique(out, v)
	}
	sort.Strings(out)
	return out
}
func sortPlan(p *TargetPlan) {
	sort.Slice(p.DiscoveryRoots, func(i, j int) bool { return p.DiscoveryRoots[i].Domain < p.DiscoveryRoots[j].Domain })
	sort.Slice(p.ExactActiveSeeds, func(i, j int) bool {
		if p.ExactActiveSeeds[i].Host == p.ExactActiveSeeds[j].Host {
			return p.ExactActiveSeeds[i].PathPattern < p.ExactActiveSeeds[j].PathPattern
		}
		return p.ExactActiveSeeds[i].Host < p.ExactActiveSeeds[j].Host
	})
	sort.Slice(p.WildcardRules, func(i, j int) bool { return p.WildcardRules[i].SourceRuleID < p.WildcardRules[j].SourceRuleID })
	sort.Slice(p.Exclusions, func(i, j int) bool { return p.Exclusions[i].ID < p.Exclusions[j].ID })
	sort.Slice(p.Warnings, func(i, j int) bool {
		if p.Warnings[i].SourceRuleID == p.Warnings[j].SourceRuleID {
			return p.Warnings[i].Code < p.Warnings[j].Code
		}
		return p.Warnings[i].SourceRuleID < p.Warnings[j].SourceRuleID
	})
	sort.Strings(p.AllowedProtocols)
	sort.Ints(p.AllowedPorts)
}
