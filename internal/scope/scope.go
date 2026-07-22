package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Rule struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	File     string `json:"file"`
	Enabled  bool   `json:"enabled"`
}

type RuleKind string

const (
	IncludeRule RuleKind = "include"
	ExcludeRule RuleKind = "exclude"
)

type NormalizedRule struct {
	ID       string   `json:"id"`
	Digest   string   `json:"digest"`
	Kind     RuleKind `json:"kind"`
	Protocol string   `json:"protocol"`
	Host     string   `json:"host"`
	Port     string   `json:"port"`
	File     string   `json:"file"`
	Enabled  bool     `json:"enabled"`
}

type Reason string

const (
	ReasonAllowed          Reason = "allowed"
	ReasonInvalidTarget    Reason = "unsupported_target"
	ReasonInvalidHostname  Reason = "invalid_hostname"
	ReasonExcluded         Reason = "matched_exclusion"
	ReasonProtocolMismatch Reason = "protocol_not_authorized"
	ReasonHostMismatch     Reason = "host_mismatch"
	ReasonPortMismatch     Reason = "port_not_authorized"
	ReasonPathMismatch     Reason = "path_not_authorized"
	ReasonNoInclude        Reason = "no_matching_include"
)

type Evaluation struct {
	Target            string   `json:"target"`
	Allowed           bool     `json:"allowed"`
	Reason            Reason   `json:"reason"`
	MatchedIncludeIDs []string `json:"matched_include_rule_ids,omitempty"`
	MatchedExcludeIDs []string `json:"matched_exclude_rule_ids,omitempty"`
}

type burpFile struct {
	Target struct {
		Scope struct {
			Include []Rule `json:"include"`
			Exclude []Rule `json:"exclude"`
		} `json:"scope"`
	} `json:"target"`
}

type compiled struct {
	rule                       NormalizedRule
	protocol, host, port, file *regexp.Regexp
}

type Scope struct {
	include []compiled
	exclude []compiled
	digest  string
}

func LoadBurp(path string) (Scope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Scope{}, err
	}
	var f burpFile
	if err := json.Unmarshal(b, &f); err != nil {
		return Scope{}, err
	}
	return Compile(f.Target.Scope.Include, f.Target.Scope.Exclude)
}

func Compile(includes, excludes []Rule) (Scope, error) {
	in, err := compile(includes, IncludeRule)
	if err != nil {
		return Scope{}, fmt.Errorf("include scope: %w", err)
	}
	ex, err := compile(excludes, ExcludeRule)
	if err != nil {
		return Scope{}, fmt.Errorf("exclude scope: %w", err)
	}
	if len(in) == 0 {
		return Scope{}, fmt.Errorf("scope requires at least one enabled include rule")
	}
	s := Scope{include: in, exclude: ex}
	s.digest = digestRules(append(s.IncludeRules(), s.ExcludeRules()...))
	return s, nil
}

func compile(rules []Rule, kind RuleKind) ([]compiled, error) {
	out := make([]compiled, 0, len(rules))
	seen := map[string]bool{}
	for _, source := range rules {
		if !source.Enabled {
			continue
		}
		r := normalizeRule(source, kind)
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		vals := []string{r.Protocol, r.Host, r.Port, r.File}
		dest := make([]*regexp.Regexp, 4)
		for i, v := range vals {
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid rule expression %q: %w", v, err)
			}
			dest[i] = re
		}
		out = append(out, compiled{rule: r, protocol: dest[0], host: dest[1], port: dest[2], file: dest[3]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rule.ID < out[j].rule.ID })
	return out, nil
}

func normalizeRule(r Rule, kind RuleKind) NormalizedRule {
	protocol := strings.TrimSpace(r.Protocol)
	host := strings.ToLower(strings.TrimSpace(r.Host))
	port := strings.TrimSpace(r.Port)
	file := strings.TrimSpace(r.File)
	if protocol == "" {
		protocol = ".*"
	}
	if host == "" {
		host = ".*"
	}
	if port == "" {
		port = ".*"
	}
	if file == "" {
		file = ".*"
	}
	canonical := struct {
		Kind                       RuleKind `json:"kind"`
		Protocol, Host, Port, File string
		Enabled                    bool
	}{kind, protocol, host, port, file, true}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	return NormalizedRule{ID: string(kind) + "-" + digest[:16], Digest: digest, Kind: kind, Protocol: protocol, Host: host, Port: port, File: file, Enabled: true}
}

func (s Scope) Digest() string                 { return s.digest }
func (s Scope) IncludeRules() []NormalizedRule { return copiedRules(s.include) }
func (s Scope) ExcludeRules() []NormalizedRule { return copiedRules(s.exclude) }
func (s Scope) IncludeDigests() []string       { return ruleDigests(s.include) }
func (s Scope) ExcludeDigests() []string       { return ruleDigests(s.exclude) }

func copiedRules(rules []compiled) []NormalizedRule {
	out := make([]NormalizedRule, len(rules))
	for i := range rules {
		out[i] = rules[i].rule
	}
	return out
}
func ruleDigests(rules []compiled) []string {
	out := make([]string, len(rules))
	for i := range rules {
		out[i] = rules[i].rule.Digest
	}
	return out
}
func digestRules(rules []NormalizedRule) string {
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	b, _ := json.Marshal(rules)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s Scope) Allows(raw string) bool { return s.Evaluate(raw).Allowed }

func (s Scope) Evaluate(raw string) Evaluation {
	e := Evaluation{Target: raw, Reason: ReasonInvalidTarget}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return e
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	values := []string{strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), port, path}
	for _, r := range s.exclude {
		if matches(r, values) {
			e.MatchedExcludeIDs = append(e.MatchedExcludeIDs, r.rule.ID)
		}
	}
	if len(e.MatchedExcludeIDs) > 0 {
		e.Reason = ReasonExcluded
		return e
	}
	for _, r := range s.include {
		if matches(r, values) {
			e.MatchedIncludeIDs = append(e.MatchedIncludeIDs, r.rule.ID)
		}
	}
	if len(e.MatchedIncludeIDs) > 0 {
		e.Allowed = true
		e.Reason = ReasonAllowed
		return e
	}
	e.Reason = mismatchReason(s.include, values)
	return e
}

func mismatchReason(rules []compiled, v []string) Reason {
	if !anyMatch(rules, 0, v[0]) {
		return ReasonProtocolMismatch
	}
	if !anyPrefix(rules, v, 2) {
		return ReasonHostMismatch
	}
	if !anyPrefix(rules, v, 3) {
		return ReasonPortMismatch
	}
	if !anyPrefix(rules, v, 4) {
		return ReasonPathMismatch
	}
	return ReasonNoInclude
}
func anyMatch(rules []compiled, index int, value string) bool {
	for _, r := range rules {
		if full(regexAt(r, index), value) {
			return true
		}
	}
	return false
}
func anyPrefix(rules []compiled, values []string, count int) bool {
	for _, r := range rules {
		ok := true
		for i := 0; i < count; i++ {
			if !full(regexAt(r, i), values[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
func regexAt(r compiled, index int) *regexp.Regexp {
	return []*regexp.Regexp{r.protocol, r.host, r.port, r.file}[index]
}

func (s Scope) AllowsRedirect(from, to string) bool { return s.Allows(from) && s.Allows(to) }
func matches(r compiled, v []string) bool {
	return full(r.protocol, v[0]) && full(r.host, v[1]) && full(r.port, v[2]) && full(r.file, v[3])
}
func full(r *regexp.Regexp, v string) bool {
	loc := r.FindStringIndex(v)
	return loc != nil && loc[0] == 0 && loc[1] == len(v)
}

func HostScope(hosts ...string) (Scope, error) {
	rules := make([]Rule, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if net.ParseIP(h) == nil {
			h = `(?:^|.*\.)` + regexp.QuoteMeta(h) + `$`
		} else {
			h = `^` + regexp.QuoteMeta(h) + `$`
		}
		rules = append(rules, Rule{Protocol: `^https?$`, Host: h, Port: `^(?:80|443)$`, File: `^/.*`, Enabled: true})
	}
	return Compile(rules, nil)
}
