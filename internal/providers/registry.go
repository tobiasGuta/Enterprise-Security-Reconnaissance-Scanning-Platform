package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

func Registry(cfg config.Config) *capability.Registry {
	r := capability.NewRegistry()
	red := redaction.New(cfg.Logging.SecretNames...)
	probes := providerSpecsByName(cfg)
	subfinder := commandprovider.New(commandprovider.Definition{Name: "discover.subdomains", Description: "Discover candidate subdomains from passive roots", Provider: "subfinder", Executable: cfg.Tools.Subfinder, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "subfinder", Probe: probes["subfinder"], BuildArgs: subfinderArgs}, nil, red)
	chaos := commandprovider.New(commandprovider.Definition{Name: "discover.subdomains", Description: "Enrich candidate subdomains from ProjectDiscovery Chaos", Provider: "chaos", Executable: cfg.Tools.Chaos, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, RequiredSecrets: []string{"CHAOS_KEY"}, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "chaos", Probe: probes["chaos"], BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return chaosArgs(i, cfg.Recon.ChaosKey)
	}}, nil, red)
	multi, err := capability.NewMulti("subfinder", map[string]capability.Capability{"subfinder": subfinder, "chaos": chaos})
	if err != nil {
		panic(err)
	}
	if err := r.Register(multi); err != nil {
		panic(err)
	}
	defs := []commandprovider.Definition{
		{Name: "resolve.dns", Description: "Resolve scope-authorized names", Provider: "dnsx", Executable: cfg.Tools.DNSx, Version: "3", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "dnsx", Probe: probes["dnsx"], BuildInvocation: dnsxInvocation},
		{Name: "scan.ports", Description: "Discover scope-authorized network ports", Provider: "naabu", Executable: cfg.Tools.Naabu, Version: "2", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "naabu", Probe: probes["naabu"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) { return naabuArgs(i, p, cfg.Recon) }},
		{Name: "probe.http", Description: "Probe authorized HTTP services", Provider: "httpx", Executable: cfg.Tools.HTTPX, Version: "3", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "httpx", Probe: probes["httpx"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return httpxArgs(i, p, cfg.Recon)
		}},
		{Name: "crawl.web", Description: "Crawl an authorized web target", Provider: "katana", Executable: cfg.Tools.Katana, Version: "2", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "katana", Probe: probes["katana"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return katanaArgs(i, p, cfg.Recon)
		}},
		{Name: "discover.archive_urls", Description: "Discover passive archive URLs", Provider: "gau", Executable: cfg.Tools.GAU, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "gau", Probe: probes["gau"], BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
			return gauArgs(i)
		}},
		{Name: "scan.nuclei", Description: "Run a policy-constrained safe Nuclei profile", Provider: "nuclei", Executable: cfg.Tools.Nuclei, Version: "2", Risk: policy.Moderate, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Nuclei.Timeout, OutputAdapter: "nuclei", Probe: probes["nuclei"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return nucleiArgs(i, p, cfg.Nuclei)
		}},
	}
	for _, d := range defs {
		if err := r.Register(commandprovider.New(d, nil, red)); err != nil {
			panic(err)
		}
	}
	for _, c := range internalCapabilities() {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
	return r
}

func subfinderArgs(i commandprovider.Input, _ policy.Policy) ([]string, error) {
	args, err := domainsArgs(i, "-d")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent"), nil
}

func chaosArgs(i commandprovider.Input, key string) ([]string, error) {
	if key == "" {
		return nil, fmt.Errorf("CHAOS_KEY is required for the chaos provider")
	}
	args, err := domainsArgs(i, "-d")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent"), nil
}

func naabuArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetHostsArgs(i, "-host")
	if err != nil {
		return nil, err
	}
	args = append(args, "-silent", "-rate", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)))
	if i.Ports != "" {
		args = append(args, "-p", i.Ports)
	}
	return args, nil
}

func httpxArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent", "-json", "-status-code", "-tech-detect", "-threads", fmt.Sprint(bounded(c.Concurrency, p.Concurrency))), nil
}

func katanaArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	args = append(args, "-silent", "-jsonl", "-fs", "fqdn", "-rate-limit", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)), "-concurrency", fmt.Sprint(bounded(c.Concurrency, hostConcurrency(p))))
	if i.Headless {
		args = append(args, "-headless")
	}
	return args, nil
}

func gauArgs(i commandprovider.Input) ([]string, error) {
	domains := append([]string{}, i.Domains...)
	if i.Domain != "" {
		domains = append(domains, i.Domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains are required")
	}
	return append([]string{"--json"}, domains...), nil
}

func nucleiArgs(i commandprovider.Input, p policy.Policy, c config.Nuclei) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	args = append(args, "-jsonl", "-silent", "-dr", "-rl", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)), "-c", fmt.Sprint(bounded(c.TemplateConcurrency, p.Concurrency)), "-bulk-size", fmt.Sprint(bounded(c.HostConcurrency, hostConcurrency(p))), "-headc", fmt.Sprint(bounded(c.HeadlessConcurrency, p.Concurrency)), "-severity", strings.Join(c.Severity, ","), "-tags", strings.Join(c.IncludeTags, ","), "-etags", strings.Join(c.ExcludeTags, ","))
	if c.TemplateDirectory != "" {
		args = append(args, "-t", c.TemplateDirectory)
	}
	return args, nil
}
func targetsArgs(i commandprovider.Input, flag string) ([]string, error) {
	if len(i.Targets) == 0 {
		return nil, fmt.Errorf("targets are required")
	}
	args := make([]string, 0, len(i.Targets)*2)
	for _, t := range i.Targets {
		args = append(args, flag, t)
	}
	return args, nil
}
func targetHostsArgs(i commandprovider.Input, flag string) ([]string, error) {
	hosts, err := normalizedTargetHosts(i.Targets)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(hosts)*2)
	for _, host := range hosts {
		args = append(args, flag, host)
	}
	return args, nil
}
func dnsxInvocation(i commandprovider.Input, _ policy.Policy) (commandprovider.Invocation, error) {
	hosts, err := normalizedTargetHosts(i.Targets)
	if err != nil {
		return commandprovider.Invocation{}, err
	}
	return commandprovider.Invocation{Args: []string{"-silent"}, Stdin: []byte(strings.Join(hosts, "\n") + "\n")}, nil
}
func normalizedTargetHosts(targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets are required")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("target %q must be an HTTP URL", target)
		}
		host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		if host == "" {
			return nil, fmt.Errorf("target %q has an invalid hostname", target)
		}
		seen[host] = true
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}
func domainsArgs(i commandprovider.Input, flag string) ([]string, error) {
	domains := append([]string{}, i.Domains...)
	if i.Domain != "" {
		domains = append(domains, i.Domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains are required")
	}
	args := make([]string, 0, len(domains)*2)
	for _, domain := range domains {
		args = append(args, flag, domain)
	}
	return args, nil
}

type internalCap struct{ m capability.Manifest }

func (c internalCap) Manifest() capability.Manifest { return c.m }
func (c internalCap) Validate(_ context.Context, r capability.Request) error {
	if len(r.Action.Input) == 0 {
		return fmt.Errorf("structured input is required")
	}
	return nil
}
func (c internalCap) Execute(_ context.Context, r capability.Request) (capability.Result, error) {
	var input map[string]any
	if err := json.Unmarshal(r.Action.Input, &input); err != nil {
		return capability.Result{}, err
	}
	var output any = input
	summary := c.m.Name + " completed"
	switch c.m.Name {
	case "targeting.prepare":
		detailed, ok := r.Scope.(targeting.DetailedScope)
		if !ok {
			return capability.Result{}, fmt.Errorf("target preparation requires detailed scope evaluation")
		}
		candidates := append(stringList(input["exact_urls"]), stringList(input["discovered_urls"])...)
		filtered := targeting.FilterURLs(detailed, candidates)
		if len(filtered.AuthorizedURLs) == 0 {
			return capability.Result{}, fmt.Errorf("target plan has no executable authorized targets")
		}
		ports := intList(input["ports"])
		portTargets := []string{}
		for _, raw := range filtered.AuthorizedURLs {
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			port := 80
			if u.Scheme == "https" {
				port = 443
			}
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
			if containsIntValue(ports, port) {
				portTargets = append(portTargets, raw)
			}
		}
		sort.Strings(portTargets)
		output = map[string]any{"urls": filtered.AuthorizedURLs, "port_targets": portTargets, "filtered": filtered.Filtered, "accepted_count": filtered.AcceptedCount, "filtered_count": filtered.FilteredCount, "target_plan_digest": input["target_plan_digest"]}
		summary = fmt.Sprintf("prepared %d fully authorized active targets", len(filtered.AuthorizedURLs))
	case "compare.assets":
		current := stringList(input["current"])
		previous := stringList(input["previous"])
		prev := map[string]string{}
		for _, v := range previous {
			prev[extractURL(v)] = observationFingerprint(v)
		}
		var changed []string
		routes := map[string][]string{"active": {}, "redirects": {}, "authentication": {}, "ignored": {}}
		for _, v := range current {
			target := extractURL(v)
			if old, exists := prev[target]; !exists || old != observationFingerprint(v) {
				changed = append(changed, target)
				status := extractStatus(v)
				switch {
				case status >= 200 && status <= 299:
					routes["active"] = append(routes["active"], target)
				case status == 301 || status == 302 || status == 307 || status == 308:
					routes["redirects"] = append(routes["redirects"], target)
				case status == 401 || status == 403:
					routes["authentication"] = append(routes["authentication"], target)
				default:
					routes["ignored"] = append(routes["ignored"], target)
				}
			}
		}
		var removed []string
		if complete, _ := input["coverage_complete"].(bool); complete {
			cur := map[string]bool{}
			for _, v := range current {
				cur[extractURL(v)] = true
			}
			for _, v := range previous {
				if !cur[extractURL(v)] {
					removed = append(removed, extractURL(v))
				}
			}
		}
		scanTargets := append(append(append([]string{}, routes["active"]...), routes["redirects"]...), routes["authentication"]...)
		output = map[string]any{"new_or_changed": changed, "crawl_targets": routes["active"], "scan_targets": scanTargets, "status_routes": routes, "removed": removed, "changes": append(changeRows("new_or_changed", changed), changeRows("removed", removed)...)}
		summary = fmt.Sprintf("asset comparison found %d new or changed and %d removed", len(changed), len(removed))
	case "classify.endpoint":
		targets := append(stringList(input["active"]), stringList(input["passive"])...)
		seen := map[string]bool{}
		var endpoints []normalize.EndpointKey
		var interesting []map[string]any
		for _, raw := range targets {
			raw = extractURL(raw)
			key, err := normalize.Endpoint(raw, "GET", "")
			if err == nil && !seen[key.Digest] {
				seen[key.Digest] = true
				endpoints = append(endpoints, key)
				var matched []string
				lower := strings.ToLower(key.ExactURL)
				for _, word := range []string{"admin", "api", "swagger", "openapi", "graphql", "oauth", "login", "token", "debug", "upload"} {
					if strings.Contains(lower, word) {
						matched = append(matched, word)
					}
				}
				if len(matched) > 0 {
					interesting = append(interesting, map[string]any{"endpoint": key, "matched_keywords": matched})
				}
			}
		}
		output = map[string]any{"endpoints": endpoints, "interesting_endpoints": interesting}
		summary = fmt.Sprintf("classified %d unique endpoints (%d interesting)", len(endpoints), len(interesting))
	case "report.changes":
		output = map[string]any{"changes": input["changes"], "endpoints": input["endpoints"], "candidate_matches": input["candidate_matches"]}
		summary = "generated changes-only report"
	}
	b, err := json.Marshal(output)
	if err != nil {
		return capability.Result{}, err
	}
	return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Status: "succeeded", Summary: summary, Output: b}}, nil
}
func internalCapabilities() []capability.Capability {
	names := []string{"targeting.prepare", "classify.endpoint", "compare.assets", "report.changes"}
	out := make([]capability.Capability, 0, len(names))
	for _, n := range names {
		out = append(out, internalCap{capability.Manifest{Name: n, Description: n, Version: "1", Risk: policy.Passive, InputSchema: json.RawMessage(`{"type":"object"}`), OutputSchema: json.RawMessage(`{"type":"object"}`), RetrySafe: true, Idempotent: true, SupportedProviders: []string{"platform"}, DefaultTimeout: time.Minute}})
	}
	return out
}
func intList(v any) []int {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []int{}
	for _, item := range raw {
		if n, ok := item.(float64); ok {
			out = append(out, int(n))
		}
	}
	return out
}
func containsIntValue(items []int, value int) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func stringList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func extractURL(raw string) string {
	var v map[string]any
	if json.Unmarshal([]byte(raw), &v) == nil {
		for _, key := range []string{"url", "input", "host"} {
			if s, ok := v[key].(string); ok && s != "" {
				return s
			}
		}
	}
	return raw
}
func extractStatus(raw string) int {
	var v map[string]any
	if json.Unmarshal([]byte(raw), &v) == nil {
		for _, key := range []string{"status_code", "status-code", "status"} {
			if n, ok := v[key].(float64); ok {
				return int(n)
			}
		}
	}
	return 0
}
func observationFingerprint(raw string) string {
	var v map[string]any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	stable := map[string]any{}
	for _, key := range []string{"status_code", "status-code", "host", "url", "input", "tech", "technologies", "webserver", "ip", "a", "cname", "port", "scheme", "title"} {
		if value, ok := v[key]; ok {
			stable[key] = value
		}
	}
	b, _ := json.Marshal(stable)
	return string(b)
}
func changeRows(kind string, items []string) []map[string]string {
	out := make([]map[string]string, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]string{"kind": kind, "value": item})
	}
	return out
}
func bounded(configured, policyLimit int) int {
	if policyLimit > 0 && policyLimit < configured {
		return policyLimit
	}
	return configured
}

func hostConcurrency(p policy.Policy) int {
	if p.HostConcurrency > 0 {
		return p.HostConcurrency
	}
	return p.Concurrency
}
