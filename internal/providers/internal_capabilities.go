package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type TargetingPrepareInput struct {
	ExactURLs        []string `json:"exact_urls"`
	DiscoveredURLs   []string `json:"discovered_urls"`
	Ports            []int    `json:"ports"`
	TargetPlanDigest string   `json:"target_plan_digest"`
}

type TargetingPrepareOutput struct {
	URLs             []string                   `json:"urls"`
	PortTargets      []string                   `json:"port_targets"`
	Filtered         []targeting.FilterDecision `json:"filtered"`
	AcceptedCount    int                        `json:"accepted_count"`
	FilteredCount    int                        `json:"filtered_count"`
	TargetPlanDigest string                     `json:"target_plan_digest"`
}

type CompareAssetsInput struct {
	Current          []string `json:"current"`
	Previous         []string `json:"previous"`
	CoverageComplete bool     `json:"coverage_complete"`
	TargetPlanDigest string   `json:"target_plan_digest"`
}

type StatusRoutes struct {
	Active         []string `json:"active"`
	Redirects      []string `json:"redirects"`
	Authentication []string `json:"authentication"`
	Ignored        []string `json:"ignored"`
}

type AssetChange struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type CompareAssetsOutput struct {
	NewOrChanged []string      `json:"new_or_changed"`
	CrawlTargets []string      `json:"crawl_targets"`
	ScanTargets  []string      `json:"scan_targets"`
	StatusRoutes StatusRoutes  `json:"status_routes"`
	Removed      []string      `json:"removed"`
	Changes      []AssetChange `json:"changes"`
}

type ClassifyEndpointInput struct {
	Active           []string `json:"active"`
	Passive          []string `json:"passive"`
	TargetPlanDigest string   `json:"target_plan_digest"`
}

type InterestingEndpoint struct {
	Endpoint        normalize.EndpointKey `json:"endpoint"`
	MatchedKeywords []string              `json:"matched_keywords"`
}

type ClassifyEndpointOutput struct {
	Endpoints            []normalize.EndpointKey `json:"endpoints"`
	InterestingEndpoints []InterestingEndpoint   `json:"interesting_endpoints"`
}

type ReportChangesInput struct {
	Changes          []AssetChange         `json:"changes"`
	Endpoints        []InterestingEndpoint `json:"endpoints"`
	CandidateMatches []string              `json:"candidate_matches"`
	TargetPlanDigest string                `json:"target_plan_digest"`
}

type ReportChangesOutput struct {
	Changes          []AssetChange         `json:"changes"`
	Endpoints        []InterestingEndpoint `json:"endpoints"`
	CandidateMatches []string              `json:"candidate_matches"`
	TargetPlanDigest string                `json:"target_plan_digest"`
}

type internalCap struct{ m capability.Manifest }

func (c internalCap) Manifest() capability.Manifest { return c.m }

func (c internalCap) ValidateDefinition(raw json.RawMessage) error {
	return validateInternalInput(c.m.Name, raw)
}

func (c internalCap) Validate(_ context.Context, r capability.Request) error {
	if err := validateInternalInput(c.m.Name, r.Action.Input); err != nil {
		return err
	}
	if c.m.Name == "targeting.prepare" {
		if _, ok := r.Scope.(targeting.DetailedScope); !ok {
			return fmt.Errorf("target preparation requires detailed scope evaluation")
		}
	}
	return nil
}

func (c internalCap) Execute(_ context.Context, r capability.Request) (capability.Result, error) {
	var output any
	var summary string
	var err error
	switch c.m.Name {
	case "targeting.prepare":
		output, summary, err = executeTargetingPrepare(r)
	case "compare.assets":
		output, summary, err = executeCompareAssets(r.Action.Input)
	case "classify.endpoint":
		output, summary, err = executeClassifyEndpoint(r.Action.Input)
	case "report.changes":
		output, summary, err = executeReportChanges(r.Action.Input)
	default:
		err = fmt.Errorf("unsupported internal capability %q", c.m.Name)
	}
	if err != nil {
		return capability.Result{}, err
	}
	b, err := json.Marshal(output)
	if err != nil {
		return capability.Result{}, err
	}
	return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Status: "succeeded", Summary: summary, Output: b}}, nil
}

func internalCapabilities() []capability.Capability {
	definitions := []struct {
		name, description string
		input, output     string
	}{
		{"targeting.prepare", "Filter and prepare scope-authorized active targets", targetingPrepareInputSchema, targetingPrepareOutputSchema},
		{"compare.assets", "Compare current and previous HTTP asset observations", compareAssetsInputSchema, compareAssetsOutputSchema},
		{"classify.endpoint", "Normalize and classify discovered endpoints", classifyEndpointInputSchema, classifyEndpointOutputSchema},
		{"report.changes", "Produce a typed changes-only report", reportChangesInputSchema, reportChangesOutputSchema},
	}
	out := make([]capability.Capability, 0, len(definitions))
	for _, definition := range definitions {
		out = append(out, internalCap{capability.Manifest{Name: definition.name, Description: definition.description, Version: "2", Risk: policy.Passive, InputSchema: json.RawMessage(definition.input), OutputSchema: json.RawMessage(definition.output), RetrySafe: true, Idempotent: true, SupportedProviders: []string{"platform"}, DefaultTimeout: time.Minute}})
	}
	return out
}

func validateInternalInput(name string, raw json.RawMessage) error {
	switch name {
	case "targeting.prepare":
		var input TargetingPrepareInput
		if err := strictInternal(raw, &input, "exact_urls", "discovered_urls", "ports", "target_plan_digest"); err != nil {
			return fmt.Errorf("targeting.prepare input: %w", err)
		}
		if err := requireDigest(input.TargetPlanDigest); err != nil {
			return err
		}
		seenPorts := map[int]bool{}
		for _, port := range input.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("targeting.prepare input: port %d is outside 1-65535", port)
			}
			if seenPorts[port] {
				return fmt.Errorf("targeting.prepare input: duplicate port %d", port)
			}
			seenPorts[port] = true
		}
	case "compare.assets":
		var input CompareAssetsInput
		if err := strictInternal(raw, &input, "current", "previous", "coverage_complete", "target_plan_digest"); err != nil {
			return fmt.Errorf("compare.assets input: %w", err)
		}
		if err := requireDigest(input.TargetPlanDigest); err != nil {
			return err
		}
		if err := validateObservationURLs(append(append([]string{}, input.Current...), input.Previous...)); err != nil {
			return fmt.Errorf("compare.assets input: %w", err)
		}
	case "classify.endpoint":
		var input ClassifyEndpointInput
		if err := strictInternal(raw, &input, "active", "passive", "target_plan_digest"); err != nil {
			return fmt.Errorf("classify.endpoint input: %w", err)
		}
		if err := requireDigest(input.TargetPlanDigest); err != nil {
			return err
		}
		if err := validateObservationURLs(append(append([]string{}, input.Active...), input.Passive...)); err != nil {
			return fmt.Errorf("classify.endpoint input: %w", err)
		}
	case "report.changes":
		var input ReportChangesInput
		if err := strictInternal(raw, &input, "changes", "endpoints", "candidate_matches", "target_plan_digest"); err != nil {
			return fmt.Errorf("report.changes input: %w", err)
		}
		if err := requireDigest(input.TargetPlanDigest); err != nil {
			return err
		}
		for index, change := range input.Changes {
			if strings.TrimSpace(change.Kind) == "" || strings.TrimSpace(change.Value) == "" {
				return fmt.Errorf("report.changes input: change %d requires kind and value", index)
			}
			if change.Kind != "new_or_changed" && change.Kind != "removed" {
				return fmt.Errorf("report.changes input: change %d has unsupported kind %q", index, change.Kind)
			}
		}
		for index, endpoint := range input.Endpoints {
			if err := validateInterestingEndpoint(endpoint); err != nil {
				return fmt.Errorf("report.changes input: endpoint %d: %w", index, err)
			}
		}
		for index, candidate := range input.CandidateMatches {
			if strings.TrimSpace(candidate) == "" {
				return fmt.Errorf("report.changes input: candidate match %d is empty", index)
			}
		}
	default:
		return fmt.Errorf("unsupported internal capability %q", name)
	}
	return nil
}

func executeTargetingPrepare(r capability.Request) (TargetingPrepareOutput, string, error) {
	var input TargetingPrepareInput
	if err := strictInternal(r.Action.Input, &input, "exact_urls", "discovered_urls", "ports", "target_plan_digest"); err != nil {
		return TargetingPrepareOutput{}, "", err
	}
	detailed, ok := r.Scope.(targeting.DetailedScope)
	if !ok {
		return TargetingPrepareOutput{}, "", fmt.Errorf("target preparation requires detailed scope evaluation")
	}
	candidates := append(append([]string{}, input.ExactURLs...), input.DiscoveredURLs...)
	filtered := targeting.FilterURLs(detailed, candidates)
	if len(filtered.AuthorizedURLs) == 0 {
		return TargetingPrepareOutput{}, "", fmt.Errorf("target plan has no executable authorized targets")
	}
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
		if containsIntValue(input.Ports, port) {
			portTargets = append(portTargets, raw)
		}
	}
	sort.Strings(portTargets)
	output := TargetingPrepareOutput{URLs: filtered.AuthorizedURLs, PortTargets: portTargets, Filtered: filtered.Filtered, AcceptedCount: filtered.AcceptedCount, FilteredCount: filtered.FilteredCount, TargetPlanDigest: input.TargetPlanDigest}
	return output, fmt.Sprintf("prepared %d fully authorized active targets", len(filtered.AuthorizedURLs)), nil
}

func executeCompareAssets(raw json.RawMessage) (CompareAssetsOutput, string, error) {
	var input CompareAssetsInput
	if err := strictInternal(raw, &input, "current", "previous", "coverage_complete", "target_plan_digest"); err != nil {
		return CompareAssetsOutput{}, "", err
	}
	previous := map[string]string{}
	for _, value := range input.Previous {
		previous[extractURL(value)] = observationFingerprint(value)
	}
	changed := []string{}
	routes := StatusRoutes{Active: []string{}, Redirects: []string{}, Authentication: []string{}, Ignored: []string{}}
	for _, value := range input.Current {
		target := extractURL(value)
		if old, exists := previous[target]; !exists || old != observationFingerprint(value) {
			changed = append(changed, target)
			switch status := extractStatus(value); {
			case status >= 200 && status <= 299:
				routes.Active = append(routes.Active, target)
			case status == 301 || status == 302 || status == 307 || status == 308:
				routes.Redirects = append(routes.Redirects, target)
			case status == 401 || status == 403:
				routes.Authentication = append(routes.Authentication, target)
			default:
				routes.Ignored = append(routes.Ignored, target)
			}
		}
	}
	removed := []string{}
	if input.CoverageComplete {
		current := map[string]bool{}
		for _, value := range input.Current {
			current[extractURL(value)] = true
		}
		for _, value := range input.Previous {
			if !current[extractURL(value)] {
				removed = append(removed, extractURL(value))
			}
		}
	}
	scanTargets := append(append(append([]string{}, routes.Active...), routes.Redirects...), routes.Authentication...)
	changes := append(changeRows("new_or_changed", changed), changeRows("removed", removed)...)
	output := CompareAssetsOutput{NewOrChanged: changed, CrawlTargets: routes.Active, ScanTargets: scanTargets, StatusRoutes: routes, Removed: removed, Changes: changes}
	return output, fmt.Sprintf("asset comparison found %d new or changed and %d removed", len(changed), len(removed)), nil
}

func executeClassifyEndpoint(raw json.RawMessage) (ClassifyEndpointOutput, string, error) {
	var input ClassifyEndpointInput
	if err := strictInternal(raw, &input, "active", "passive", "target_plan_digest"); err != nil {
		return ClassifyEndpointOutput{}, "", err
	}
	targets := append(append([]string{}, input.Active...), input.Passive...)
	seen := map[string]bool{}
	endpoints := []normalize.EndpointKey{}
	interesting := []InterestingEndpoint{}
	for _, rawTarget := range targets {
		key, err := normalize.Endpoint(extractURL(rawTarget), "GET", "")
		if err != nil || seen[key.Digest] {
			continue
		}
		seen[key.Digest] = true
		endpoints = append(endpoints, key)
		matched := []string{}
		lower := strings.ToLower(key.ExactURL)
		for _, word := range []string{"admin", "api", "swagger", "openapi", "graphql", "oauth", "login", "token", "debug", "upload"} {
			if strings.Contains(lower, word) {
				matched = append(matched, word)
			}
		}
		if len(matched) > 0 {
			interesting = append(interesting, InterestingEndpoint{Endpoint: key, MatchedKeywords: matched})
		}
	}
	output := ClassifyEndpointOutput{Endpoints: endpoints, InterestingEndpoints: interesting}
	return output, fmt.Sprintf("classified %d unique endpoints (%d interesting)", len(endpoints), len(interesting)), nil
}

func executeReportChanges(raw json.RawMessage) (ReportChangesOutput, string, error) {
	var input ReportChangesInput
	if err := strictInternal(raw, &input, "changes", "endpoints", "candidate_matches", "target_plan_digest"); err != nil {
		return ReportChangesOutput{}, "", err
	}
	return ReportChangesOutput(input), "generated changes-only report", nil
}

func strictInternal(raw json.RawMessage, destination any, required ...string) error {
	if len(raw) == 0 {
		return fmt.Errorf("structured input is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("input must contain exactly one JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, field := range required {
		value, ok := fields[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("field %q is required and cannot be null", field)
		}
	}
	return nil
}

func requireDigest(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("target_plan_digest is required")
	}
	return nil
}

func validateObservationURLs(values []string) error {
	for index, value := range values {
		if _, err := normalize.URL(extractURL(value)); err != nil {
			return fmt.Errorf("item %d does not contain a valid HTTP URL: %w", index, err)
		}
	}
	return nil
}

func validateInterestingEndpoint(value InterestingEndpoint) error {
	if _, err := normalize.URL(value.Endpoint.ExactURL); err != nil {
		return fmt.Errorf("invalid exact_url: %w", err)
	}
	if strings.TrimSpace(value.Endpoint.RouteSignature) == "" || strings.TrimSpace(value.Endpoint.Method) == "" || strings.TrimSpace(value.Endpoint.Digest) == "" {
		return fmt.Errorf("endpoint route_signature, method, and digest are required")
	}
	if value.Endpoint.QueryParameters == nil {
		return fmt.Errorf("endpoint query_parameters is required and cannot be null")
	}
	if len(value.MatchedKeywords) == 0 {
		return fmt.Errorf("matched_keywords must contain at least one value")
	}
	for _, keyword := range value.MatchedKeywords {
		if strings.TrimSpace(keyword) == "" {
			return fmt.Errorf("matched_keywords cannot contain empty values")
		}
	}
	return nil
}

func containsIntValue(items []int, value int) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func extractURL(raw string) string {
	var value struct {
		URL   string `json:"url"`
		Input string `json:"input"`
		Host  string `json:"host"`
	}
	if json.Unmarshal([]byte(raw), &value) == nil {
		for _, candidate := range []string{value.URL, value.Input, value.Host} {
			if candidate != "" {
				return candidate
			}
		}
	}
	return raw
}

func extractStatus(raw string) int {
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &value) == nil {
		for _, key := range []string{"status_code", "status-code", "status"} {
			var status int
			if rawStatus, ok := value[key]; ok && json.Unmarshal(rawStatus, &status) == nil {
				return status
			}
		}
	}
	return 0
}

func observationFingerprint(raw string) string {
	var value map[string]any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return raw
	}
	stable := map[string]any{}
	for _, key := range []string{"status_code", "status-code", "host", "url", "input", "tech", "technologies", "webserver", "ip", "a", "cname", "port", "scheme", "title"} {
		if item, ok := value[key]; ok {
			stable[key] = item
		}
	}
	b, _ := json.Marshal(stable)
	return string(b)
}

func changeRows(kind string, items []string) []AssetChange {
	out := make([]AssetChange, 0, len(items))
	for _, item := range items {
		out = append(out, AssetChange{Kind: kind, Value: item})
	}
	return out
}

const targetingPrepareInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["exact_urls","discovered_urls","ports","target_plan_digest"],"properties":{"exact_urls":{"type":"array","items":{"type":"string"}},"discovered_urls":{"type":"array","items":{"type":"string"}},"ports":{"type":"array","items":{"type":"integer","minimum":1,"maximum":65535},"uniqueItems":true},"target_plan_digest":{"type":"string","minLength":1}}}`
const targetingPrepareOutputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["urls","port_targets","filtered","accepted_count","filtered_count","target_plan_digest"],"properties":{"urls":{"type":"array","items":{"type":"string","format":"uri"}},"port_targets":{"type":"array","items":{"type":"string","format":"uri"}},"filtered":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["target","accepted","reason"],"properties":{"target":{"type":"string"},"accepted":{"type":"boolean"},"reason":{"type":"string"},"authorized_urls":{"type":"array","items":{"type":"string","format":"uri"}},"source_rule_ids":{"type":"array","items":{"type":"string"}}}}},"accepted_count":{"type":"integer","minimum":0},"filtered_count":{"type":"integer","minimum":0},"target_plan_digest":{"type":"string","minLength":1}}}`
const compareAssetsInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["current","previous","coverage_complete","target_plan_digest"],"properties":{"current":{"type":"array","items":{"type":"string"}},"previous":{"type":"array","items":{"type":"string"}},"coverage_complete":{"type":"boolean"},"target_plan_digest":{"type":"string","minLength":1}}}`
const compareAssetsOutputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["new_or_changed","crawl_targets","scan_targets","status_routes","removed","changes"],"properties":{"new_or_changed":{"type":"array","items":{"type":"string","format":"uri"}},"crawl_targets":{"type":"array","items":{"type":"string","format":"uri"}},"scan_targets":{"type":"array","items":{"type":"string","format":"uri"}},"status_routes":{"type":"object","additionalProperties":false,"required":["active","redirects","authentication","ignored"],"properties":{"active":{"type":"array","items":{"type":"string","format":"uri"}},"redirects":{"type":"array","items":{"type":"string","format":"uri"}},"authentication":{"type":"array","items":{"type":"string","format":"uri"}},"ignored":{"type":"array","items":{"type":"string","format":"uri"}}}},"removed":{"type":"array","items":{"type":"string","format":"uri"}},"changes":{"type":"array","items":{"$ref":"#/$defs/change"}}},"$defs":{"change":{"type":"object","additionalProperties":false,"required":["kind","value"],"properties":{"kind":{"enum":["new_or_changed","removed"]},"value":{"type":"string","format":"uri"}}}}}`
const classifyEndpointInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["active","passive","target_plan_digest"],"properties":{"active":{"type":"array","items":{"type":"string"}},"passive":{"type":"array","items":{"type":"string"}},"target_plan_digest":{"type":"string","minLength":1}}}`
const endpointSchema = `{"type":"object","additionalProperties":false,"required":["exact_url","route_signature","method","content_type","query_parameters","digest"],"properties":{"exact_url":{"type":"string","format":"uri"},"route_signature":{"type":"string"},"method":{"type":"string"},"content_type":{"type":"string"},"query_parameters":{"type":"array","items":{"type":"string"}},"digest":{"type":"string","minLength":1}}}`
const classifyEndpointOutputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["endpoints","interesting_endpoints"],"properties":{"endpoints":{"type":"array","items":{"$ref":"#/$defs/endpoint"}},"interesting_endpoints":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["endpoint","matched_keywords"],"properties":{"endpoint":{"$ref":"#/$defs/endpoint"},"matched_keywords":{"type":"array","items":{"type":"string"}}}}}},"$defs":{"endpoint":` + endpointSchema + `}}`
const reportChangesInputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["changes","endpoints","candidate_matches","target_plan_digest"],"properties":{"changes":{"type":"array","items":{"$ref":"#/$defs/change"}},"endpoints":{"type":"array","items":{"$ref":"#/$defs/interesting"}},"candidate_matches":{"type":"array","items":{"type":"string","minLength":1}},"target_plan_digest":{"type":"string","minLength":1}},"$defs":{"change":{"type":"object","additionalProperties":false,"required":["kind","value"],"properties":{"kind":{"enum":["new_or_changed","removed"]},"value":{"type":"string","minLength":1}}},"interesting":{"type":"object","additionalProperties":false,"required":["endpoint","matched_keywords"],"properties":{"endpoint":` + endpointSchema + `,"matched_keywords":{"type":"array","minItems":1,"items":{"type":"string","minLength":1}}}}}}`
const reportChangesOutputSchema = reportChangesInputSchema
