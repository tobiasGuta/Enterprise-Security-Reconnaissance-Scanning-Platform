package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type Input struct {
	Domain     string   `json:"domain,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	Targets    []string `json:"targets,omitempty"`
	Headless   bool     `json:"headless,omitempty"`
	Ports      string   `json:"ports,omitempty"`
	Method     string   `json:"method,omitempty"`
	PlanDigest string   `json:"target_plan_digest,omitempty"`
}
type Invocation struct {
	Args  []string
	Stdin []byte
}
type Definition struct {
	Name, Description, Provider, Executable, Version string
	Risk                                             policy.Risk
	ScopeType                                        string
	RetrySafe, Idempotent                            bool
	RequiredSecrets                                  []string
	Timeout                                          time.Duration
	PassiveInput                                     bool
	OutputAdapter                                    string
	BuildArgs                                        func(Input, policy.Policy) ([]string, error)
	BuildInvocation                                  func(Input, policy.Policy) (Invocation, error)
	Probe                                            providercheck.Spec
}
type Runner interface {
	Run(context.Context, string, []string, []byte) (stdout, stderr []byte, exitCode int, err error)
	Version(context.Context, string, []string) (string, error)
}
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			code = e.ExitCode()
		} else {
			code = -1
		}
	}
	return out.Bytes(), errOut.Bytes(), code, err
}
func (OSRunner) Version(ctx context.Context, name string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(b)), err
	}
	return strings.TrimSpace(string(b)), nil
}

type Provider struct {
	def      Definition
	runner   Runner
	redactor *redaction.Redactor
}

func New(def Definition, runner Runner, r *redaction.Redactor) *Provider {
	if runner == nil {
		runner = OSRunner{}
	}
	if r == nil {
		r = redaction.New()
	}
	return &Provider{def: def, runner: runner, redactor: r}
}
func (p *Provider) Manifest() capability.Manifest {
	return capability.Manifest{Name: p.def.Name, Description: p.def.Description, Version: p.def.Version, Risk: p.def.Risk, InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"domain":{"type":"string"},"domains":{"type":"array","items":{"type":"string"}},"targets":{"type":"array","items":{"type":"string"}},"headless":{"type":"boolean"},"ports":{"type":"string"},"method":{"type":"string"},"target_plan_digest":{"type":"string"}}}`), OutputSchema: json.RawMessage(`{"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}},"authorized":{"type":"array"},"filtered":{"type":"array"},"warnings":{"type":"array"}}}`), RequiredScopeType: p.def.ScopeType, ApprovalRequired: p.def.Risk == policy.Moderate || p.def.Risk == policy.High, RetrySafe: p.def.RetrySafe, Idempotent: p.def.Idempotent, SupportedProviders: []string{p.def.Provider}, ProducedArtifactTypes: []string{"raw-provider-output", "normalized-json"}, RequiredSecrets: p.def.RequiredSecrets, DefaultTimeout: p.def.Timeout}
}
func (p *Provider) ValidateDefinition(raw json.RawMessage) error {
	var in Input
	return strict(raw, &in)
}
func (p *Provider) Validate(_ context.Context, req capability.Request) error {
	var in Input
	if err := strict(req.Action.Input, &in); err != nil {
		return fmt.Errorf("%s input: %w", p.def.Name, err)
	}
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	if len(domains) == 0 && len(in.Targets) == 0 {
		return fmt.Errorf("domains or targets are required")
	}
	if req.Scope == nil {
		return fmt.Errorf("validated scope is required")
	}
	if req.Policy.MaximumPayloadSize > 0 && int64(len(req.Action.Input)) > req.Policy.MaximumPayloadSize {
		return fmt.Errorf("input exceeds policy maximum payload size")
	}
	if in.Headless && !req.Policy.HeadlessBrowser {
		return fmt.Errorf("headless browser use is denied by policy")
	}
	if in.Method != "" {
		if err := policy.ValidateHTTPMethod(req.Policy, in.Method); err != nil {
			return err
		}
	}
	if len(domains) > 0 && !p.def.PassiveInput {
		return fmt.Errorf("bare domains are permitted only for passive discovery providers")
	}
	for _, root := range domains {
		if err := validatePassiveRoot(root); err != nil {
			return fmt.Errorf("discovery root %q: %w", root, err)
		}
	}
	for _, target := range in.Targets {
		if !strings.Contains(target, "://") {
			return fmt.Errorf("active target %q must be an authorized URL with explicit protocol", target)
		}
		if !req.Scope.Allows(target) {
			return fmt.Errorf("target %q is outside authorized scope", target)
		}
	}
	_, err := p.def.invocation(in, req.Policy)
	return err
}
func (p *Provider) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	var in Input
	if err := json.Unmarshal(req.Action.Input, &in); err != nil {
		return capability.Result{}, err
	}
	invocation, err := p.def.invocation(in, req.Policy)
	if err != nil {
		return capability.Result{}, err
	}
	timeout := p.def.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now().UTC()
	versionCtx, versionCancel := context.WithTimeout(runCtx, 5*time.Second)
	versionArgs := p.def.Probe.VersionArgs
	if len(versionArgs) == 0 {
		versionArgs = []string{"-version"}
	}
	version, versionErr := p.runner.Version(versionCtx, p.def.Executable, versionArgs)
	versionCancel()
	if p.def.Probe.Name != "" {
		versionResult := providercheck.EvaluateExecutable(p.def.Probe, p.def.Executable, version, versionErr)
		if versionResult.Status != providercheck.Compatible {
			return p.versionFailure(req, in, invocation, started, versionResult, versionErr)
		}
	}
	stdout, stderr, exit, runErr := p.runner.Run(runCtx, p.def.Executable, invocation.Args, invocation.Stdin)
	completed := time.Now().UTC()
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	safeArgs, _ := json.Marshal(map[string]any{"provider": p.def.Provider, "target_count": len(in.Targets), "discovery_root_count": len(domains), "stdin_bytes": len(invocation.Stdin), "headless": in.Headless, "target_plan_digest": in.PlanDigest})
	safeStdout := p.redactor.Text(string(stdout))
	safeStderr := p.redactor.Text(string(stderr))
	lines := splitLines(safeStdout)
	normalized := map[string]any{"lines": lines, "authorized": lines, "filtered": []any{}, "warnings": []any{}, "accepted_count": len(lines), "filtered_count": 0}
	if p.def.OutputAdapter != "" {
		detailed, ok := req.Scope.(targeting.DetailedScope)
		if !ok {
			return capability.Result{}, fmt.Errorf("provider %s requires detailed scope evaluation", p.def.Provider)
		}
		batch := provideroutput.Parse(p.def.OutputAdapter, lines)
		accepted, authorizedURLs, filtered := filterRecords(detailed, batch.Records)
		normalized = map[string]any{"lines": accepted, "authorized": accepted, "authorized_urls": authorizedURLs, "filtered": filtered, "records": batch.Records, "warnings": batch.Warnings, "accepted_count": len(accepted), "filtered_count": len(filtered)}
		lines = accepted
	}
	output, _ := json.Marshal(normalized)
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: p.def.Name, Provider: p.def.Provider, ToolVersion: p.redactor.Text(version), SanitizedArguments: safeArgs, ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: started, CompletedAt: &completed, ExitCode: &exit, TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded)}
	result := capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: fmt.Sprintf("%s accepted %d normalized records", p.def.Provider, len(lines)), Output: output}, ToolRun: tool, RawStdout: []byte(safeStdout), RawStderr: []byte(safeStderr)}
	if runErr != nil {
		diagnostic := diagnosticSnippet(safeStderr, 3072)
		message := diagnosticSnippet(p.redactor.Text(runErr.Error()), 512)
		if message == "" {
			message = "provider execution failed"
		}
		if diagnostic != "" {
			message += ": " + diagnostic
		}
		result.Action.Status = "failed"
		result.Action.Summary = fmt.Sprintf("%s execution failed", p.def.Provider)
		result.Action.Error = &domain.StructuredError{Classification: classify(runErr, runCtx), Message: message, Retryable: exit < 0 || runCtx.Err() != nil}
		return result, &safeExecutionError{cause: runErr, message: message}
	}
	return result, nil
}

func (p *Provider) versionFailure(req capability.Request, in Input, invocation Invocation, started time.Time, check providercheck.Result, versionErr error) (capability.Result, error) {
	completed := time.Now().UTC()
	exit := -1
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	safeArgs, _ := json.Marshal(map[string]any{"provider": p.def.Provider, "target_count": len(in.Targets), "discovery_root_count": len(domains), "stdin_bytes": len(invocation.Stdin), "headless": in.Headless, "target_plan_digest": in.PlanDigest})
	detail := diagnosticSnippet(p.redactor.Text(check.Details), 1024)
	message := fmt.Sprintf("%s executable verification failed (%s): expected %s; configure %s with its full path", p.def.Provider, check.Status, check.ExpectedVersion, p.def.Probe.ExecutableEnv)
	if detail != "" {
		message += ": " + detail
	}
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: p.def.Name, Provider: p.def.Provider, ToolVersion: detail, SanitizedArguments: safeArgs, ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: started, CompletedAt: &completed, ExitCode: &exit}
	result := capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Summary: fmt.Sprintf("%s executable verification failed", p.def.Provider), Error: &domain.StructuredError{Classification: "provider_unavailable", Message: message, Retryable: false}}, ToolRun: tool, RawStderr: []byte(detail)}
	return result, &safeExecutionError{cause: versionErr, message: message}
}

type safeExecutionError struct {
	cause   error
	message string
}

func (e *safeExecutionError) Error() string { return e.message }
func (e *safeExecutionError) Unwrap() error { return e.cause }

func (d Definition) invocation(in Input, p policy.Policy) (Invocation, error) {
	if d.BuildInvocation != nil {
		return d.BuildInvocation(in, p)
	}
	if d.BuildArgs == nil {
		return Invocation{}, fmt.Errorf("provider invocation builder is required")
	}
	args, err := d.BuildArgs(in, p)
	return Invocation{Args: args}, err
}
func strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func splitLines(s string) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
func classify(err error, ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	var e *exec.Error
	if errors.As(err, &e) {
		return "provider_unavailable"
	}
	return "provider_error"
}
func diagnosticSnippet(value string, limit int) string {
	if limit < 1 {
		return ""
	}
	var out strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			r = ' '
		}
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1
		}
		if out.Len()+size > limit {
			break
		}
		out.WriteRune(r)
	}
	return strings.Join(strings.Fields(out.String()), " ")
}
func validatePassiveRoot(raw string) error {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if net.ParseIP(host) != nil {
		return nil
	}
	if host == "" || strings.ContainsAny(host, " /:@") {
		return fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("invalid hostname")
		}
	}
	return nil
}

func filterRecords(sc targeting.DetailedScope, records []provideroutput.Record) ([]string, []string, []targeting.FilterDecision) {
	accepted := []string{}
	authorizedURLs := []string{}
	filtered := []targeting.FilterDecision{}
	for _, record := range records {
		switch record.Kind {
		case provideroutput.HostRecord:
			r := targeting.FilterDiscoveredHosts(sc, []string{record.Host})
			if len(r.Authorized) > 0 {
				accepted = append(accepted, r.Authorized...)
				authorizedURLs = append(authorizedURLs, r.AuthorizedURLs...)
			} else {
				filtered = append(filtered, r.Filtered...)
			}
		case provideroutput.URLRecord:
			r := targeting.FilterURLs(sc, []string{record.Target})
			if len(r.Authorized) > 0 {
				accepted = append(accepted, r.Authorized...)
				authorizedURLs = append(authorizedURLs, r.AuthorizedURLs...)
			} else {
				filtered = append(filtered, r.Filtered...)
			}
		case provideroutput.PortRecord:
			r := targeting.FilterDiscoveredHosts(sc, []string{record.Host})
			matched := false
			for _, raw := range r.AuthorizedURLs {
				u, err := url.Parse(raw)
				if err != nil {
					continue
				}
				port := u.Port()
				if port == "" {
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				value, _ := strconv.Atoi(port)
				if value == record.Port {
					matched = true
					accepted = append(accepted, record.Target)
					break
				}
			}
			if !matched {
				reason := "port_not_authorized"
				if len(r.Filtered) > 0 {
					reason = string(r.Filtered[0].Reason)
				}
				filtered = append(filtered, targeting.FilterDecision{Target: record.Target, Reason: scopeReason(reason)})
			}
		}
	}
	sort.Strings(accepted)
	accepted = dedupe(accepted)
	sort.Strings(authorizedURLs)
	authorizedURLs = dedupe(authorizedURLs)
	return accepted, authorizedURLs, filtered
}
func scopeReason(value string) platformscope.Reason { return platformscope.Reason(value) }
func dedupe(items []string) []string {
	if len(items) < 2 {
		return items
	}
	out := items[:1]
	for _, v := range items[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
