package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type Manifest struct {
	Name                  string              `json:"name"`
	Description           string              `json:"description"`
	Version               string              `json:"version"`
	Risk                  policy.Risk         `json:"risk"`
	InputSchema           json.RawMessage     `json:"input_schema"`
	OutputSchema          json.RawMessage     `json:"output_schema"`
	RequiredScopeType     string              `json:"required_scope_type"`
	ApprovalRequired      bool                `json:"approval_required"`
	RetrySafe             bool                `json:"retry_safe"`
	Idempotent            bool                `json:"idempotent"`
	SupportedProviders    []string            `json:"supported_providers"`
	ProducedArtifactTypes []string            `json:"produced_artifact_types"`
	RequiredSecrets       []string            `json:"required_secrets"`
	PolicyRequirements    policy.Requirements `json:"policy_requirements"`
	DefaultTimeout        time.Duration       `json:"default_timeout"`
}
type Request struct {
	Action           domain.ActionRequest   `json:"action"`
	ProgramID        domain.ID              `json:"program_id"`
	Provider         string                 `json:"provider"`
	Approved         bool                   `json:"approved"`
	Policy           policy.Policy          `json:"policy"`
	Scope            Scope                  `json:"scope"`
	PolicyPhase      string                 `json:"-"`
	DecisionRecorder PolicyDecisionRecorder `json:"-"`
}

type PolicyDecisionRecord struct {
	ProgramID    domain.ID            `json:"program_id"`
	Action       domain.ActionRequest `json:"action"`
	Provider     string               `json:"provider"`
	PolicyID     string               `json:"policy_id"`
	Phase        string               `json:"phase"`
	Requirements policy.Requirements  `json:"requirements"`
	Evaluation   policy.Evaluation    `json:"evaluation"`
}

type PolicyDecisionRecorder interface {
	RecordPolicyDecision(context.Context, PolicyDecisionRecord) error
}
type Result struct {
	Action    domain.ActionResult `json:"action"`
	ToolRun   *domain.ToolRun     `json:"tool_run,omitempty"`
	RawStdout []byte              `json:"-"`
	RawStderr []byte              `json:"-"`
}
type Scope interface{ Allows(string) bool }
type Capability interface {
	Manifest() Manifest
	Validate(context.Context, Request) error
	Execute(context.Context, Request) (Result, error)
}
type DefinitionValidator interface{ ValidateDefinition(json.RawMessage) error }
type Registry struct {
	items map[string]Capability
	now   func() time.Time
}

type Multi struct {
	manifest        Manifest
	defaultProvider string
	providers       map[string]Capability
}

func NewMulti(defaultProvider string, providers map[string]Capability) (*Multi, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one provider is required")
	}
	base, ok := providers[defaultProvider]
	if !ok {
		return nil, fmt.Errorf("default provider %q is not registered", defaultProvider)
	}
	m := base.Manifest()
	m.SupportedProviders = nil
	for name, p := range providers {
		providerManifest := p.Manifest()
		if providerManifest.Name != m.Name {
			return nil, fmt.Errorf("provider %s implements %s, expected %s", name, providerManifest.Name, m.Name)
		}
		m.PolicyRequirements = mergeRequirements(m.PolicyRequirements, providerManifest.PolicyRequirements)
		m.SupportedProviders = append(m.SupportedProviders, name)
	}
	sort.Strings(m.SupportedProviders)
	return &Multi{manifest: m, defaultProvider: defaultProvider, providers: providers}, nil
}

func mergeRequirements(a, b policy.Requirements) policy.Requirements {
	return policy.Requirements{Authentication: a.Authentication || b.Authentication, DirectoryFuzzing: a.DirectoryFuzzing || b.DirectoryFuzzing, CrossOrigin: a.CrossOrigin || b.CrossOrigin, IntrusiveChecks: a.IntrusiveChecks || b.IntrusiveChecks}
}
func (m *Multi) Manifest() Manifest { return m.manifest }
func (m *Multi) provider(name string) (Capability, error) {
	if name == "" {
		name = m.defaultProvider
	}
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q is not supported for %s", name, m.manifest.Name)
	}
	return p, nil
}
func (m *Multi) Validate(ctx context.Context, r Request) error {
	p, err := m.provider(r.Provider)
	if err != nil {
		return err
	}
	return p.Validate(ctx, r)
}
func (m *Multi) Execute(ctx context.Context, r Request) (Result, error) {
	p, err := m.provider(r.Provider)
	if err != nil {
		return Result{}, err
	}
	return p.Execute(ctx, r)
}
func (m *Multi) ValidateDefinition(raw json.RawMessage) error {
	p, err := m.provider(m.defaultProvider)
	if err != nil {
		return err
	}
	if v, ok := p.(DefinitionValidator); ok {
		return v.ValidateDefinition(raw)
	}
	return nil
}

func NewRegistry() *Registry { return &Registry{items: map[string]Capability{}, now: time.Now} }
func (r *Registry) Register(c Capability) error {
	m := c.Manifest()
	if m.Name == "" || m.Version == "" {
		return fmt.Errorf("capability name and version are required")
	}
	if _, ok := r.items[m.Name]; ok {
		return fmt.Errorf("capability %s already registered", m.Name)
	}
	r.items[m.Name] = c
	return nil
}
func (r *Registry) Get(name string) (Capability, bool) { c, ok := r.items[name]; return c, ok }
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.items))
	for n := range r.items {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func (r *Registry) Execute(ctx context.Context, req Request) (Result, error) {
	c, err := r.authorize(ctx, req)
	if err != nil {
		return Result{}, err
	}
	if err := c.Validate(ctx, req); err != nil {
		return Result{}, err
	}
	return c.Execute(ctx, req)
}

// Validate authorizes and validates an action without executing its provider.
func (r *Registry) Validate(ctx context.Context, req Request) error {
	c, err := r.authorize(ctx, req)
	if err != nil {
		return err
	}
	return c.Validate(ctx, req)
}

func (r *Registry) authorize(ctx context.Context, req Request) (Capability, error) {
	c, ok := r.Get(req.Action.Capability)
	if !ok {
		return nil, fmt.Errorf("unknown capability %q", req.Action.Capability)
	}
	manifest := c.Manifest()
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	eval := policy.EvaluateAt(req.Policy, manifest.Name, manifest.Risk, req.Approved, manifest.PolicyRequirements, req.Action.Input, now().UTC())
	phase := req.PolicyPhase
	if phase == "" {
		phase = "execution"
	}
	if req.DecisionRecorder != nil {
		record := PolicyDecisionRecord{ProgramID: req.ProgramID, Action: req.Action, Provider: req.Provider, PolicyID: req.Policy.ID, Phase: phase, Requirements: manifest.PolicyRequirements, Evaluation: eval}
		if err := req.DecisionRecorder.RecordPolicyDecision(ctx, record); err != nil {
			return nil, fmt.Errorf("persist policy decision: %w", err)
		}
	}
	if eval.Decision != policy.Allow {
		return nil, fmt.Errorf("policy %s: %s", eval.Decision, eval.Reason)
	}
	return c, nil
}
func (r *Registry) ValidateDefinitionInput(name string, raw json.RawMessage) error {
	c, ok := r.Get(name)
	if !ok {
		return fmt.Errorf("unknown capability %q", name)
	}
	if v, ok := c.(DefinitionValidator); ok {
		return v.ValidateDefinition(raw)
	}
	return nil
}
