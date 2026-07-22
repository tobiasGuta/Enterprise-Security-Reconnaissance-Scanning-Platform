package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type testCap struct {
	name     string
	calls    *int
	failOnce bool
}

func (c testCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: c.name, Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (c testCap) Validate(context.Context, capability.Request) error { return nil }
func (c testCap) Execute(_ context.Context, r capability.Request) (capability.Result, error) {
	*c.calls++
	if c.failOnce && *c.calls == 1 {
		return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Error: &domain.StructuredError{Retryable: true}}}, errors.New("temporary")
	}
	return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Status: "succeeded", Summary: "ok", Output: json.RawMessage(`{"lines":["https://example.test"]}`)}}, nil
}

type allScope struct{}

func (allScope) Allows(string) bool { return true }

type memoryPersist struct {
	mu    sync.Mutex
	saves int
}

func (p *memoryPersist) Save(context.Context, *State) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	return nil
}
func registryFor(t *testing.T, capabilityImpl capability.Capability) *capability.Registry {
	t.Helper()
	r := capability.NewRegistry()
	if err := r.Register(capabilityImpl); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestDependencyValidation(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	base := Definition{Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`)}}}
	if err := Validate(base, r); err != nil {
		t.Fatal(err)
	}
	cyclic := base
	cyclic.Steps = []Step{{ID: "a", Capability: "x", DependsOn: []string{"b"}, Input: json.RawMessage(`{}`)}, {ID: "b", Capability: "x", DependsOn: []string{"a"}, Input: json.RawMessage(`{}`)}}
	if err := Validate(cyclic, r); err == nil {
		t.Fatal("cycle accepted")
	}
	shell := base
	shell.Steps[0].Capability = "shell"
	if err := Validate(shell, r); err == nil {
		t.Fatal("unknown shell capability accepted")
	}
}
func TestRetryIdempotencyAndResume(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, true})
	persist := &memoryPersist{}
	engine := Engine{Registry: r, Executor: r, Persister: persist, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{"target":"x"}`), Retry: RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}}
	task := domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID, RequestedBy: "cli"}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
	key := state.Steps["a"].Run.IdempotencyKey
	state, err = engine.Run(context.Background(), def, state, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("successful step reran after resume")
	}
	if state.Steps["a"].Run.IdempotencyKey != key {
		t.Fatal("idempotency key changed")
	}
	if persist.saves < 3 {
		t.Fatal("state was not persisted across transitions")
	}
}
func TestApprovalPause(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	engine := Engine{Registry: r, Executor: r, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", ApprovalRequired: true, Input: json.RawMessage(`{}`)}}}
	state, err := engine.Run(context.Background(), def, nil, domain.Task{ID: domain.NewID()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunPaused || state.Steps["a"].Run.Status != domain.StepAwaitingApproval || calls != 0 {
		t.Fatalf("unexpected state: %#v", state)
	}
}
func TestResumeAfterFileBackedRestart(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	store := FileStore{Root: t.TempDir()}
	engine := Engine{Registry: r, Executor: r, Persister: store, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`)}}}
	task := domain.Task{ID: domain.NewID()}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(string(state.Run.ID))
	if err != nil {
		t.Fatal(err)
	}
	restarted := Engine{Registry: r, Executor: r, Persister: store, Policy: engine.Policy, Scope: allScope{}}
	if _, err := restarted.Run(context.Background(), def, loaded, task, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("restart reran completed work; calls=%d", calls)
	}
}

type namedCap string

func (c namedCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: string(c), Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (c namedCap) Validate(context.Context, capability.Request) error { return nil }
func (c namedCap) Execute(context.Context, capability.Request) (capability.Result, error) {
	panic("workflow test executor should be used")
}

type dnsFailureExecutor struct {
	calls      map[string]int
	dnsTargets []string
}

func (e *dnsFailureExecutor) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	e.calls[req.Action.Capability]++
	if req.Action.Capability == "resolve.dns" {
		var input struct {
			Targets []string `json:"targets"`
		}
		if err := json.Unmarshal(req.Action.Input, &input); err != nil {
			return capability.Result{}, err
		}
		e.dnsTargets = append([]string(nil), input.Targets...)
		return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Error: &domain.StructuredError{Classification: "provider_error", Message: "mock dns failure"}}}, errors.New("mock dns failure")
	}
	output := json.RawMessage(`{"lines":["https://authorized.example.test/"],"authorized_urls":["https://authorized.example.test/"]}`)
	if req.Action.Capability == "targeting.prepare" {
		output = json.RawMessage(`{"urls":["https://authorized.example.test/"]}`)
	}
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "ok", Output: output}}, nil
}

func TestResumeAfterDNSFailureRetainsSuccessfulScopePreparation(t *testing.T) {
	registry := capability.NewRegistry()
	for _, name := range []string{"discover.subdomains", "targeting.prepare", "resolve.dns"} {
		if err := registry.Register(namedCap(name)); err != nil {
			t.Fatal(err)
		}
	}
	executor := &dnsFailureExecutor{calls: map[string]int{}}
	engine := Engine{Registry: registry, Executor: executor, Policy: policy.Policy{AllowedCapabilities: registry.Names()}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "dns-failure", Version: "1", Steps: []Step{
		{ID: "discover", Capability: "discover.subdomains", Input: json.RawMessage(`{}`)},
		{ID: "prepare", Capability: "targeting.prepare", DependsOn: []string{"discover"}, Input: json.RawMessage(`{}`)},
		{ID: "dns", Capability: "resolve.dns", DependsOn: []string{"prepare"}, Input: json.RawMessage(`{"targets":[]}`), Bindings: map[string]string{"targets": "prepare.output.urls"}, Retry: RetryPolicy{MaxAttempts: 1}},
	}}
	task := domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID, RequestedBy: "test"}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err == nil {
		t.Fatal("expected DNS failure")
	}
	if state.Steps["discover"].Run.Status != domain.StepSucceeded || state.Steps["prepare"].Run.Status != domain.StepSucceeded || state.Steps["dns"].Run.Status != domain.StepFailed {
		t.Fatalf("unexpected state: %#v", state.Steps)
	}
	dnsStepRunID := state.Steps["dns"].Run.ID
	state, err = engine.Run(context.Background(), def, state, task, nil)
	if err == nil {
		t.Fatal("expected retry DNS failure")
	}
	if executor.calls["discover.subdomains"] != 1 || executor.calls["targeting.prepare"] != 1 || executor.calls["resolve.dns"] != 2 {
		t.Fatalf("unexpected resume calls: %#v", executor.calls)
	}
	if state.Steps["dns"].Run.ID != dnsStepRunID {
		t.Fatalf("unchanged failed DNS input created a duplicate step run: before=%s after=%s", dnsStepRunID, state.Steps["dns"].Run.ID)
	}
	if len(executor.dnsTargets) != 1 || executor.dnsTargets[0] != "https://authorized.example.test/" {
		t.Fatalf("DNS step did not receive prepared authorized targets: %#v", executor.dnsTargets)
	}
}
