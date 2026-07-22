package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type Definition struct {
	ID                        domain.ID       `json:"id"`
	Name                      string          `json:"name"`
	Version                   string          `json:"version"`
	Description               string          `json:"description"`
	Steps                     []Step          `json:"steps"`
	DefaultPolicyRequirements json.RawMessage `json:"default_policy_requirements"`
	CreatedAt                 time.Time       `json:"created_at"`
}
type Step struct {
	ID                 string            `json:"id"`
	Capability         string            `json:"capability"`
	Provider           string            `json:"provider,omitempty"`
	DependsOn          []string          `json:"depends_on,omitempty"`
	Condition          string            `json:"condition,omitempty"`
	Input              json.RawMessage   `json:"input"`
	Bindings           map[string]string `json:"bindings,omitempty"`
	Retry              RetryPolicy       `json:"retry"`
	Timeout            time.Duration     `json:"timeout"`
	ApprovalRequired   bool              `json:"approval_required,omitempty"`
	RerunOnInputChange bool              `json:"rerun_on_input_change,omitempty"`
}
type RetryPolicy struct {
	MaxAttempts int           `json:"max_attempts"`
	BaseDelay   time.Duration `json:"base_delay"`
}
type StepState struct {
	Run       domain.StepRun `json:"run"`
	InputHash string         `json:"input_hash"`
}
type State struct {
	Run    domain.WorkflowRun    `json:"run"`
	Steps  map[string]*StepState `json:"steps"`
	Events []Event               `json:"events"`
}
type Event struct {
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	StepID  string    `json:"step_id,omitempty"`
	Message string    `json:"message"`
}
type Executor interface {
	Execute(context.Context, capability.Request) (capability.Result, error)
}
type Persister interface {
	Save(context.Context, *State) error
}
type ApprovalFunc func(context.Context, Step, policy.Risk) (bool, error)
type Controls struct {
	mu                sync.RWMutex
	paused, cancelled bool
}

func (c *Controls) Pause()  { c.mu.Lock(); defer c.mu.Unlock(); c.paused = true }
func (c *Controls) Resume() { c.mu.Lock(); defer c.mu.Unlock(); c.paused = false }
func (c *Controls) Cancel() { c.mu.Lock(); defer c.mu.Unlock(); c.cancelled = true }
func (c *Controls) state() (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.paused, c.cancelled
}

type Engine struct {
	Registry  *capability.Registry
	Executor  Executor
	Persister Persister
	Approval  ApprovalFunc
	Policy    policy.Policy
	Scope     capability.Scope
}

func Validate(d Definition, r *capability.Registry) error {
	if d.Name == "" || d.Version == "" {
		return fmt.Errorf("workflow name and version are required")
	}
	byID := map[string]Step{}
	for _, s := range d.Steps {
		if s.ID == "" {
			return fmt.Errorf("step id is required")
		}
		if _, ok := byID[s.ID]; ok {
			return fmt.Errorf("duplicate step %q", s.ID)
		}
		if _, ok := r.Get(s.Capability); !ok {
			return fmt.Errorf("step %s uses unknown capability %q", s.ID, s.Capability)
		}
		if len(s.Input) == 0 || !json.Valid(s.Input) {
			return fmt.Errorf("step %s has invalid input JSON", s.ID)
		}
		if err := r.ValidateDefinitionInput(s.Capability, s.Input); err != nil {
			return fmt.Errorf("step %s input schema: %w", s.ID, err)
		}
		if s.Condition != "" && !strings.HasPrefix(s.Condition, "success:") && !strings.HasPrefix(s.Condition, "changed:") && !strings.HasPrefix(s.Condition, "nonempty:") {
			return fmt.Errorf("step %s has unsupported condition %q", s.ID, s.Condition)
		}
		byID[s.ID] = s
	}
	for _, s := range d.Steps {
		for _, dep := range s.DependsOn {
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("step %s depends on unknown step %s", s.ID, dep)
			}
		}
		for _, binding := range s.Bindings {
			parts := strings.Split(binding, ".")
			if len(parts) < 3 || parts[1] != "output" {
				return fmt.Errorf("step %s has unsupported binding %q", s.ID, binding)
			}
			if _, ok := byID[parts[0]]; !ok {
				return fmt.Errorf("step %s binding references unknown step %s", s.ID, parts[0])
			}
		}
		if s.Condition != "" {
			_, reference, _ := strings.Cut(s.Condition, ":")
			source := strings.Split(reference, ".")[0]
			if _, ok := byID[source]; !ok {
				return fmt.Errorf("step %s condition references unknown step %s", s.ID, source)
			}
		}
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("cyclic dependency at step %s", id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dep := range byID[id].DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) Run(ctx context.Context, d Definition, state *State, task domain.Task, controls *Controls) (*State, error) {
	if err := Validate(d, e.Registry); err != nil {
		return nil, err
	}
	if e.Executor == nil {
		e.Executor = e.Registry
	}
	if controls == nil {
		controls = &Controls{}
	}
	now := time.Now().UTC()
	if state == nil {
		state = &State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, WorkflowDefinitionID: d.ID, WorkflowVersion: d.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: task.RequestedBy, Summary: json.RawMessage(`{}`)}, Steps: map[string]*StepState{}}
		state.Events = append(state.Events, Event{now, "workflow_started", "", "workflow execution started"})
	} else {
		state.Run.Status = domain.RunRunning
		state.Events = append(state.Events, Event{now, "workflow_resumed", "", "workflow execution resumed"})
	}
	if err := e.save(ctx, state); err != nil {
		return state, err
	}
	ordered := topological(d)
	for _, step := range ordered {
		paused, cancelled := controls.state()
		if cancelled {
			return e.terminal(ctx, state, domain.RunCancelled, "workflow_cancelled")
		}
		if paused {
			state.Run.Status = domain.RunPaused
			e.event(state, "workflow_paused", step.ID, "pause requested")
			_ = e.save(ctx, state)
			return state, nil
		}
		input, err := resolveInput(step, state)
		if err != nil {
			return e.fail(ctx, state, step.ID, "input_resolution", err)
		}
		hash := inputHash(input)
		if existing := state.Steps[step.ID]; existing != nil && existing.Run.Status == domain.StepSucceeded && (!step.RerunOnInputChange || existing.InputHash == hash) {
			e.event(state, "step_resumed", step.ID, "previous successful result retained")
			continue
		}
		if !dependenciesSucceeded(step, state) {
			return e.fail(ctx, state, step.ID, "dependency", errors.New("dependency did not succeed"))
		}
		if !condition(step.Condition, state) {
			state.Steps[step.ID] = transitionStep(state, step, input, hash, domain.StepSkipped)
			e.event(state, "step_skipped", step.ID, "condition was false")
			if err := e.save(ctx, state); err != nil {
				return state, err
			}
			continue
		}
		capabilityImpl, _ := e.Registry.Get(step.Capability)
		approved := false
		if step.ApprovalRequired || capabilityImpl.Manifest().ApprovalRequired {
			if e.Approval == nil {
				ss := transitionStep(state, step, input, hash, domain.StepAwaitingApproval)
				ss.Run.ApprovalState = "pending"
				state.Steps[step.ID] = ss
				state.Run.Status = domain.RunPaused
				e.event(state, "approval_required", step.ID, "approval is required before execution")
				_ = e.save(ctx, state)
				return state, nil
			}
			approved, err = e.Approval(ctx, step, capabilityImpl.Manifest().Risk)
			if err != nil {
				return e.fail(ctx, state, step.ID, "approval", err)
			}
			if !approved {
				return e.fail(ctx, state, step.ID, "approval_rejected", errors.New("approval rejected"))
			}
		}
		ss := transitionStep(state, step, input, hash, domain.StepRunning)
		ss.Run.ApprovalState = map[bool]string{true: "approved", false: "not_required"}[approved]
		state.Steps[step.ID] = ss
		e.event(state, "step_started", step.ID, "capability execution started")
		if err := e.save(ctx, state); err != nil {
			return state, err
		}
		max := step.Retry.MaxAttempts
		if max < 1 {
			max = 1
		}
		var result capability.Result
		for attempt := 1; attempt <= max; attempt++ {
			ss.Run.AttemptCount = attempt
			action := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: state.Run.ID, StepRunID: ss.Run.ID, RequestedBy: "workflow", Capability: step.Capability, Reason: "deterministic workflow step " + step.ID, Input: input, IdempotencyKey: ss.Run.IdempotencyKey}
			runCtx := ctx
			cancel := func() {}
			if step.Timeout > 0 {
				runCtx, cancel = context.WithTimeout(ctx, step.Timeout)
			}
			result, err = e.Executor.Execute(runCtx, capability.Request{Action: action, Provider: step.Provider, Approved: approved, Policy: e.Policy, Scope: e.Scope})
			cancel()
			if err == nil {
				break
			}
			if result.Action.Error == nil || !result.Action.Error.Retryable || attempt == max {
				break
			}
			delay := step.Retry.BaseDelay
			if delay <= 0 {
				delay = time.Second
			}
			timer := time.NewTimer(delay * time.Duration(1<<(attempt-1)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return e.fail(ctx, state, step.ID, "cancelled", ctx.Err())
			case <-timer.C:
			}
		}
		done := time.Now().UTC()
		ss.Run.CompletedAt = &done
		if err != nil {
			ss.Run.Status = domain.StepFailed
			ss.Run.ErrorClassification = "execution"
			ss.Run.ErrorDetails = err.Error()
			e.event(state, "step_failed", step.ID, err.Error())
			_ = e.save(ctx, state)
			return e.fail(ctx, state, step.ID, "execution", err)
		}
		ss.Run.Status = domain.StepSucceeded
		ss.Run.Output = result.Action.Output
		if step.Capability == "report.changes" && len(result.Action.Output) > 0 {
			state.Run.Summary = append(json.RawMessage(nil), result.Action.Output...)
		}
		e.event(state, "step_succeeded", step.ID, result.Action.Summary)
		if err := e.save(ctx, state); err != nil {
			return state, err
		}
	}
	return e.terminal(ctx, state, domain.RunCompleted, "workflow_completed")
}
func (e *Engine) save(ctx context.Context, s *State) error {
	if e.Persister != nil {
		return e.Persister.Save(ctx, s)
	}
	return nil
}
func (e *Engine) event(s *State, t, step, msg string) {
	s.Events = append(s.Events, Event{time.Now().UTC(), t, step, msg})
}
func (e *Engine) terminal(ctx context.Context, s *State, status domain.RunStatus, event string) (*State, error) {
	now := time.Now().UTC()
	s.Run.Status = status
	s.Run.CompletedAt = &now
	e.event(s, event, "", string(status))
	return s, e.save(ctx, s)
}
func (e *Engine) fail(ctx context.Context, s *State, step, class string, err error) (*State, error) {
	s.Run.Status = domain.RunFailed
	e.event(s, "workflow_failed", step, class+": "+err.Error())
	_ = e.save(ctx, s)
	return s, err
}
func newStep(state *State, s Step, input json.RawMessage, hash string, status domain.StepStatus) *StepState {
	keySum := sha256.Sum256([]byte(string(state.Run.ID) + "\x00" + s.ID + "\x00" + hash))
	return &StepState{Run: domain.StepRun{ID: domain.NewID(), WorkflowRunID: state.Run.ID, StepDefinitionID: s.ID, Capability: s.Capability, Status: status, Input: input, IdempotencyKey: hex.EncodeToString(keySum[:]), ApprovalState: "not_required"}, InputHash: hash}
}

func transitionStep(state *State, s Step, input json.RawMessage, hash string, status domain.StepStatus) *StepState {
	next := newStep(state, s, input, hash, status)
	if previous := state.Steps[s.ID]; previous != nil && previous.Run.IdempotencyKey == next.Run.IdempotencyKey {
		next.Run.ID = previous.Run.ID
	}
	return next
}

func inputHash(in []byte) string { sum := sha256.Sum256(in); return hex.EncodeToString(sum[:]) }
func dependenciesSucceeded(s Step, state *State) bool {
	for _, d := range s.DependsOn {
		run := state.Steps[d]
		if run == nil || (run.Run.Status != domain.StepSucceeded && run.Run.Status != domain.StepSkipped) {
			return false
		}
	}
	return true
}
func condition(expr string, state *State) bool {
	if expr == "" {
		return true
	}
	kind, reference, _ := strings.Cut(expr, ":")
	id := strings.Split(reference, ".")[0]
	s := state.Steps[id]
	if s == nil {
		return false
	}
	if kind == "success" {
		return s.Run.Status == domain.StepSucceeded
	}
	if kind == "changed" {
		var v map[string]any
		if json.Unmarshal(s.Run.Output, &v) != nil {
			return false
		}
		changes, ok := v["changes"].([]any)
		return ok && len(changes) > 0
	}
	if kind == "nonempty" {
		parts := strings.Split(reference, ".")
		var value any
		if json.Unmarshal(s.Run.Output, &value) != nil {
			return false
		}
		for _, part := range parts[2:] {
			m, ok := value.(map[string]any)
			if !ok {
				return false
			}
			value, ok = m[part]
			if !ok {
				return false
			}
		}
		switch v := value.(type) {
		case []any:
			return len(v) > 0
		case string:
			return v != ""
		default:
			return v != nil
		}
	}
	return false
}
func resolveInput(s Step, state *State) (json.RawMessage, error) {
	var target map[string]any
	if err := json.Unmarshal(s.Input, &target); err != nil {
		return nil, err
	}
	for field, binding := range s.Bindings {
		parts := strings.Split(binding, ".")
		source := state.Steps[parts[0]]
		if source == nil {
			return nil, fmt.Errorf("binding source %s has no state", parts[0])
		}
		if len(source.Run.Output) == 0 && source.Run.Status == domain.StepSkipped {
			continue
		}
		var value any
		if err := json.Unmarshal(source.Run.Output, &value); err != nil {
			return nil, err
		}
		for _, part := range parts[2:] {
			if strings.HasSuffix(part, "[]") {
				part = strings.TrimSuffix(part, "[]")
				m, ok := value.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("binding %s is not an object", binding)
				}
				arr, ok := m[part].([]any)
				if !ok {
					return nil, fmt.Errorf("binding %s is not an array", binding)
				}
				value = arr
				continue
			}
			if arr, ok := value.([]any); ok {
				extracted := make([]any, 0, len(arr))
				for _, item := range arr {
					if raw, ok := item.(string); ok {
						var parsed map[string]any
						if json.Unmarshal([]byte(raw), &parsed) == nil {
							if v, ok := parsed[part]; ok {
								extracted = append(extracted, v)
								continue
							}
						}
					}
					if m, ok := item.(map[string]any); ok {
						if v, ok := m[part]; ok {
							extracted = append(extracted, v)
						}
					}
				}
				value = extracted
				continue
			}
			m, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("binding %s is not an object", binding)
			}
			value, ok = m[part]
			if !ok {
				return nil, fmt.Errorf("binding %s not found", binding)
			}
		}
		target[field] = value
	}
	return json.Marshal(target)
}
func topological(d Definition) []Step {
	byID := map[string]Step{}
	for _, s := range d.Steps {
		byID[s.ID] = s
	}
	seen := map[string]bool{}
	out := make([]Step, 0, len(d.Steps))
	var add func(string)
	add = func(id string) {
		if seen[id] {
			return
		}
		deps := append([]string(nil), byID[id].DependsOn...)
		sort.Strings(deps)
		for _, dep := range deps {
			add(dep)
		}
		seen[id] = true
		out = append(out, byID[id])
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		add(id)
	}
	return out
}

type RegistryExecutor struct{ Registry *capability.Registry }

func (r RegistryExecutor) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	return r.Registry.Execute(ctx, req)
}
