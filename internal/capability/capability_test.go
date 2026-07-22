package capability

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type guardedCapability struct {
	manifest Manifest
	called   bool
}

func (c *guardedCapability) Manifest() Manifest { return c.manifest }
func (c *guardedCapability) Validate(context.Context, Request) error {
	c.called = true
	return nil
}
func (c *guardedCapability) Execute(context.Context, Request) (Result, error) {
	c.called = true
	return Result{}, nil
}

type capturedDecision struct {
	records []PolicyDecisionRecord
	err     error
}

func (c *capturedDecision) RecordPolicyDecision(_ context.Context, record PolicyDecisionRecord) error {
	c.records = append(c.records, record)
	return c.err
}

func TestModeledPolicyRestrictionsDenyBeforeProviderAndAreAudited(t *testing.T) {
	tests := []struct {
		name         string
		requirements policy.Requirements
		configure    func(*policy.Policy)
		reason       string
	}{
		{"authentication", policy.Requirements{Authentication: true}, nil, "authentication usage"},
		{"directory fuzzing", policy.Requirements{DirectoryFuzzing: true}, nil, "directory fuzzing"},
		{"cross origin", policy.Requirements{CrossOrigin: true}, nil, "cross-origin"},
		{"intrusive checks", policy.Requirements{IntrusiveChecks: true}, nil, "intrusive checks"},
		{"scan window", policy.Requirements{}, func(p *policy.Policy) { p.ScanWindows = []string{"Mon 09:00-10:00 UTC"} }, "outside configured scan windows"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low, PolicyRequirements: test.requirements}}
			registry := NewRegistry()
			registry.now = func() time.Time { return time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC) }
			if err := registry.Register(implementation); err != nil {
				t.Fatal(err)
			}
			configured := policy.Policy{ID: "restricted", AllowedCapabilities: []string{"guarded"}}
			if test.configure != nil {
				test.configure(&configured)
			}
			audit := &capturedDecision{}
			_, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: configured, Scope: allowAllScope{}, DecisionRecorder: audit})
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("error=%v", err)
			}
			if implementation.called {
				t.Fatal("provider validation or execution was reached")
			}
			if len(audit.records) != 1 || audit.records[0].Evaluation.Decision != policy.Deny || !strings.Contains(audit.records[0].Evaluation.Reason, test.reason) {
				t.Fatalf("audit=%#v", audit.records)
			}
		})
	}
}

func TestPolicyAuditFailureFailsClosedBeforeProvider(t *testing.T) {
	implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low}}
	registry := NewRegistry()
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	audit := &capturedDecision{err: errors.New("audit unavailable")}
	_, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"guarded"}}, Scope: allowAllScope{}, DecisionRecorder: audit})
	if err == nil || implementation.called {
		t.Fatalf("error=%v provider_called=%v", err, implementation.called)
	}
}

func TestExplicitPolicyPermissionsAllowDeclaredBehavior(t *testing.T) {
	requirements := policy.Requirements{Authentication: true, DirectoryFuzzing: true, CrossOrigin: true, IntrusiveChecks: true}
	implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low, PolicyRequirements: requirements}}
	registry := NewRegistry()
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	audit := &capturedDecision{}
	configured := policy.Policy{AllowedCapabilities: []string{"guarded"}, AuthenticationUsage: true, DirectoryFuzzing: true, CrossOrigin: true, IntrusiveChecks: true}
	if _, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: configured, Scope: allowAllScope{}, DecisionRecorder: audit}); err != nil {
		t.Fatal(err)
	}
	if !implementation.called || len(audit.records) != 1 || audit.records[0].Evaluation.Decision != policy.Allow {
		t.Fatalf("provider_called=%v audit=%#v", implementation.called, audit.records)
	}
}

type allowAllScope struct{}

func (allowAllScope) Allows(string) bool { return true }
