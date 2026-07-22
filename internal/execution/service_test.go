package execution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

var errFakeExit = errors.New("exit status 1")

type failingRunner struct{}

func (failingRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	return []byte(`{"partial":true}` + "\n"), []byte("password=sensitive-test-value\nresolver configuration failed\n"), 1, errFakeExit
}
func (failingRunner) Version(context.Context, string, []string) (string, error) { return "test-1", nil }

type capturedStore struct {
	called    bool
	step      domain.StepRun
	tool      *domain.ToolRun
	artifacts []domain.Artifact
	result    domain.ActionResult
	err       error
}

func (*capturedStore) PreviousObservationValues(context.Context, domain.ID, domain.ID, string) ([]string, error) {
	return nil, nil
}
func (s *capturedStore) PersistResult(_ context.Context, _ domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult) error {
	s.called, s.step, s.tool, s.artifacts, s.result = true, step, tool, append([]domain.Artifact(nil), artifacts...), result
	return s.err
}

func TestFailedProviderAndPersistenceErrorsAreBothPreserved(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{Name: "probe.http", Provider: "fake-httpx", Executable: "fake-httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return []string{"-u", i.Targets[0]}, nil
	}}, failingRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	persistCause := errors.New("database unavailable")
	store := &capturedStore{err: persistCause}
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowedScope{}}
	_, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, errFakeExit) || !errors.Is(err, persistCause) {
		t.Fatalf("execution and persistence causes were not preserved: %v", err)
	}
}

type capturedArtifacts struct{ requests []artifact.PutRequest }

func (s *capturedArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	s.requests = append(s.requests, req)
	return domain.Artifact{ID: domain.NewID(), TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), CreatedAt: time.Now().UTC()}, nil
}

type allowedScope struct{}

func (allowedScope) Allows(string) bool { return true }

func TestFailedProviderAttemptPersistsToolStepArtifactsAndOriginalError(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{Name: "probe.http", Provider: "fake-httpx", Executable: "fake-httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return []string{"-u", i.Targets[0]}, nil
	}}, failingRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "probe.http", Input: input, IdempotencyKey: "failure-test"}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowedScope{}}
	result, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: programID}).Execute(context.Background(), req)
	if err == nil || !errors.Is(err, errFakeExit) {
		t.Fatalf("original error was not preserved: %v", err)
	}
	if !strings.Contains(err.Error(), "resolver configuration failed") {
		t.Fatalf("diagnostic missing: %v", err)
	}
	if !store.called || store.step.Status != domain.StepFailed || store.step.ErrorClassification == "" {
		t.Fatalf("failed step not persisted: %#v", store.step)
	}
	if store.tool == nil || store.tool.ExitCode == nil || *store.tool.ExitCode != 1 || store.tool.StepRunID != stepID {
		t.Fatalf("failed tool not persisted: %#v", store.tool)
	}
	if store.result.Status != "failed" || result.Action.Error == nil {
		t.Fatalf("failed action result not persisted: %#v", store.result)
	}
	var stderrSeen, normalizedSeen bool
	for _, req := range artifacts.requests {
		if req.ProgramID != programID || req.TaskID != taskID || req.WorkflowRunID != runID || req.StepRunID != stepID || req.ToolRunID != store.tool.ID {
			t.Fatalf("incomplete artifact lineage: %#v", req)
		}
		switch req.Name {
		case "stderr.txt":
			stderrSeen = true
			if strings.Contains(string(req.Data), "sensitive-test-value") || !strings.Contains(string(req.Data), "<redacted>") {
				t.Fatalf("stderr was not redacted: %q", req.Data)
			}
		case "result.json":
			normalizedSeen = true
		}
	}
	if !stderrSeen || !normalizedSeen || len(store.artifacts) < 2 {
		t.Fatalf("failure artifacts missing: requests=%#v persisted=%#v", artifacts.requests, store.artifacts)
	}
}

func TestOSRunnerAcceptanceDeliversDNSHostsAndPersistsFailedStderr(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{
		Name:       "resolve.dns",
		Provider:   "fake-dnsx",
		Executable: os.Args[0],
		Version:    "1",
		Risk:       policy.Low,
		BuildInvocation: func(commandprovider.Input, policy.Policy) (commandprovider.Invocation, error) {
			return commandprovider.Invocation{
				Args:  []string{"-test.run=^TestExecutionFakeExecutable$", "--", "dns-failure"},
				Stdin: []byte("one.example.test\ntwo.example.test\n"),
			}, nil
		},
	}, commandprovider.OSRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}

	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://one.example.test/", "https://two.example.test/path"}})
	req := capability.Request{
		Action: domain.ActionRequest{
			ID:             domain.NewID(),
			TaskID:         taskID,
			WorkflowRunID:  runID,
			StepRunID:      stepID,
			Capability:     "resolve.dns",
			Input:          input,
			IdempotencyKey: "fake-executable-failure",
		},
		Policy: policy.Policy{AllowedCapabilities: []string{"resolve.dns"}},
		Scope:  allowedScope{},
	}

	_, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: programID}).Execute(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "fake DNS failure") {
		t.Fatalf("expected fake executable failure diagnostic, got %v", err)
	}
	if store.tool == nil || store.tool.ExitCode == nil || *store.tool.ExitCode != 9 {
		t.Fatalf("fake executable exit was not persisted: %#v", store.tool)
	}

	for _, put := range artifacts.requests {
		if put.Name != "stderr.txt" {
			continue
		}
		stderr := string(put.Data)
		if !strings.Contains(stderr, "received=one.example.test,two.example.test") {
			t.Fatalf("newline-delimited stdin did not reach fake executable: %q", stderr)
		}
		if strings.Contains(stderr, "acceptance-secret") || !strings.Contains(stderr, "<redacted>") {
			t.Fatalf("persisted stderr was not redacted: %q", stderr)
		}
		return
	}
	t.Fatal("stderr.txt was not persisted")
}

func TestExecutionFakeExecutable(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "dns-failure" {
		return
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	hosts := strings.TrimSuffix(string(stdin), "\n")
	if hosts != "one.example.test\ntwo.example.test" {
		_, _ = os.Stderr.WriteString("unexpected stdin=" + hosts + "\n")
		os.Exit(3)
	}
	_, _ = os.Stdout.WriteString("{\"partial\":true}\n")
	_, _ = os.Stderr.WriteString("password=acceptance-secret\nreceived=" + strings.ReplaceAll(hosts, "\n", ",") + "\nfake DNS failure\n")
	os.Exit(9)
}
