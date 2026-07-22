package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/providers"
)

func TestScopePlanCLIProducesJSONWithoutRuntimeConfiguration(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "targeting", "testdata", "mixed_real_world_scope.json")
	out, err := captureStdout(func() error { return scopeCommand([]string{"plan", "--scope", path}) })
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		NetworkExecution bool  `json:"network_execution"`
		Exact            []any `json:"exact_active_seeds"`
		Roots            []any `json:"discovery_roots"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(payload.Exact) == 0 || len(payload.Roots) == 0 {
		t.Fatalf("incomplete plan: %s", out)
	}
}

func TestWorkflowPlanCLIAndRepeatedManualRoots(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "targeting", "testdata", "mixed_real_world_scope.json")
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(func() error {
		return workflowPlan(cfg, providers.Registry(cfg), []string{"--program-id", "00000000-0000-0000-0000-000000000001", "--scope", path, "--discovery-root", "one.example", "--discovery-root", "two.example", "--discovery-root-reason", "passive operator request"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		NetworkExecution bool `json:"network_execution"`
		TargetPlan       struct {
			Roots []any `json:"discovery_roots"`
		} `json:"target_plan"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.NetworkExecution || len(payload.TargetPlan.Roots) < 3 {
		t.Fatalf("unexpected dry run: %s", out)
	}
}

func TestManualDiscoveryRootReasonAndDeprecatedDomainBehavior(t *testing.T) {
	if _, err := manualRoots([]string{"example.com"}, "", ""); err == nil {
		t.Fatal("missing reason accepted")
	}
	roots, err := manualRoots(nil, "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0].Reason == "" {
		t.Fatalf("deprecated domain was not auditable: %#v", roots)
	}
}

func TestWorkflowRunScopeDoesNotRequireDomain(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "targeting", "testdata", "mixed_real_world_scope.json")
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database.URL = "://invalid"
	err = workflowRun(context.Background(), cfg, providers.Registry(cfg), []string{"--program-id", "00000000-0000-0000-0000-000000000001", "--scope", path, "--workflow", "authorized-web-baseline"})
	if err == nil {
		t.Fatal("expected database configuration failure")
	}
	if strings.Contains(err.Error(), "--domain") {
		t.Fatalf("domain is still required: %v", err)
	}
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	read := make(chan struct {
		text string
		err  error
	}, 1)
	go func() {
		b, readErr := io.ReadAll(r)
		read <- struct {
			text string
			err  error
		}{string(b), readErr}
	}()
	callErr := fn()
	_ = w.Close()
	os.Stdout = old
	result := <-read
	_ = r.Close()
	if callErr != nil {
		return result.text, callErr
	}
	return result.text, result.err
}
