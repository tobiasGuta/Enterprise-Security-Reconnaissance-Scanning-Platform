package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/console"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/doctor"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		if !errors.Is(err, doctor.ErrUnhealthy) {
			slog.Error("command failed", "error", err)
		}
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	_ = config.LoadEnvFile(".env")
	if args[0] == "scope" {
		return scopeCommand(args[1:])
	}
	if args[0] == "doctor" {
		cfg, configErr := config.LoadDoctor()
		return doctorCommand(ctx, cfg, configErr, args[1:])
	}
	planning := args[0] == "workflow" && len(args) > 1 && args[1] == "plan"
	var cfg config.Config
	var err error
	if planning {
		cfg, err = config.LoadPlanning()
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		return err
	}
	switch args[0] {
	case "migrate":
		return withStore(ctx, cfg, func(s *database.Store) error { return s.Migrate(ctx) })
	case "program":
		return programCommand(ctx, cfg, args[1:])
	case "task":
		return taskCommand(ctx, cfg, args[1:])
	case "workflow":
		return workflowCommand(ctx, cfg, args[1:])
	case "run":
		return runCommand(ctx, cfg, args[1:])
	case "approvals":
		return approvalCommand(ctx, cfg, args[1:])
	case "queue":
		return queueCommand(ctx, cfg, args[1:])
	case "report":
		return reportCommand(ctx, cfg, args[1:])
	case "console":
		return consoleCommand(ctx, cfg, args[1:])
	case "capabilities":
		b, _ := json.MarshalIndent(providers.Registry(cfg).Names(), "", "  ")
		fmt.Println(string(b))
		return nil
	default:
		return usage()
	}
}
func usage() error {
	return fmt.Errorf("usage: platform <migrate|program|task|scope|workflow|run|approvals|queue|report|console|capabilities|doctor> ...")
}

func consoleCommand(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8088", "loopback address for the local operator console")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireLoopbackAddress(*listen); err != nil {
		return err
	}
	store, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	rdb := redisClient(cfg)
	defer rdb.Close()
	workQueue := queue.New(rdb, cfg.Worker.ConsumerGroup, cfg.Worker.ConsumerName, cfg.Worker.MaxRetries, cfg.Worker.RetryBase)
	if err := workQueue.EnsureGroup(ctx); err != nil {
		return fmt.Errorf("initialize console queue view: %w", err)
	}
	server := console.HTTPServer(*listen, console.New(store, workQueue))
	slog.Info("Reconductor operator console ready", "url", "http://"+*listen)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func requireLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("console --listen must be a loopback host:port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("console refuses non-loopback address %q because authentication is not configured", address)
	}
	return nil
}

func doctorCommand(ctx context.Context, cfg config.Config, configErr error, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report := doctor.Run(ctx, cfg, configErr)
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "table":
		if err := doctor.WriteTable(os.Stdout, report); err != nil {
			return err
		}
	case "json":
		if err := doctor.WriteJSON(os.Stdout, report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported doctor format %q (use table or json)", *format)
	}
	if !report.Healthy {
		return doctor.ErrUnhealthy
	}
	return nil
}
func withStore(ctx context.Context, cfg config.Config, fn func(*database.Store) error) error {
	s, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}
func readyStore(ctx context.Context, cfg config.Config) (*database.Store, error) {
	s, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return nil, err
	}
	if err := s.Migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		fmt.Println(string(b))
	}
	return err
}

func programCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("program requires create or list")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("program create", flag.ContinueOnError)
		name := fs.String("name", "", "program name")
		platform := fs.String("platform", "private", "HackerOne, Bugcrowd, private, lab, or internal")
		description := fs.String("description", "", "description")
		scopeRef := fs.String("scope", "", "scope file/reference")
		policyRef := fs.String("policy", "default", "policy reference")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || *scopeRef == "" {
			return fmt.Errorf("--name and --scope are required")
		}
		sc, err := platformscope.LoadBurp(*scopeRef)
		if err != nil {
			return fmt.Errorf("load scope: %w", err)
		}
		plan, err := targeting.Plan(sc, nil)
		if err != nil {
			return err
		}
		if !plan.HasExecutableTargets() {
			return fmt.Errorf("target plan has no executable authorized targets")
		}
		now := time.Now().UTC()
		warnings, _ := json.Marshal(plan.Warnings)
		p := domain.Program{ID: domain.NewID(), Name: *name, Platform: *platform, Description: *description, ScopeReference: *scopeRef, PolicyReference: *policyRef, ScopeDigest: sc.Digest(), IncludeRuleDigests: sc.IncludeDigests(), ExcludeRuleDigests: sc.ExcludeDigests(), TargetPlanDigest: plan.Digest, ScopePlanWarnings: warnings, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateProgram(ctx, p, scopeSnapshot(p.ID, *scopeRef, sc, plan)); err != nil {
			return err
		}
		return printJSON(p)
	case "list":
		p, err := s.ListPrograms(ctx)
		if err != nil {
			return err
		}
		return printJSON(p)
	default:
		return fmt.Errorf("unknown program command %q", args[0])
	}
}
func taskCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("task requires create, list, show, pause, resume, or cancel")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("task create", flag.ContinueOnError)
		programID := fs.String("program-id", "", "program UUID")
		objective := fs.String("objective", "", "human objective")
		requested := fs.String("requested-by", "cli", "request source")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *programID == "" || *objective == "" {
			return fmt.Errorf("--program-id and --objective are required")
		}
		placeholderScope, _ := platformscope.HostScope("placeholder.invalid")
		placeholderPlan, _ := targeting.Plan(placeholderScope, nil)
		def := workflows.ContinuousWebRecon(placeholderPlan, false)
		defJSON, _ := json.Marshal(def)
		if err := s.CreateWorkflowDefinition(ctx, def.ID, def.Name, def.Version, def.Description, defJSON); err != nil {
			return err
		}
		now := time.Now().UTC()
		t := domain.Task{ID: domain.NewID(), ProgramID: domain.ID(*programID), Objective: *objective, WorkflowDefinitionID: def.ID, Status: domain.TaskPending, RequestedBy: *requested, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateTask(ctx, t); err != nil {
			return err
		}
		return printJSON(t)
	case "list":
		items, err := s.ListTasks(ctx)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("task show <task-id>")
		}
		t, err := s.GetTask(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		return printJSON(t)
	case "pause", "resume", "cancel":
		if len(args) < 2 {
			return fmt.Errorf("task %s <task-id>", args[0])
		}
		status := map[string]domain.TaskStatus{"pause": domain.TaskPaused, "resume": domain.TaskRunning, "cancel": domain.TaskCancelled}[args[0]]
		reason := ""
		if args[0] == "cancel" && len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		return s.SetTaskStatus(ctx, domain.ID(args[1]), status, reason)
	default:
		return fmt.Errorf("unknown task command %q", args[0])
	}
}

type stringFlags []string

func (s *stringFlags) String() string         { return strings.Join(*s, ",") }
func (s *stringFlags) Set(value string) error { *s = append(*s, value); return nil }

func scopeCommand(args []string) error {
	if len(args) == 0 || args[0] != "plan" {
		return fmt.Errorf("scope requires: scope plan --scope <burp-scope.json>")
	}
	fs := flag.NewFlagSet("scope plan", flag.ContinueOnError)
	scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
	var roots stringFlags
	fs.Var(&roots, "discovery-root", "manual passive discovery root (repeatable)")
	reason := fs.String("discovery-root-reason", "", "auditable reason for manual discovery roots")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *scopePath == "" {
		return fmt.Errorf("--scope is required")
	}
	manual, err := manualRoots(roots, *reason, "")
	if err != nil {
		return err
	}
	plan, err := loadTargetPlan(*scopePath, manual)
	if err != nil {
		return err
	}
	return printJSON(plan)
}

func loadTargetPlan(path string, manual []targeting.ManualDiscoveryRoot) (targeting.TargetPlan, error) {
	sc, err := platformscope.LoadBurp(path)
	if err != nil {
		return targeting.TargetPlan{}, fmt.Errorf("load scope: %w", err)
	}
	plan, err := targeting.Plan(sc, manual)
	if err != nil {
		return targeting.TargetPlan{}, err
	}
	return plan, nil
}

func scopeSnapshot(programID domain.ID, reference string, sc platformscope.Scope, plan targeting.TargetPlan) domain.ScopeSnapshot {
	warnings, _ := json.Marshal(plan.Warnings)
	planJSON, _ := json.Marshal(plan)
	return domain.ScopeSnapshot{ID: domain.NewID(), ProgramID: programID, ScopeReference: reference, ScopeDigest: sc.Digest(), IncludeRuleDigests: sc.IncludeDigests(), ExcludeRuleDigests: sc.ExcludeDigests(), TargetPlanDigest: plan.Digest, PlanningWarnings: warnings, TargetPlan: planJSON, AddedIncludeDigests: []string{}, RemovedIncludeDigests: []string{}, AddedExcludeDigests: []string{}, RemovedExcludeDigests: []string{}, CreatedAt: time.Now().UTC()}
}

func manualRoots(roots []string, reason, deprecatedDomain string) ([]targeting.ManualDiscoveryRoot, error) {
	if len(roots) > 0 && strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("--discovery-root-reason is required with --discovery-root")
	}
	out := make([]targeting.ManualDiscoveryRoot, 0, len(roots)+1)
	for _, root := range roots {
		out = append(out, targeting.ManualDiscoveryRoot{Domain: root, Reason: reason})
	}
	if strings.TrimSpace(deprecatedDomain) != "" {
		out = append(out, targeting.ManualDiscoveryRoot{Domain: deprecatedDomain, Reason: "deprecated --domain compatibility input"})
	}
	return out, nil
}

func workflowPlan(cfg config.Config, registry *capability.Registry, args []string) error {
	fs := flag.NewFlagSet("workflow plan", flag.ContinueOnError)
	programID := fs.String("program-id", "", "program UUID (recorded only; no database access)")
	scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
	workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
	headless := fs.Bool("headless", false, "show policy-approved headless mode")
	deprecatedDomain := fs.String("domain", "", "deprecated passive discovery root")
	var roots stringFlags
	fs.Var(&roots, "discovery-root", "manual passive discovery root (repeatable)")
	reason := fs.String("discovery-root-reason", "", "auditable reason for manual discovery roots")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *programID == "" || *scopePath == "" {
		return fmt.Errorf("--program-id and --scope are required")
	}
	manual, err := manualRoots(roots, *reason, *deprecatedDomain)
	if err != nil {
		return err
	}
	if *deprecatedDomain != "" {
		fmt.Fprintln(os.Stderr, "warning: --domain is deprecated; it is treated only as a passive discovery root")
	}
	plan, err := loadTargetPlan(*scopePath, manual)
	if err != nil {
		return err
	}
	if !plan.HasExecutableTargets() {
		return fmt.Errorf("target plan has no executable authorized targets")
	}
	def, err := workflows.Build(*workflowName, plan, *headless)
	if err != nil {
		return err
	}
	if err := workflow.Validate(def, registry); err != nil {
		return err
	}
	type plannedCapability struct {
		Step             string      `json:"step"`
		Capability       string      `json:"capability"`
		Provider         string      `json:"provider,omitempty"`
		Risk             policy.Risk `json:"risk"`
		ApprovalRequired bool        `json:"approval_required"`
	}
	capabilities := make([]plannedCapability, 0, len(def.Steps))
	for _, step := range def.Steps {
		c, ok := registry.Get(step.Capability)
		if !ok {
			continue
		}
		m := c.Manifest()
		capabilities = append(capabilities, plannedCapability{Step: step.ID, Capability: step.Capability, Provider: step.Provider, Risk: m.Risk, ApprovalRequired: step.ApprovalRequired || m.ApprovalRequired})
	}
	return printJSON(map[string]any{
		"network_execution": false, "program_id": *programID, "workflow": map[string]any{"name": def.Name, "version": def.Version}, "target_plan": plan,
		"initial_active_targets": plan.InitialURLs(), "capabilities": capabilities, "rate_limit": cfg.Policy.DefaultRateLimit, "concurrency": cfg.Policy.DefaultConcurrency,
		"authorized_ports": plan.AllowedPorts, "headless": *headless, "nuclei_profile": map[string]any{"approval_required": true, "severity": cfg.Nuclei.Severity, "include_tags": cfg.Nuclei.IncludeTags, "exclude_tags": cfg.Nuclei.ExcludeTags, "rate_limit": cfg.Nuclei.RateLimit}, "warnings": plan.Warnings,
	})
}

func workflowCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("workflow requires validate, plan, or run")
	}
	registry := providers.Registry(cfg)
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("workflow validate", flag.ContinueOnError)
		scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
		workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *scopePath == "" {
			return fmt.Errorf("--scope is required")
		}
		plan, err := loadTargetPlan(*scopePath, nil)
		if err != nil {
			return err
		}
		if !plan.HasExecutableTargets() {
			return fmt.Errorf("target plan has no executable authorized targets")
		}
		def, err := workflows.Build(*workflowName, plan, cfg.Recon.Headless)
		if err != nil {
			return err
		}
		if err := workflow.Validate(def, registry); err != nil {
			return err
		}
		return printJSON(map[string]any{"name": def.Name, "version": def.Version, "valid": true, "steps": len(def.Steps)})
	case "plan":
		return workflowPlan(cfg, registry, args[1:])
	case "run":
		return workflowRun(ctx, cfg, registry, args[1:])
	default:
		return fmt.Errorf("unknown workflow command %q", args[0])
	}
}
func workflowRun(ctx context.Context, cfg config.Config, registry *capability.Registry, args []string) error {
	fs := flag.NewFlagSet("workflow run", flag.ContinueOnError)
	programID := fs.String("program-id", "", "program UUID")
	taskID := fs.String("task-id", "", "existing task UUID (optional)")
	objective := fs.String("objective", "continuous authorized web reconnaissance", "task objective")
	domainName := fs.String("domain", "", "authorized root domain")
	scopePath := fs.String("scope", "", "Burp scope JSON path")
	workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
	var discoveryRoots stringFlags
	fs.Var(&discoveryRoots, "discovery-root", "manual passive discovery root (repeatable)")
	discoveryReason := fs.String("discovery-root-reason", "", "auditable reason for manually supplied passive roots")
	ackScopeExpansion := fs.Bool("acknowledge-scope-expansion", false, "acknowledge an expanded scope plan")
	resumeID := fs.String("resume", "", "workflow run UUID to resume")
	approve := fs.Bool("approve-moderate", false, "explicitly approve the safe moderate Nuclei step for this run")
	headless := fs.Bool("headless", cfg.Recon.Headless, "enable policy-approved Katana headless mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *programID == "" || *scopePath == "" {
		return fmt.Errorf("--program-id and --scope are required")
	}
	manual, err := manualRoots(discoveryRoots, *discoveryReason, *domainName)
	if err != nil {
		return err
	}
	if *domainName != "" {
		fmt.Fprintln(os.Stderr, "warning: --domain is deprecated; it is treated only as a passive discovery root")
	}
	sc, err := platformscope.LoadBurp(*scopePath)
	if err != nil {
		return err
	}
	plan, err := targeting.Plan(sc, manual)
	if err != nil {
		return err
	}
	if !plan.HasExecutableTargets() {
		return fmt.Errorf("target plan has no executable authorized targets")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	change, err := s.CheckAndRecordScopeSnapshot(ctx, scopeSnapshot(domain.ID(*programID), *scopePath, sc, plan), *ackScopeExpansion, "cli")
	if err != nil {
		return err
	}
	if change.ExpandsScope && !change.Acknowledged {
		return fmt.Errorf("scope change expands authorization; review the plan and rerun with --acknowledge-scope-expansion")
	}
	def, err := workflows.Build(*workflowName, plan, *headless)
	if err != nil {
		return err
	}
	defJSON, _ := json.Marshal(def)
	if err := s.CreateWorkflowDefinition(ctx, def.ID, def.Name, def.Version, def.Description, defJSON); err != nil {
		return err
	}
	fileStore := workflow.FileStore{Root: "state/runs"}
	var state *workflow.State
	if *resumeID != "" {
		state, err = fileStore.Load(*resumeID)
		if err != nil {
			return err
		}
	}
	var task domain.Task
	if state != nil {
		task, err = s.GetTask(ctx, state.Run.TaskID)
		if err != nil {
			return err
		}
	} else if *taskID != "" {
		task, err = s.GetTask(ctx, domain.ID(*taskID))
		if err != nil {
			return err
		}
	} else {
		now := time.Now().UTC()
		task = domain.Task{ID: domain.NewID(), ProgramID: domain.ID(*programID), Objective: *objective, WorkflowDefinitionID: def.ID, Status: domain.TaskRunning, RequestedBy: "cli", CreatedAt: now, UpdatedAt: now}
		if err := s.CreateTask(ctx, task); err != nil {
			return err
		}
	}
	if task.ProgramID != domain.ID(*programID) {
		return fmt.Errorf("task %s belongs to program %s, not %s", task.ID, task.ProgramID, *programID)
	}
	redactor := redaction.New(cfg.Logging.SecretNames...)
	artifacts, err := artifact.NewLocal(cfg.ArtifactStorage.Root, redactor)
	if err != nil {
		return err
	}
	if _, err := artifact.PurgeExpired(ctx, s, artifacts, 1000); err != nil {
		return fmt.Errorf("purge expired artifacts: %w", err)
	}
	pol := policy.Policy{ID: "runtime", AllowedCapabilities: registry.Names(), RateLimit: cfg.Policy.DefaultRateLimit, Concurrency: cfg.Policy.DefaultConcurrency, ProviderConcurrency: cfg.Policy.DefaultProviderConcurrency, HostConcurrency: cfg.Policy.DefaultHostConcurrency, ScanWindows: cfg.Policy.ScanWindows, AllowedHTTPMethods: cfg.Policy.AllowedMethods, AuthenticationUsage: cfg.Policy.AuthenticationUsage, HeadlessBrowser: *headless, DirectoryFuzzing: cfg.Policy.DirectoryFuzzing, MaximumPayloadSize: cfg.Policy.MaxPayloadBytes, FollowRedirects: cfg.Policy.FollowRedirects, CrossOrigin: cfg.Policy.CrossOrigin, IntrusiveChecks: cfg.Policy.IntrusiveChecks, ArtifactRetention: cfg.Policy.ArtifactRetention, ExcludedTemplateTags: cfg.Nuclei.ExcludeTags}
	maxParallel := policy.ProgramParallelism(pol)
	limiter := budget.NewLocal(budget.Limits{Program: maxParallel, Provider: pol.ProviderConcurrency, Host: pol.HostConcurrency})
	engine := workflow.Engine{Registry: registry, Executor: execution.Service{Registry: registry, Store: s, Artifacts: artifacts, ProgramID: task.ProgramID}, Persister: database.WorkflowPersister{Store: s, File: fileStore}, Policy: pol, Scope: sc, Budget: limiter, MaxParallel: maxParallel}
	approvedByRecord := false
	if state != nil {
		for _, ss := range state.Steps {
			if ss.Run.Status == domain.StepAwaitingApproval {
				decision, checkErr := s.StepApprovalDecision(ctx, ss.Run.ID)
				if checkErr != nil {
					return checkErr
				}
				if decision == "rejected" {
					return fmt.Errorf("approval for step %s was rejected", ss.Run.StepDefinitionID)
				}
				approvedByRecord = approvedByRecord || decision == "approved"
			}
		}
	}
	if *approve || approvedByRecord {
		engine.Approval = func(_ context.Context, _ workflow.Step, _ policy.Risk) (bool, error) { return true, nil }
	}
	controls := &workflow.Controls{}
	if task.Status == domain.TaskCancelled {
		controls.Cancel()
	} else if task.Status == domain.TaskPaused {
		controls.Pause()
	}
	watchCtx, stopWatching := context.WithCancel(ctx)
	defer stopWatching()
	go watchTaskControls(watchCtx, s, task.ID, controls)
	state, runErr := engine.Run(ctx, def, state, task, controls)
	_ = printJSON(state)
	if state != nil {
		status := map[domain.RunStatus]domain.TaskStatus{domain.RunCompleted: domain.TaskCompleted, domain.RunPaused: domain.TaskPaused, domain.RunFailed: domain.TaskFailed, domain.RunCancelled: domain.TaskCancelled}[state.Run.Status]
		if status != "" {
			_ = s.SetTaskStatus(ctx, task.ID, status, "")
		}
	}
	return runErr
}

type taskReader interface {
	GetTask(context.Context, domain.ID) (domain.Task, error)
}

func watchTaskControls(ctx context.Context, store taskReader, taskID domain.ID, controls *workflow.Controls) {
	watchTaskControlsInterval(ctx, store, taskID, controls, 500*time.Millisecond)
}

func watchTaskControlsInterval(ctx context.Context, store taskReader, taskID domain.ID, controls *workflow.Controls, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			task, err := store.GetTask(ctx, taskID)
			if err != nil {
				slog.Warn("workflow task control refresh failed", "task_id", taskID, "error", err)
				continue
			}
			switch task.Status {
			case domain.TaskCancelled:
				controls.Cancel()
				return
			case domain.TaskPaused:
				controls.Pause()
			}
		}
	}
}

func runCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("run show|retry <run-id>")
	}
	if args[0] == "retry" {
		forward := append([]string{"--resume", args[1]}, args[2:]...)
		return workflowRun(ctx, cfg, providers.Registry(cfg), forward)
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "show":
		r, err := s.GetWorkflowRun(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		return printJSON(r)
	default:
		return fmt.Errorf("unknown run command")
	}
}
func approvalCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("approvals requires list, approve, or reject")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "list":
		v, err := s.ListApprovals(ctx)
		if err != nil {
			return err
		}
		return printJSON(v)
	case "approve", "reject":
		if len(args) < 2 {
			return fmt.Errorf("approvals %s <approval-id> [actor]", args[0])
		}
		actor := "human"
		if len(args) > 2 {
			actor = args[2]
		}
		decision := map[string]string{"approve": "approved", "reject": "rejected"}[args[0]]
		return s.DecideApproval(ctx, domain.ID(args[1]), decision, actor)
	default:
		return fmt.Errorf("unknown approvals command")
	}
}
func queueCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("queue requires pending, failed, or retry")
	}
	rdb := redisClient(cfg)
	defer rdb.Close()
	q := queue.New(rdb, cfg.Worker.ConsumerGroup, cfg.Worker.ConsumerName, cfg.Worker.MaxRetries, cfg.Worker.RetryBase)
	if err := q.EnsureGroup(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "pending":
		p, err := q.Pending(ctx)
		if err != nil {
			return err
		}
		return printJSON(p)
	case "failed":
		v, err := q.DeadLetters(ctx, 100)
		if err != nil {
			return err
		}
		return printJSON(v)
	case "retry":
		if len(args) < 2 {
			return fmt.Errorf("queue retry <dead-letter-message-id>")
		}
		return q.RetryDeadLetter(ctx, args[1])
	default:
		return fmt.Errorf("unknown queue command")
	}
}
func reportCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) < 2 || args[0] != "changes" {
		return fmt.Errorf("report changes <program-id>")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	v, err := s.LatestChanges(ctx, domain.ID(args[1]))
	if err != nil {
		return err
	}
	fmt.Println(string(v))
	return nil
}
func redisClient(cfg config.Config) *redis.Client {
	opts := &redis.Options{Addr: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB, DialTimeout: 5 * time.Second, ReadTimeout: cfg.Worker.ReadBlock + time.Second, WriteTimeout: 5 * time.Second}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return redis.NewClient(opts)
}
