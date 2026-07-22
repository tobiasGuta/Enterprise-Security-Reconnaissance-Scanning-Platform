package queue

import (
	"context"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type Dispatcher struct {
	Queue    *Streams
	Registry *capability.Registry
	Audit    capability.PolicyDecisionRecorder
}

func (d Dispatcher) Dispatch(ctx context.Context, job Job) (string, error) {
	if d.Queue == nil || d.Registry == nil {
		return "", fmt.Errorf("queue and capability registry are required")
	}
	if _, ok := d.Registry.Get(job.Action.Capability); !ok {
		return "", fmt.Errorf("unknown capability %q", job.Action.Capability)
	}
	sc, err := platformscope.Compile(job.ScopeIncludes, job.ScopeExcludes)
	if err != nil {
		return "", err
	}
	request := capability.Request{Action: job.Action, ProgramID: job.ProgramID, Provider: job.Provider, Approved: job.Approved, Policy: job.Policy, Scope: sc, PolicyPhase: "dispatch", DecisionRecorder: d.Audit}
	if err := d.Registry.Validate(ctx, request); err != nil {
		return "", err
	}
	if job.ID == "" {
		job.ID = domain.NewID()
	}
	return d.Queue.Enqueue(ctx, job)
}
