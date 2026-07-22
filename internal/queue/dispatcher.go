package queue

import (
	"context"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type Dispatcher struct {
	Queue    *Streams
	Registry *capability.Registry
}

func (d Dispatcher) Dispatch(ctx context.Context, job Job) (string, error) {
	if d.Queue == nil || d.Registry == nil {
		return "", fmt.Errorf("queue and capability registry are required")
	}
	c, ok := d.Registry.Get(job.Action.Capability)
	if !ok {
		return "", fmt.Errorf("unknown capability %q", job.Action.Capability)
	}
	sc, err := platformscope.Compile(job.ScopeIncludes, job.ScopeExcludes)
	if err != nil {
		return "", err
	}
	evaluation := policy.Evaluate(job.Policy, job.Action.Capability, c.Manifest().Risk, job.Approved)
	if evaluation.Decision != policy.Allow {
		return "", fmt.Errorf("policy %s: %s", evaluation.Decision, evaluation.Reason)
	}
	if err := c.Validate(ctx, capability.Request{Action: job.Action, Provider: job.Provider, Approved: job.Approved, Policy: job.Policy, Scope: sc}); err != nil {
		return "", err
	}
	if job.ID == "" {
		job.ID = domain.NewID()
	}
	return d.Queue.Enqueue(ctx, job)
}
