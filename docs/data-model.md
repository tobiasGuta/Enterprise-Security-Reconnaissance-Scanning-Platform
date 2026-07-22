# Data model

The primary hierarchy is:

```text
Program -> Task -> WorkflowRun -> StepRun -> ToolRun
```

Programs hold engagement identity, scope/policy references, current scope and target-plan digests, normalized include/exclude digests, and warnings. Scope versions retain the sanitized plan, added/removed rule digests, expansion classification, and acknowledgement. Tasks hold a human objective. Each execution creates a distinct WorkflowRun. StepRun stores attempts, structured input/output, idempotency and approval state. ToolRun records provider/version, sanitized arguments, environment, timings, timeout, exit code, and artifact references.

Audit events preserve program scope decisions and task/run/step/tool lineage for scope loads, plan derivation, manual roots, accepted/filtered targets, exclusions, protocol/port rejection, scope changes, and moderate approvals.

Assets are stable logical identities. Asset observations describe what a capability saw during a particular successful workflow run. Endpoint identity includes host, normalized route signature, HTTP method, content type, and query-parameter names, while retaining the exact observed URL.

Route signatures generalize integer, UUID, long hex/ObjectID, date/timestamp, and strong high-entropy identifier segments. They do not generalize a path merely because it has several siblings.

Scanner output becomes `candidate_findings`. Verification results independently record confirmed, rejected, inconclusive, or manual-review verdicts. Only a confirmed candidate may become a `verified_finding`; the scanner does not assert business impact.
