# Workflows

Workflow definitions contain stable capability names, typed JSON inputs, dependency IDs, bounded retries, timeouts, supported conditions, and explicit output bindings. Validation rejects cycles, unknown capabilities, invalid JSON, missing dependencies, unsupported conditions, and undeclared binding sources. There is no command or script field.

The engine persists before and after each meaningful state transition. A resumed run retains a succeeded step when its normalized input hash is unchanged. It reruns only when the definition opts into input-change reruns or the operator starts an explicit retry. Pause, cancellation, skipped steps, retryable failures, approvals, and terminal states are distinct.

## Scope-derived inputs

Every definition receives a deterministic target-plan digest. Exact host rules yield explicit protocol/port URL combinations only when an initial path is authorized. Narrow child-subdomain regexes yield passive discovery roots and wildcard metadata; the base root is not promoted to active scope. Manual discovery roots are passive-only, repeated flags require a reason, and discovered hostnames are filtered before DNSx. A changed plan changes step input hashes, preventing stale successful steps from being silently reused.

## `continuous-web-recon`

Version `2.0.0` runs passive discovery only for planned roots, filters each result, merges authorized discovered URLs with exact seeds, then runs DNSx, an optional authorized port intersection in Naabu, HTTPX, asset comparison, crawling, GAU, endpoint classification, an approved safe Nuclei profile, and a changes report. It supports multiple unrelated domains without `--domain`.

## `authorized-web-baseline`

This workflow starts only from scope-derived exact seeds, then resolves, optionally scans a common authorized port intersection, probes, compares, crawls changed assets, classifies endpoints, pauses for Nuclei approval, and reports changes. It needs no discovery root.

HTTP observations are routed deterministically: 2xx assets may be crawled, 2xx/redirect/authentication responses may enter the approved safe scan profile, and other statuses are retained as observations but not scanned.

Every scheduled invocation should create a new Task execution and WorkflowRun. The first run treats observed HTTP assets as new. Negative transitions require a complete successful source step; a failed or incomplete scan never marks an asset removed or a finding resolved.

Moderate Nuclei execution pauses without approval. Intrusive, destructive, denial-of-service, brute-force, credential-stuffing, and state-changing behavior is not part of this workflow.

```powershell
go run ./cmd/platform scope plan --scope .\scope\mixed-example.json
go run ./cmd/platform workflow plan --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
go run ./cmd/platform workflow run --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
```
