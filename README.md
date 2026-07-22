# Reconductor

Reconductor is a deterministic, human-directed enterprise security reconnaissance platform for authorized bug bounty and penetration-testing work. It automates repeatable discovery and safe scanning while keeping scope, policy, approval, and vulnerability decisions under human control.

The platform does **not** contain an LLM, planner, agent loop, prompt engine, embeddings, or unrestricted shell interface. A future local planner can only submit the same validated `ActionRequest` objects used by the CLI, scheduler, workflow runner, and worker.

## Safety model

Every network capability is checked against an explicit scope and policy before execution. Passive and low-risk capabilities may run within configured limits. Moderate and high-risk actions require the applicable approval. Forbidden actions never run. Workflow input can select a registered capability and provider; it cannot supply an executable or command array.

Burp-compatible scope JSON is the targeting source of truth. Exact active seeds stay separate from passive discovery roots: `*.dev.example.test` may derive the passive root `dev.example.test`, but that root is never probed unless a complete protocol/host/port/path evaluation independently authorizes it. Exclusions always win.

The built-in Nuclei profile excludes denial-of-service, brute-force, fuzzing, and intrusive tags. Scanner matches are persisted as candidate findings with a default confidence, not as verified findings. Independent deterministic verification or human review is required before promotion.

## Architecture

```text
Human / CLI / scheduler / future web API / future local AI
                           |
                    ActionRequest
                           |
            schema + scope + policy checks
                           |
                  approval if required
                           |
       deterministic capability/provider registry
                           |
        results + artifacts + observations + audit
                           |
       candidates -> verification -> verified findings
```

The persisted hierarchy is `Program -> Task -> WorkflowRun -> StepRun -> ToolRun`. Artifacts, observations, candidates, approvals, and audit events retain those execution IDs.

## Current capabilities

| Capability | Provider | Risk |
|---|---|---|
| `discover.subdomains` | Subfinder; optional Chaos | passive |
| `resolve.dns` | DNSx | low |
| `scan.ports` | Naabu | low |
| `probe.http` | HTTPX | low |
| `crawl.web` | Katana, including configured headless mode | low |
| `discover.archive_urls` | GAU | passive |
| `targeting.prepare` | in-process scope filter and deduplicator | passive |
| `classify.endpoint` | in-process | passive |
| `scan.nuclei` | constrained Nuclei provider | moderate |
| `compare.assets` | in-process | passive |
| `report.changes` | in-process | passive |

There are two generic scope-driven definitions: `continuous-web-recon` adds passive discovery for derived/operator-approved roots, while `authorized-web-baseline` operates only from exact active seeds. Both support multiple unrelated domains.

## Local setup

Requirements: Go 1.25+, PostgreSQL 15+, Redis 7+, and the enabled ProjectDiscovery/GAU executables on `PATH` for local workflow execution.

On systems with same-name commands, set the corresponding `*_EXECUTABLE` variable in `.env` to the full binary path. In particular, `HTTPX_EXECUTABLE` must resolve to [ProjectDiscovery HTTPX](https://docs.projectdiscovery.io/opensource/httpx/install), not the Python HTTPX client. The provider verifies ProjectDiscovery HTTPX with `-version` before probing any target.

Check the complete local execution environment without sending target traffic:

```powershell
go run ./cmd/platform doctor
go run ./cmd/platform doctor --format json
```

The doctor resolves every configured provider, verifies its identity and tested version family, discovers the active Nuclei template version, and tests PostgreSQL and Redis connectivity. External provider execution uses the same compatibility checks, so a successful doctor cannot be bypassed by a later workflow step. See [environment diagnostics](docs/doctor.md).

```powershell
Copy-Item .env.example .env
docker compose up -d postgres redis
go run ./cmd/platform migrate
go run ./cmd/platform capabilities
```

Create a program using an explicit Burp-compatible scope file:

```powershell
go run ./cmd/platform program create --name example --platform private --scope scope/example.json
go run ./cmd/platform program list
```

Review the non-network plans, then run without a root-domain argument:

```powershell
go run ./cmd/platform scope plan --scope .\scope\example.json
go run ./cmd/platform workflow plan --program-id <uuid> --scope .\scope\example.json
go run ./cmd/platform workflow validate --scope .\scope\example.json
go run ./cmd/platform workflow run --program-id <uuid> --scope .\scope\example.json --objective "Authorized low-rate baseline reconnaissance"
```

The run pauses before the moderate Nuclei step unless the operator explicitly supplies `--approve-moderate`. Resume from the saved run state with `--resume <workflow-run-id>` and the original program/scope/plan flags. Successful unchanged steps retain their idempotency keys and are not repeated.

Katana headless crawling requires both `--headless` and a policy that permits it. The setting is passed to Katana rather than merely accepted by the CLI.

Use `--workflow authorized-web-baseline` for exact seeds only. `--discovery-root` is repeatable, passive-only, and requires `--discovery-root-reason`. Deprecated `--domain` is treated only as an auditable passive root. A detected scope expansion requires `--acknowledge-scope-expansion` after review.

## CLI

```text
platform program create|list
platform task create|list|show|pause|resume|cancel
platform scope plan
platform workflow validate|plan|run
platform run show|retry
platform approvals list|approve|reject
platform queue pending|failed|retry
platform report changes
platform capabilities
platform doctor [--format table|json]
platform migrate
```

`run retry <run-id>` accepts the same `--program-id`, `--domain`, `--scope`, and approval flags as `workflow run`; successful unchanged steps are retained. Queue inspection uses the single Redis consumer group and dead-letter stream.

## Reliable delivery

Distributed capability jobs use Redis Streams:

```text
platform.capability.jobs
platform.capability.results
platform.events
platform.dead_letter
```

Workers acknowledge only after the result, execution lineage, artifacts, observations, candidates, and audit record are durably persisted. Pending entries are reclaimed after the lease timeout. Temporary failures move through a durable retry schedule with bounded exponential backoff; exhausted or permanent failures go to the dead-letter stream. Duplicate delivery is checked using the step idempotency key.

## Data and evidence

Versioned embedded migrations create normalized programs, scope-plan history, policies, workflows, executions, artifacts, assets/observations, endpoints, candidates, verification results, verified findings, approvals, and audit events. Scope history retains rule and plan digests, warnings, changes, and expansion acknowledgement without secrets.

Local artifacts use:

```text
artifacts/programs/<program>/tasks/<task>/runs/<run>/steps/<step>/tool-runs/<tool>/
```

Each record includes size, SHA-256 digest, content type, location, redaction state, and full lineage. Normal artifacts are redacted. Deliberately retained sensitive evidence is stored separately with restrictive permissions and marked sensitive.

## Configuration

All supported variables and local-only defaults are in [.env.example](.env.example). Runtime parsing is centralized in `internal/config`; invalid limits, durations, pipeline stages, and storage drivers fail at startup. Secret values are excluded from configuration strings and structured logs.

Docker publishes PostgreSQL and Redis only on `127.0.0.1` by default. Change local credentials before using a shared host. Production deployments should inject secrets rather than committing an `.env` file.

## Development

```powershell
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./...
```

PostgreSQL and Redis integration tests run when `TEST_DATABASE_URL` and `TEST_REDIS_ADDR` are set. All network tests use local test services; they do not contact public targets. CI runs formatting, vet, unit/integration/race tests, migrations, build, vulnerability scanning, and a worker image build.

More detail: [architecture](docs/architecture.md), [workflows](docs/workflows.md), [capabilities](docs/capabilities.md), [policies](docs/policies.md), [data model](docs/data-model.md), [artifacts](docs/artifacts.md), [environment diagnostics](docs/doctor.md), [AI readiness](docs/ai-readiness.md), and [migration](docs/migration.md).

## Current limitations

- Local workflow execution requires compatible external tools; `platform doctor` reports missing, wrong, or incompatible binaries before a workflow starts. The versioned worker image bundles all registered external providers and the pinned Nuclei template snapshot.
- Ambiguous host/protocol/port regexes remain enforceable by the full scope evaluator, but produce warnings and no invented active targets or ports.
- The first successful workflow run necessarily treats all observed HTTP assets as new; later runs load the previous successful HTTP observation snapshot and compare stable status/technology fields.
- `continuous-web-recon` currently runs end to end in the local CLI. Distributed workers execute reliable individual capability jobs; a distributed workflow coordinator/scheduler is not yet included.
- Safe verification playbooks currently evaluate independently captured response evidence. An approved HTTP evidence-acquisition capability is still needed for one-command live verification.
- The CLI is the supported interface; a web service and scheduler have not yet been added.
