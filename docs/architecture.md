# Architecture

The application is split into commands under `cmd/` and business packages under `internal/`. Commands load one typed configuration and call services; they do not duplicate scope, policy, queue, or execution rules.

`ActionRequest` is the execution boundary. The capability registry resolves a stable capability name to a fixed provider implementation. Providers validate typed JSON, verify every target against scope, construct their own argument list, invoke an executable without a shell, and return structured output. Arbitrary executable names and raw command arrays are not part of the contract.

`scope` preserves normalized source rules with stable SHA-256 identities and complete URL evaluation. `targeting` conservatively classifies exact host/IP literals, narrow wildcard roots, protocol/port combinations, paths, exclusions, and ambiguous expressions. Provider-specific adapters parse records independently; malformed or filtered records become decisions and warnings instead of failing a usable batch. Raw redacted stdout/stderr and normalized results are separate artifacts.

The local workflow runner and Redis Streams worker share that registry. Local mode provides a complete operator-driven workflow. Streams provide crash-recoverable distributed capability delivery. Results are acknowledged only after durable persistence.

Structured IDs correlate executions internally. The target URL is never changed to carry a task or scan identifier.

The legacy aggregator is no longer required: the executor persists tool runs, artifacts, observations, candidates, and audit events transactionally. This removes a second lossy results-list hop.

## Package map

- `config`: environment defaults and validation
- `domain`: stable data and action contracts
- `migrations`, `database`: versioned PostgreSQL schema and persistence
- `scope`, `policy`: authorization boundaries
- `targeting`, `provideroutput`: deterministic plans and typed provider-record filtering
- `capability`, `providers`: controlled execution registry
- `workflow`, `workflows`: state machine and production definition
- `queue`, `worker`: Redis Streams delivery and recovery
- `artifact`, `redaction`: evidence storage and secret filtering
- `assets`, `normalize`: observations, comparison, endpoint identity
- `findings`: candidate lifecycle and safe verification verdicts
