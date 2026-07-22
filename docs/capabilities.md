# Capabilities

Active providers accept explicit authorized HTTP URLs; they never invent `https://` for a bare hostname. Subfinder, Chaos, and GAU accept bare domains only as passive roots. Named adapters normalize Subfinder, Chaos, DNSx, Naabu, HTTPX, Katana, GAU, and Nuclei output one record at a time. Protocol, host, port, path, and exclusions are rechecked; malformed records warn and filtered records do not fail the usable batch.

A capability manifest declares its stable name, version, risk, schemas, scope type, approval behavior, retry/idempotency properties, providers, artifact types, symbolic secret requirements, and default timeout.

Every external provider also has a centralized executable probe containing its version arguments, tested compatibility family, configuration variable, and exact worker-image pin. The doctor and runtime executor use the same parser. Missing executables, commands that do not return a semantic version, and versions outside the tested family are rejected before target execution.

External providers receive only validated structured fields. They construct fixed arguments internally and use `exec.CommandContext` directly—never a shell. Target values remain separate arguments, cancellation terminates the process, version information is recorded, and output is redacted before normal persistence.

`discover.subdomains` supports Subfinder by default and Chaos when `CHAOS_KEY` is configured and the provider is explicitly selected. Katana receives `-headless` only when requested and policy-approved. Nuclei runs in a dedicated per-execution process so callback correlation never requires changing the target URL; it receives the centralized rate, host/template/headless concurrency, timeout, severity, include-tag, exclude-tag, and template-directory settings. Takeover is not added implicitly or executed twice.

The internal `targeting.prepare` capability rechecks and deduplicates exact and discovered URLs immediately before active execution. Other internal capabilities classify normalized endpoint identities, compare snapshots, and produce changes-only reports without launching a subprocess. Redacted raw stdout/stderr and normalized result artifacts are stored separately.
