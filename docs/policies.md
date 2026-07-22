# Policies and approvals

Risk levels are `passive`, `low`, `moderate`, `high`, and `forbidden`. Passive/low capabilities are allowed only after scope checks and within configured limits. Moderate actions need workflow or action approval. High actions need explicit per-action approval. Forbidden actions always fail closed.

Policies can restrict capabilities, HTTP methods, authentication, headless mode, directory fuzzing, template tags, payload size, redirects, cross-origin behavior, intrusive checks, rate/concurrency, scan windows, and retention. The current CLI constructs a conservative runtime policy from centralized configuration.

Approval records link a request, task, action, risk, reason, decision maker, decision time, and optional expiration. Policy is evaluated before dispatch and again inside the worker immediately before execution.

Redirect scope is evaluated on both the original and destination URL. A permitted source never makes an out-of-scope redirect destination permissible.

Scope expansion is a separate human-control gate. Adding an include or removing an exclude records a pending scope version and blocks workflow execution until the operator reviews the plan and supplies `--acknowledge-scope-expansion`. Passive roots never grant active authorization. Complex regexes remain valid enforcement rules but are not converted into invented targets or ports.
