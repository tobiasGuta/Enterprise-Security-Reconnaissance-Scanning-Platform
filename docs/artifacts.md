# Artifacts and evidence lineage

`artifact.Storage` currently has a local filesystem implementation and is intentionally small enough for a future S3-compatible backend. Every write requires program, task, workflow run, step run, and tool run IDs.

Metadata records artifact type, content type, byte size, SHA-256, storage location, creation time, sensitivity, and redaction state. Normal data passes through centralized redaction. Sensitive evidence is placed in a separate directory with restrictive permissions and must be explicitly marked.

Normal logs and notifications must never contain credentials, authorization headers, cookies, JWTs, API keys, webhook URLs, password fields, or user-configured secret names. Notifications should use internal candidate/finding IDs and safe summaries, not credential-bearing curl commands.
