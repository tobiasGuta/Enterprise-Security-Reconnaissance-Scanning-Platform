# Future local-AI boundary

No AI component is implemented.

A future local planner may propose only validated `ActionRequest` values containing task/run IDs, requested-by source, a registered capability, reason, structured input, and idempotency key. It must use the same schema, scope, policy, approval, queue, and audit path as the CLI and scheduler.

The planner must not receive unrestricted shell access, executable selection, raw command arrays, direct provider credentials, migration access, or an approval bypass. `future_ai` is only an attribution value; it grants no additional authority.

`ActionResult` is the return boundary. It contains status, safe summary, structured output, artifact IDs, and a classified error. Large evidence stays in artifact storage rather than planner context.
