# BreachLens AI Evaluation

Generated at: `2026-05-30T19:40:05+00:00`
Runtime: `mcp` / `splunk_mcp` / index `breachlens`
Configured AI: `ollama` / `hf.co/LockeLamora2077/NiNa:latest`

Method: each alert is investigated once with deterministic fallback and once with the configured AI provider. An AI row is accepted only when the note status is allowed, evidence IDs resolve, and claims cite real evidence fields.

| Alert | Path | Provider | Status | Accepted | Evidence IDs | Claims | Transport | Seconds | Warnings |
| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |
| BLS-2026-001 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | mcp | 3.925 |  |
| BLS-2026-001 | configured_ai | ollama | confirmed_compromise | yes | 8 | 6 | mcp | 21.401 |  |
| BLS-2026-002 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | mcp | 3.868 |  |
| BLS-2026-002 | configured_ai | ollama | confirmed_compromise | yes | 4 | 4 | mcp | 15.975 |  |
| BLS-2026-003 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | mcp | 3.887 |  |
| BLS-2026-003 | configured_ai | ollama | confirmed_compromise | yes | 5 | 5 | mcp | 17.145 |  |

My read: NiNa passed the JSON/evidence/field-reference gate while the investigation path was running through Splunk MCP.
