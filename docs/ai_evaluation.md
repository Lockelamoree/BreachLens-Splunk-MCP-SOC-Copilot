# BreachLens AI Evaluation

This is the latest local AI evaluation I ran before submission cleanup. It is intentionally small and repeatable: each alert is investigated once with deterministic fallback and once with the configured AI provider.

Command:

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\evaluate_ai.py --alerts 3
```

Acceptance rule: an AI row only counts when the analyst note uses an allowed status, cites valid evidence IDs, and includes claims that point to real evidence fields.

Generated at: `2026-05-30T18:40:14+00:00`
Runtime: `rest` / `splunk_rest` / index `breachlens`
Configured AI: `ollama` / `hf.co/LockeLamora2077/NiNa:latest`

| Alert | Path | Provider | Status | Accepted | Evidence IDs | Claims | Transport | Seconds | Warnings |
| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |
| BLS-2026-001 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | rest | 0.927 |  |
| BLS-2026-001 | configured_ai | ollama | confirmed_compromise | yes | 5 | 5 | rest | 13.184 |  |
| BLS-2026-002 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | rest | 0.912 |  |
| BLS-2026-002 | configured_ai | ollama | confirmed_compromise | yes | 6 | 3 | rest | 10.615 |  |
| BLS-2026-003 | deterministic | deterministic | deterministic_fallback | no | 4 | 4 | rest | 0.948 |  |
| BLS-2026-003 | configured_ai | ollama | confirmed_compromise | yes | 8 | 4 | rest | 17.536 |  |

My read: NiNa passed the stricter JSON/evidence/field-reference gate on all three local Splunk alerts. This is still REST live-data validation, not MCP proof.
