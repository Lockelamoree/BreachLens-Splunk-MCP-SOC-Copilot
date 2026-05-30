# BreachLens Live MCP Validation

Generated at: `2026-05-30T19:30:56+00:00`
Runtime: `mcp` / `splunk_mcp`
MCP endpoint: `https://localhost:18089/services/mcp`
All required tools observed: `True`

## Required Tool Calls

| Tool | OK | Result Count | Error |
| --- | --- | ---: | --- |
| `splunk_get_indexes` | True | 14 |  |
| `splunk_get_metadata` | True | 1 |  |
| `splunk_get_knowledge_objects` | True | 1 |  |
| `splunk_run_query` | True | 1 |  |

## Investigation Proof

- Alert: `BLS-2026-001`
- Investigation: `INV-AD49E96F`
- Evidence items: `23`
- Transcript transports: `mcp`
- Transcript tools: `splunk_get_indexes, splunk_get_knowledge_objects, splunk_get_metadata, splunk_run_query`
- Ledger claims: `20`
