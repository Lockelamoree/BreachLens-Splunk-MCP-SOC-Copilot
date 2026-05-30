# Hackathon Criteria Review

These are my own submission notes. I am keeping the weak spots visible because they matter for the final recording.

Source criteria: [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) and official rules, checked during the build.

## Submission Fit

| Requirement | My status | Evidence | What I still need to do |
| --- | --- | --- | --- |
| Security track fit | Good | BreachLens investigates identity, cloud, endpoint, and proxy telemetry, then produces evidence, detections, MITRE mapping, and response actions. | Say "Security track" clearly in the Devpost text and video. |
| Uses Splunk data | Good | Local Splunk app, `breachlens` index, sourcetypes, saved searches, dashboard, REST client, MCP client, and live Splunk evidence links. | Final recording should not use `sample` mode. |
| Uses AI / agentic capability | Good | The agent runs pivots, builds an evidence chain, and uses NiNa/Ollama for a constrained analyst note. | Record with NiNa visible, not deterministic fallback. |
| Required tools/APIs | Needs final proof | `McpSplunkClient` is implemented and the UI/test expect `splunk_mcp`. | Install/configure Splunk MCP Server locally and capture `mcp / splunk_mcp`. |
| Public repo | Good | Source, docs, sample data, architecture diagram, and license are pushed. | Keep secrets out before every push. |
| README/configs/data | Good | README, `.env.example`, `requirements.txt`, `package.json`, Splunk app, and sample data are included. | Add final MCP validation output after recording if useful. |
| Architecture diagram | Good | `architecture_diagram.md` is at the repo root. | Optional: export a PNG for Devpost readability. |
| Demo video | Pending | Script exists. | Record a public video under 3 minutes. |
| No secrets | Good | `.env` is ignored and quick scans have not found committed tokens. | Re-scan before final submission. |

## Judging Criteria

| Criterion | My read | Why |
| --- | ---: | --- |
| Technological implementation | 8/10 | Backend, frontend, Splunk app, live REST data, MCP client, evidence validation, exports, detections, and tests are working. Full MCP validation is the remaining proof point. |
| Design | 8/10 | The UI is an actual SOC workflow with a proof strip, timeline, evidence drawer, SPL transcript, and detections. |
| Potential impact | 8/10 | It turns a multi-pivot investigation into an evidence package an analyst can review and export. |
| Quality of idea | 7/10 | SOC copilots are a crowded idea, but the evidence gate is the part that makes this more serious. |
| Splunk MCP bonus | 7/10 until final proof | The client and UI proof path exist. The recording needs live `splunk_mcp` mode. |

## Final Proof I Need

Before recording:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

The output and video should show:

```text
Splunk MCP live
mcp
splunk_mcp
NiNa
4/4 observed
splunk_get_indexes
splunk_get_metadata
splunk_get_knowledge_objects
splunk_run_query
```
