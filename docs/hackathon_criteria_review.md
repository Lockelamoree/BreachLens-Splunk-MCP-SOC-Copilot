# Hackathon Criteria Review

These are my own submission notes. I am keeping the weak spots visible because they matter for the final submission.

Source criteria: [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) and official rules, checked during the build.

## Submission Fit

| Requirement | My status | Evidence | What I still need to do |
| --- | --- | --- | --- |
| Security track fit | Good | BreachLens investigates identity, cloud, endpoint, and proxy telemetry, then produces evidence, detections, MITRE mapping, and response actions. | Say "Security track" clearly in the Devpost text. |
| Uses Splunk data | Good | Local Splunk app, `breachlens` index, sourcetypes, saved searches, dashboard, REST client, MCP client, and live Splunk evidence links. | Keep the demo link visible in Devpost. |
| Uses AI / agentic capability | Good | The agent runs pivots, builds an evidence chain, and uses NiNa/Ollama for a constrained analyst note with field-backed claims. | Keep NiNa visible in the video link and description. |
| Required tools/APIs | Good | `McpSplunkClient` is implemented, Splunk MCP Server 1.2.0 is installed locally, and `docs/mcp_validation.md` shows `mcp / splunk_mcp` with all required tool calls observed. | Keep the MCP proof doc linked in the repo. |
| Public repo | Good | Source, docs, sample data, architecture diagram, and license are pushed. | Keep secrets out before every push. |
| README/configs/data | Good | README, `.env.example`, `requirements.txt`, `package.json`, Splunk app, sample data, AI evaluation, MCP validation, and security boundaries are included. | Keep secrets out before any follow-up push. |
| Architecture diagram | Good | `architecture_diagram.md` is at the repo root. | Optional: export a PNG for Devpost readability. |
| Demo video | Good | Public demo is linked in README and the Devpost draft: https://youtu.be/FM6DZyjPXbs | Optional: improve the YouTube thumbnail to show `4/4 observed` instead of the pre-investigation state. |
| No secrets | Good | `.env` is ignored and quick scans have not found committed tokens. | Re-scan before final submission. |

## Judging Criteria

| Criterion | My read | Why |
| --- | ---: | --- |
| Technological implementation | 8.8/10 | Backend, frontend, Splunk app, live Splunk data, MCP client, evidence validation, field-backed AI claims, exports, detections, live MCP validation, and tests are working. |
| Design | 8/10 | The UI is an actual SOC workflow with a proof strip, timeline, evidence drawer, SPL transcript, and detections. |
| Potential impact | 8/10 | It turns a multi-pivot investigation into an evidence package an analyst can review and export. |
| Quality of idea | 7/10 | SOC copilots are a crowded idea, but the evidence gate is the part that makes this more serious. |
| Splunk MCP bonus | 8.6/10 | Live validation now shows `mcp / splunk_mcp`, all four required MCP tool calls, `transport=mcp`, and 23 Splunk-backed evidence items. |

## AI Evaluation Status

Current local evaluation: [docs/ai_evaluation.md](ai_evaluation.md)

NiNa/Ollama accepted all three evaluated alerts in the latest run. "Accepted" means the model returned valid JSON, an allowed status, valid evidence IDs, and claims with real evidence field references. Deterministic rows are intentionally not counted as AI acceptance.

## Final Proof To Recheck

Before any last-minute rerecording or Devpost edit, rerun:

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
