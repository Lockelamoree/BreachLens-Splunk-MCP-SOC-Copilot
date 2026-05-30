# Hackathon Criteria Review

Source criteria: [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/) and [official rules](https://splunk.devpost.com/rules), fetched May 29, 2026.

## Submission Fit

| Requirement | Status | Evidence | Risk / action |
| --- | --- | --- | --- |
| Security track fit | Pass | BreachLens investigates threats, produces evidence, detections, MITRE mapping, and response actions. | State "Security track" in Devpost text and video opening. |
| Uses Splunk data | Pass | Splunk app, index, sourcetypes, saved searches, dashboard, MCP/REST/sample clients. | Final demo should run against Splunk, not sample mode. |
| Uses AI / agentic capability | Pass with demo proof needed | Agent workflow, MCP tool orchestration, evidence gating, and AI analyst note are wired into API/UI/report output. | For strongest scoring, record with an Ollama or OpenAI-compatible provider configured so the analyst note is live model output rather than deterministic fallback. |
| Required APIs/SDKs/tools | Risk | `McpSplunkClient` calls Splunk MCP Server tools; live validation now expects `splunk_mcp`. | Capture video and screenshot with `mcp` / `splunk_mcp` badges visible. |
| Public open-source repo | Pending | Local repo has source files and MIT license. | Publish repo and ensure license appears in repository metadata. |
| README, dependencies, configs, datasets | Pass | `README.md`, `.env.example`, `requirements.txt`, `package.json`, `sample_data/`. | Add exact MCP validation output to README after final live run. |
| Architecture diagram at repo root | Pass | `architecture_diagram.md`. | Optional: export Mermaid to PNG for Devpost readability. |
| Demo video under 3 minutes | Pending | `docs/demo_script.md` exists. | Record public video with MCP badges and SPL transcript. |
| No secrets / third-party rights | Pass | `.env` ignored; `.env.example` contains blanks. | Re-scan before publishing. |

## Judging Criteria

| Criterion | Current score | Why | Highest-impact lift |
| --- | ---: | --- | --- |
| Technological Implementation | 8/10 | Working backend, frontend, Splunk app, tests, evidence validation, AI analyst note, reports, exports. | Prove MCP end-to-end and add one command/script that validates Splunk indexing plus MCP tool calls. |
| Design | 8/10 | Polished SOC console, clear timeline, metrics, evidence drawer, exports. | Add a short demo-proof strip or make MCP/tool proof visually impossible to miss. |
| Potential Impact | 8/10 | Triage compression, investigation package, detections, response guidance. | Support the "20m -> <2m" claim with a before/after workflow in README/video. |
| Quality of the Idea | 7/10 | Strong SOC copilot idea with evidence gating; category is competitive. | Emphasize evidence-gated AI as the differentiator from generic log chatbots. |
| Best Use of Splunk MCP Server bonus | 7/10 | MCP client exists and transcripts expose MCP-style tool calls. | Record final demo in MCP mode and include live validation output showing `splunk_mcp`. |

## Final Demo Proof Checklist

Run with Splunk MCP mode before recording:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
npm run test:live
```

The output should include the source badges, exported ledger/report filenames, and MCP proof tool names:

```text
splunk_get_indexes
splunk_get_metadata
splunk_get_knowledge_objects
splunk_run_query
```
