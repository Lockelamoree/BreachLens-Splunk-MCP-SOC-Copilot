# BreachLens Devpost Draft

This is the submission text I am using as a base for Devpost. I am keeping it plain because I want the project to sound like something I actually built and can defend, not a pile of buzzwords held together by screenshots.

## Project Name

BreachLens - Splunk MCP SOC Copilot

## Tagline

An evidence-gated SOC copilot for Splunk that turns one suspicious alert into a timeline, evidence ledger, report, response plan, and detection drafts.

## Track

Security

## Bonus Prize Target

Best Use of Splunk MCP Server

## Demo Video

[BreachLens - Splunk MCP SOC Copilot with Evidence-Gated AI](https://youtu.be/FM6DZyjPXbs)

## Short Description

I built BreachLens to answer a practical SOC question: can an AI-assisted workflow speed up triage without making unsupported claims?

The app investigates a synthetic identity-to-cloud-to-endpoint breach. It pulls alert context and related telemetry from Splunk, records the tool calls and SPL pivots, assigns stable evidence IDs, and builds a timeline, MITRE ATT&CK mapping, response plan, evidence drawer, ledger export, Markdown incident report, and detection drafts.

The important part is the evidence gate. The AI analyst note can summarize and prioritize, but it has to cite evidence IDs and concrete evidence fields that actually came back from Splunk. If the model gives unsupported IDs, invalid field references, or an invalid response, the backend falls back instead of trusting it. I would rather have a boring fallback than a confident hallucination in an incident report.

## What I Want The Demo To Show

- The first-viewport proof strip.
- Live Splunk data in normal `rest / splunk_rest` mode.
- Final MCP proof in `mcp / splunk_mcp` mode with the Splunk MCP Server app installed locally.
- NiNa running through local Ollama, with the Hugging Face model link visible.
- MCP transcript entries for:
  - `splunk_get_indexes`
  - `splunk_get_metadata`
  - `splunk_get_knowledge_objects`
  - `splunk_run_query`
- Evidence drawer with raw Splunk fields and source-event Splunk links.
- Evidence ledger and Markdown incident report exports.
- Detection drafts with SPL and Sigma-style output.

## How I Use Splunk

- `apps/breachlens_splunk/` defines the Splunk app, `breachlens` index, sourcetypes, inputs, saved searches, macros, and dashboard.
- `sample_data/` contains synthetic auth, cloud, EDR, proxy, and alert events.
- `rest` mode uses the local Splunk Enterprise container and real indexed events.
- `mcp` mode uses Splunk MCP Server for the final bonus proof.
- `sample` mode exists only so I can develop the UI without Splunk running.
- The SPL transcript is visible in the UI so the data path is auditable.
- Each transcript entry records the transport. REST calls can show the same abstract tool names, but only entries with `transport=mcp` should count as MCP proof.
- The UI keeps the four logical labels visible for demo clarity, while the backend maps them to the installed Splunk MCP Server tool names when needed.

## How I Use AI

- NiNa runs locally through Ollama with `OLLAMA_MODEL=hf.co/LockeLamora2077/NiNa:latest`.
- The UI shows the active provider and model link.
- The backend asks for structured JSON only: `status`, `narrative`, `evidence_ids`, and `claims`.
- The allowed statuses are `confirmed_compromise`, `partial_compromise`, and `needs_review`.
- The backend checks the returned evidence IDs and field references before accepting the analyst note.
- I can rerun the local evaluation with `cd backend; .\.venv\Scripts\python.exe scripts\evaluate_ai.py --alerts 3`.

## Architecture And Data Flow

The required root-level architecture diagram is here: [architecture_diagram.md](../architecture_diagram.md).

High-level flow:

1. Splunk indexes the synthetic breach telemetry.
2. The React console sends an alert investigation request to FastAPI.
3. The backend runs the evidence-gated SOC agent.
4. The agent gathers context through Splunk REST or Splunk MCP Server.
5. NiNa/Ollama can produce the analyst note, but only against supplied evidence.
6. The UI renders the proof strip, timeline, evidence drawer, MITRE mapping, response plan, SPL transcript, exports, and detections.

## Local Demo Commands

Start Splunk:

```powershell
Copy-Item .env.example .env
# Set SPLUNK_PASSWORD in .env before starting Splunk.
docker compose up -d splunk
```

Run the backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
```

Run the frontend:

```powershell
cd frontend
npm install --ignore-scripts
npm run dev
```

Check that local Splunk has live data:

```powershell
cd backend
@'
from app.config import load_settings
from app.splunk_client import make_splunk_client

client = make_splunk_client(load_settings())
print(client.name)
print(client.run_query("search index=breachlens | stats count by sourcetype", earliest="0"))
'@ | .\.venv\Scripts\python.exe -
```

Validate final MCP proof:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

## Judging Criteria Mapping

| Criterion | How I am addressing it |
| --- | --- |
| Technological implementation | FastAPI backend, React frontend, Splunk app, REST/MCP/sample clients, evidence validation, exports, detection generation, backend tests, and Playwright tests. |
| Design | A SOC console built around the investigation workflow: proof strip, alert queue, impact meter, timeline, evidence drawer, SPL transcript, and detections. |
| Potential impact | The app compresses a multi-pivot investigation into a reusable evidence package with response guidance. |
| Quality of idea | The differentiator is evidence-gated AI, not just chat over logs. |
| Splunk MCP bonus | The demo uses `splunk_mcp` and shows the required MCP tool calls with `transport=mcp` in the transcript. |

## Recording Checklist

- Record in `BREACHLENS_MODE=mcp`, not `sample`.
- Show the proof strip before and after clicking Investigate.
- Show it updating to `4/4 observed`.
- Open the SPL tab and show all four MCP tool calls.
- Open one evidence item and show the Splunk source-event link.
- Show the AI claim checks and field references in the analyst note.
- Export the ledger and report.
- Generate detections.
- Keep the video under 3 minutes.
