# BreachLens Devpost Submission Brief

## Project Name

BreachLens - Splunk MCP SOC Copilot

## Tagline

Evidence-gated AI investigation for Splunk: turn a suspicious alert into a reproducible SOC package with MCP tool proof, timeline, MITRE mapping, response actions, exports, and detection drafts.

## Track

Security

## Bonus Prize Target

Best Use of Splunk MCP Server

## Short Description

BreachLens is a Splunk-native SOC copilot that investigates a synthetic identity-to-cloud-to-endpoint breach. The backend uses Splunk MCP Server as the controlled tool layer for index discovery, metadata review, knowledge object review, and SPL searches. The UI turns those results into a timeline, evidence drawer, MITRE ATT&CK mapping, response plan, evidence ledger, Markdown incident report, and detection drafts.

The key idea is evidence-gated AI: model output is allowed to summarize and prioritize, but claims must reference evidence IDs returned from Splunk-backed searches. If the model is unavailable or returns unsupported output, BreachLens falls back to deterministic reasoning instead of inventing facts. Nothing says "incident response" like refusing to hallucinate a shell that never existed.

## What The Demo Must Show

- First viewport proof strip showing `Splunk MCP live`, `mcp`, `splunk_mcp`, `NiNa`, `4/4 observed`, and populated evidence items.
- Live Ollama model label for NiNa and Hugging Face link: https://huggingface.co/LockeLamora2077/NiNa
- SPL transcript entries for:
  - `splunk_get_indexes`
  - `splunk_get_metadata`
  - `splunk_get_knowledge_objects`
  - `splunk_run_query`
- Evidence drawer with raw Splunk fields and source-event Splunk links.
- Exported evidence ledger and Markdown incident report.
- Generated detection drafts with SPL and Sigma-style content.

## How It Uses Splunk

- `apps/breachlens_splunk/` defines the Splunk app, `breachlens` index, sourcetypes, inputs, saved searches, macros, and dashboard.
- `sample_data/` contains synthetic auth, cloud, EDR, proxy, and alert JSONL events.
- The backend supports three clients:
  - `rest`: local Splunk live-data mode for ordinary demo validation.
  - `mcp`: Splunk MCP Server tool calls for the final hackathon demo and bonus proof.
  - `sample`: local sample-data development mode.
- The investigation transcript records every Splunk tool call and SPL query so judges can verify the data path.

## How AI Is Integrated

- NiNa runs through local Ollama with `OLLAMA_MODEL=hf.co/LockeLamora2077/NiNa:latest`.
- The UI displays the active provider and model link in the first viewport.
- The backend asks the model for structured JSON only: `status`, `narrative`, and `evidence_ids`.
- The model is constrained to statuses: `confirmed_compromise`, `partial_compromise`, or `needs_review`.
- The backend rejects unsupported evidence IDs and falls back to deterministic output if the model response is invalid.

## Architecture And Data Flow

See the required root-level diagram: [architecture_diagram.md](../architecture_diagram.md).

High-level flow:

1. Splunk indexes the synthetic breach telemetry.
2. The React console sends an alert investigation request to FastAPI.
3. The evidence-gated SOC agent uses Splunk MCP tools to gather context and run pivots.
4. The optional Ollama/NiNa analyst note summarizes only supplied evidence.
5. The UI renders the proof strip, timeline, MITRE mapping, response plan, evidence drawer, SPL transcript, and exports.

## Local Demo Commands

Start Splunk and use live local data:

```powershell
Copy-Item .env.example .env
# Set SPLUNK_PASSWORD in .env before starting Splunk.
docker compose up -d splunk
```

Run backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
```

Run frontend:

```powershell
cd frontend
npm install --ignore-scripts
npm run dev
```

Validate live Splunk data through the backend:

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

Validate final live MCP proof:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

## Judging Criteria Mapping

| Criterion | BreachLens evidence |
| --- | --- |
| Technological implementation | FastAPI backend, React/Vite frontend, Splunk app, MCP/REST/sample clients, evidence validation, reports, detections, backend tests, Playwright tests. |
| Design | First-viewport proof strip, SOC alert queue, impact meter, incident timeline, evidence drawer, SPL transcript, detection workflow, clean Arasaka-inspired visual system. |
| Potential impact | Compresses multi-pivot SOC triage into an evidence-backed incident package with immediate response guidance and reusable detections. |
| Quality of idea | Evidence-gated AI prevents unsupported claims and keeps every timeline/response/report item tied to Splunk evidence IDs. |
| Splunk MCP bonus | Live `splunk_mcp` mode and transcript proof for index, metadata, knowledge object, and SPL query tools. |

## Recording Checklist

- Record in `BREACHLENS_MODE=mcp`, not `sample`.
- Keep the proof strip visible before and after clicking Investigate.
- Show the strip updating to `4/4 observed`.
- Click the SPL tab and show all four MCP tool calls.
- Open one evidence item and click/show the Splunk source-event link.
- Export the ledger and report.
- Generate detections.
- Keep the video under 3 minutes.
