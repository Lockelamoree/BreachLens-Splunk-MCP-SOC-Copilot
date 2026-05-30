# BreachLens

BreachLens is a Splunk MCP SOC copilot built for the Splunk Agentic Ops Hackathon Security track. It investigates a synthetic multi-stage breach, keeps every claim tied to Splunk evidence, and gives analysts a polished incident timeline, MITRE mapping, remediation plan, SPL transcript, and detection drafts.

![BreachLens investigation console](docs/breachlens-ui-real-splunk.png)

## Submission Snapshot

- **Devpost track:** Security
- **Bonus target:** Best Use of Splunk MCP Server
- **Primary workflow:** Alert triage -> Splunk MCP pivots -> evidence-gated AI note -> incident timeline -> ledger/report/detection drafts
- **Live AI model:** NiNa through local Ollama, with model link exposed in the UI: [LockeLamora2077/NiNa](https://huggingface.co/LockeLamora2077/NiNa)
- **Judge-facing proof:** first-viewport strip showing `Splunk MCP live`, `mcp`, `splunk_mcp`, `NiNa`, `4/4 observed`, and evidence count

For copy-ready Devpost text and recording notes, see [docs/devpost_submission.md](docs/devpost_submission.md).

## Why It Should Score

- **Security impact:** Reduces alert triage from scattered SPL pivots to an evidence-backed investigation package.
- **Splunk AI/MCP fit:** Uses Splunk MCP Server as the tool layer for safe agent access to Splunk searches, indexes, metadata, and knowledge objects.
- **Design:** Gives judges a complete SOC workflow rather than a chatbot bolted to logs like a "temporary" firewall rule that somehow became architecture.
- **Implementation:** Local Splunk Enterprise, a Splunk app, FastAPI backend, React console, tests, synthetic data, and reproducible setup.

## Hackathon Criteria Fit

- **Track:** Security. BreachLens helps analysts detect, investigate, and respond to identity-to-cloud-to-endpoint compromise using AI-assisted workflows and Splunk evidence.
- **Technological implementation:** FastAPI backend, React/Vite console, Splunk app artifacts, MCP/REST/sample clients, evidence validation, exports, backend unit tests, and Playwright smoke tests.
- **Design:** The first screen is the SOC workflow: alert queue, source badges, impact meter, timeline, ATT&CK mapping, response actions, evidence drawer, SPL transcript, and detection drafts.
- **Potential impact:** Compresses a multi-pivot incident investigation into an evidence-backed package with reusable detections and response guidance.
- **Quality of idea:** The core differentiator is evidence-gated AI: every timeline, MITRE, response, and report claim must trace back to Splunk evidence IDs.
- **Bonus target:** Best Use of Splunk MCP Server. The demo should visibly show `mcp`, `splunk_mcp`, and transcript entries for `splunk_get_indexes`, `splunk_get_metadata`, `splunk_get_knowledge_objects`, and `splunk_run_query`.

## How Splunk And AI Are Integrated

1. The Splunk app in `apps/breachlens_splunk/` defines the `breachlens` index, JSON sourcetypes, saved searches, macros, and dashboard.
2. Splunk indexes synthetic auth, cloud, endpoint, proxy, and alert events from `sample_data/`.
3. The FastAPI backend can run in `mcp`, `rest`, or `sample` mode. The final demo should use `mcp`.
4. In MCP mode, the agent calls Splunk MCP Server tools: `splunk_get_indexes`, `splunk_get_metadata`, `splunk_get_knowledge_objects`, and `splunk_run_query`.
5. The AI analyst note uses Ollama/OpenAI-compatible JSON output, but the backend accepts only evidence-referenced claims and falls back deterministically if the model is unavailable or unsafe.

## Repository Layout

```text
apps/breachlens_splunk/   Splunk app with index, sourcetypes, saved searches, dashboard
backend/                  FastAPI API, Splunk MCP/REST clients, agent, tests
frontend/                 React/Vite SOC console and Playwright smoke test
sample_data/              Synthetic multi-stage breach JSONL logs
docs/                     Demo script and submission checklist
architecture_diagram.md   Root-level architecture diagram for Devpost
```

## Quick Start

1. Copy the environment template.

   ```powershell
   Copy-Item .env.example .env
   ```

   The backend loads `.env` automatically. Set a local `SPLUNK_PASSWORD` in `.env` before starting Splunk. The template defaults to `BREACHLENS_MODE=rest` so the app uses live data from the local Splunk container.

2. Start local Splunk Enterprise.

   ```powershell
   docker compose up -d splunk
   ```

3. Open Splunk at `http://127.0.0.1:18000` and log in as `admin` with `SPLUNK_PASSWORD` from `.env`.

4. Verify Splunk has indexed the live demo data.

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

5. For the final MCP demo, install Splunk MCP Server from Splunkbase, enable `mcp_tool_execute` for the demo role, generate an encrypted MCP token, and set:

   ```text
   BREACHLENS_MODE=mcp
   SPLUNK_MCP_URL=<endpoint copied from the Splunk MCP Server app>
   SPLUNK_MCP_TOKEN=<encrypted token copied once from the Splunk MCP Server app>
   ```

   Optional: set `OLLAMA_BASE_URL` or `OPENAI_COMPATIBLE_BASE_URL` plus `OPENAI_API_KEY` to show a live evidence-gated AI analyst note. Without a model provider, BreachLens uses deterministic fallback reasoning and clearly labels it in the UI.

6. Run the backend.

   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8080
   ```

7. Run the frontend.

   ```powershell
   cd frontend
   npm install --ignore-scripts
   npm run dev
   ```

8. Open `http://localhost:5173`.

## Demo Without Splunk

Set `BREACHLENS_MODE=sample` to run the API against `sample_data/` without Splunk. This is useful for frontend and agent development only. The normal local demo should use `rest` for live Splunk data, and the hackathon recording should use `mcp` so the Splunk MCP Server integration is visible.

## MCP Demo Validation

After starting Splunk, the MCP Server app, the backend, and the frontend in MCP mode, run the live browser validation:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

This captures `docs/breachlens-ui-real-splunk.png`, downloads the evidence ledger and incident report, and verifies the first-viewport proof strip shows `Splunk MCP live`, `mcp`, `splunk_mcp`, `NiNa`, `4/4 observed`, evidence items, and the Splunk MCP tool transcript. The sample mode is intentionally available for development, but it should not be used for the final hackathon recording.

## API

- `GET /api/alerts`
- `POST /api/investigations` with `{ "alert_id": "BLS-2026-001", "objective": "Determine account takeover and blast radius" }`
- `GET /api/investigations/{id}`
- `POST /api/detections` with `{ "investigation_id": "<id>" }`
- `GET /api/investigations/{id}/ledger`
- `GET /api/investigations/{id}/report.md`

## Judge Demo Flow

1. Confirm the UI source badges show Splunk-backed mode.
2. Run the critical impossible-travel alert investigation.
3. Show the Impact Meter: triage compression, affected assets, verified evidence, and package readiness.
4. Click evidence chips to inspect raw Splunk fields and producing query IDs.
5. Export the Evidence Ledger JSON and Markdown incident report.
6. Generate detections and show the reusable SPL/Sigma-style drafts.

## Tests

Backend tests use the standard library test runner for the core agent path:

```powershell
cd backend
python -m unittest discover tests
```

Frontend smoke tests are Playwright based:

```powershell
cd frontend
npm run test:e2e
```

## Security Notes

- No secrets are committed. `.env` is ignored.
- MCP tokens are encrypted Splunk MCP tokens and must be generated in the Splunk MCP Server app.
- AI output is evidence-gated: timeline, MITRE mappings, and recommendations must reference evidence IDs returned from Splunk results.
- The backend rejects obvious prompt-injection objectives such as requests to ignore prior instructions or reveal system prompts.
