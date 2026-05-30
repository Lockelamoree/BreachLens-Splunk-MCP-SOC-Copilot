from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .agent import get_alerts, run_investigation
from .config import load_settings
from .detections import generate_detection_drafts
from .domain import Investigation
from .evidence import EvidenceValidationError
from .llm import make_llm_provider
from .reports import build_evidence_ledger, build_incident_report_markdown
from .splunk_client import SplunkClientError, make_splunk_client


settings = load_settings()
client = make_splunk_client(settings)
llm_provider = make_llm_provider(settings)
investigation_store: dict[str, Investigation] = {}

app = FastAPI(title="BreachLens API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


class InvestigationRequest(BaseModel):
    alert_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]
    objective: Annotated[str | None, Field(default=None, max_length=500)] = None


class DetectionRequest(BaseModel):
    investigation_id: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "mode": settings.mode,
        "splunk_client": client.name,
        "splunk_index": settings.splunk_index,
        "splunk_ui_url": settings.splunk_ui_url,
        "splunk_evidence_links_enabled": _splunk_evidence_links_enabled(),
        "ai_provider": llm_provider.name,
        "ai_model": _ai_model_name(),
        "ai_model_url": _ai_model_url(),
        "investigations_in_memory": len(investigation_store),
    }


def _ai_model_name() -> str:
    if llm_provider.name == "ollama":
        return settings.ollama_model
    if llm_provider.name == "openai_compatible":
        return settings.openai_model
    return "deterministic_fallback"


def _ai_model_url() -> str:
    model = _ai_model_name()
    if model.startswith("hf.co/"):
        repo = model.removeprefix("hf.co/").split(":", 1)[0]
        return f"https://huggingface.co/{repo}"
    return ""


def _splunk_evidence_links_enabled() -> bool:
    return bool(settings.splunk_ui_url and client.name != "sample_data")


def _splunk_ui_url_for_evidence() -> str:
    if not _splunk_evidence_links_enabled():
        return ""
    return settings.splunk_ui_url


@app.get("/api/alerts")
def list_alerts() -> dict:
    try:
        alerts = get_alerts(client, settings.splunk_index)
    except SplunkClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"alerts": [alert.to_dict() for alert in alerts]}


@app.post("/api/investigations")
def create_investigation(request: InvestigationRequest) -> dict:
    try:
        investigation = run_investigation(
            client,
            alert_id=request.alert_id,
            objective=request.objective,
            index=settings.splunk_index,
            llm_provider=llm_provider,
            splunk_ui_url=_splunk_ui_url_for_evidence(),
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SplunkClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    investigation_store[investigation.investigation_id] = investigation
    return investigation.to_dict()


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict:
    investigation = investigation_store.get(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation.to_dict()


@app.post("/api/detections")
def create_detections(request: DetectionRequest) -> dict:
    investigation = investigation_store.get(request.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    drafts = generate_detection_drafts(investigation)
    return {
        "investigation_id": investigation.investigation_id,
        "detections": [draft.to_dict() for draft in drafts],
    }


@app.get("/api/investigations/{investigation_id}/ledger")
def get_evidence_ledger(investigation_id: str) -> dict:
    investigation = investigation_store.get(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return build_evidence_ledger(investigation)


@app.get("/api/investigations/{investigation_id}/report.md", response_class=PlainTextResponse)
def get_incident_report(investigation_id: str) -> str:
    investigation = investigation_store.get(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return build_incident_report_markdown(investigation)
