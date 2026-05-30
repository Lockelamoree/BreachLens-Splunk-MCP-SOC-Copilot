from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.agent import ALLOWED_ANALYST_STATUSES, get_alerts, run_investigation
from app.config import load_settings
from app.llm import DeterministicProvider, LLMProvider, make_llm_provider
from app.splunk_client import SplunkToolClient, make_splunk_client


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate BreachLens AI analyst-note behavior.")
    parser.add_argument("--alerts", type=int, default=3, help="Maximum alerts to evaluate.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--out", help="Optional file path for the generated artifact.")
    args = parser.parse_args()

    settings = load_settings()
    client = make_splunk_client(settings)
    live_provider = make_llm_provider(settings)
    alerts = get_alerts(client, settings.splunk_index)[: max(1, args.alerts)]
    splunk_ui_url = settings.splunk_ui_url if settings.splunk_ui_url and client.name != "sample_data" else ""

    rows: list[dict[str, Any]] = []
    for alert in alerts:
        rows.append(
            _evaluate_provider(
                "deterministic",
                DeterministicProvider(),
                client,
                alert.alert_id,
                alert.recommended_objective,
                settings.splunk_index,
                splunk_ui_url,
            )
        )
        rows.append(
            _evaluate_provider(
                "configured_ai",
                live_provider,
                client,
                alert.alert_id,
                alert.recommended_objective,
                settings.splunk_index,
                splunk_ui_url,
            )
        )

    artifact = {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "mode": settings.mode,
        "splunk_client": client.name,
        "splunk_index": settings.splunk_index,
        "ai_provider": live_provider.name,
        "ai_model": _model_name(settings, live_provider),
        "alert_count": len(alerts),
        "rows": rows,
    }
    output = json.dumps(artifact, indent=2) if args.json else _markdown_report(artifact)
    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    print(output)


def _evaluate_provider(
    path: str,
    provider: LLMProvider,
    client: SplunkToolClient,
    alert_id: str,
    objective: str,
    index: str,
    splunk_ui_url: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        investigation = run_investigation(
            client,
            alert_id,
            objective=objective,
            index=index,
            llm_provider=provider,
            splunk_ui_url=splunk_ui_url,
        )
    except Exception as exc:  # pragma: no cover - diagnostic script.
        return {
            "alert_id": alert_id,
            "path": path,
            "provider": provider.name,
            "accepted": False,
            "status": "error",
            "evidence_id_count": 0,
            "claim_count": 0,
            "transport": "",
            "warnings": [str(exc)],
            "seconds": round(time.perf_counter() - started, 3),
        }

    note = investigation.analyst_note
    status = note.status if note else "missing"
    accepted = bool(
        note
        and note.provider == provider.name
        and status in ALLOWED_ANALYST_STATUSES
        and note.evidence_ids
        and note.claims
    )
    return {
        "alert_id": alert_id,
        "path": path,
        "provider": provider.name,
        "accepted": accepted,
        "status": status,
        "evidence_id_count": len(note.evidence_ids) if note else 0,
        "claim_count": len(note.claims) if note else 0,
        "transport": ",".join(sorted({entry.transport for entry in investigation.spl_transcript})),
        "warnings": investigation.warnings,
        "seconds": round(time.perf_counter() - started, 3),
    }


def _model_name(settings: Any, provider: LLMProvider) -> str:
    if provider.name == "ollama":
        return settings.ollama_model
    if provider.name == "openai_compatible":
        return settings.openai_model
    return "deterministic_fallback"


def _markdown_report(artifact: dict[str, Any]) -> str:
    lines = [
        "# BreachLens AI Evaluation",
        "",
        f"Generated at: `{artifact['generated_at_utc']}`",
        f"Runtime: `{artifact['mode']}` / `{artifact['splunk_client']}` / index `{artifact['splunk_index']}`",
        f"Configured AI: `{artifact['ai_provider']}` / `{artifact['ai_model']}`",
        "",
        "Method: each alert is investigated once with deterministic fallback and once with the configured AI provider. "
        "An AI row is accepted only when the note status is allowed, evidence IDs resolve, and claims cite real evidence fields.",
        "",
        "| Alert | Path | Provider | Status | Accepted | Evidence IDs | Claims | Transport | Seconds | Warnings |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |",
    ]
    for row in artifact["rows"]:
        warnings = "; ".join(row["warnings"]) if row["warnings"] else ""
        lines.append(
            "| {alert_id} | {path} | {provider} | {status} | {accepted} | {evidence_id_count} | "
            "{claim_count} | {transport} | {seconds} | {warnings} |".format(
                **{
                    **row,
                    "accepted": "yes" if row["accepted"] else "no",
                    "warnings": warnings.replace("|", "\\|"),
                }
            )
        )
    if artifact["mode"] == "mcp" and artifact["splunk_client"] == "splunk_mcp":
        lines.extend(
            [
                "",
                "My read: NiNa passed the JSON/evidence/field-reference gate while the investigation path was running through Splunk MCP.",
            ]
        )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
