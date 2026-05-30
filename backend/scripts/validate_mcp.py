from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.agent import get_alerts, run_investigation
from app.config import load_settings
from app.llm import DeterministicProvider
from app.reports import build_evidence_ledger
from app.splunk_client import SplunkClientError, make_splunk_client


REQUIRED_TOOLS = [
    "splunk_get_indexes",
    "splunk_get_metadata",
    "splunk_get_knowledge_objects",
    "splunk_run_query",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate live BreachLens Splunk MCP proof.")
    parser.add_argument("--out", default="", help="Optional Markdown output path.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    args = parser.parse_args()

    settings = load_settings()
    if settings.mode != "mcp":
        raise SystemExit("BREACHLENS_MODE must be mcp for MCP validation.")
    client = make_splunk_client(settings)
    if client.name != "splunk_mcp":
        raise SystemExit(f"Expected splunk_mcp client, got {client.name}.")

    artifact = _validate(settings, client)
    if args.json:
        text = json.dumps(artifact, indent=2)
    else:
        text = _markdown_report(artifact)

    if args.out:
        output_path = Path(args.out)
        if not output_path.is_absolute():
            output_path = REPO_ROOT / output_path
        output_path.write_text(text + "\n", encoding="utf-8")
    print(text)


def _validate(settings: Any, client: Any) -> dict[str, Any]:
    errors: list[str] = []
    tool_names: list[str] = []
    try:
        tool_names = sorted(
            {
                str(tool.get("name", ""))
                for tool in client.list_tools()
                if isinstance(tool, dict) and tool.get("name")
            }
        )
    except (AttributeError, SplunkClientError) as exc:
        errors.append(f"tools/list failed: {exc}")

    calls: list[dict[str, Any]] = []
    for tool_name, function in (
        ("splunk_get_indexes", client.get_indexes),
        ("splunk_get_metadata", client.get_metadata),
        ("splunk_get_knowledge_objects", client.get_knowledge_objects),
    ):
        calls.append(_run_tool(tool_name, function))

    query = f"search index={settings.splunk_index} | head 1"
    calls.append(_run_tool("splunk_run_query", lambda: client.run_query(query, earliest="0")))

    investigation_summary: dict[str, Any] = {}
    try:
        alerts = get_alerts(client, settings.splunk_index)
        if alerts:
            investigation = run_investigation(
                client,
                alerts[0].alert_id,
                index=settings.splunk_index,
                llm_provider=DeterministicProvider(),
                splunk_ui_url=settings.splunk_ui_url,
            )
            ledger = build_evidence_ledger(investigation)
            investigation_summary = {
                "alert_id": alerts[0].alert_id,
                "investigation_id": investigation.investigation_id,
                "evidence_count": len(investigation.evidence),
                "transports": sorted({entry.transport for entry in investigation.spl_transcript}),
                "tools": sorted({entry.tool for entry in investigation.spl_transcript}),
                "ledger_claim_count": ledger["claim_count"],
            }
        else:
            errors.append("No alerts returned from Splunk MCP query path.")
    except Exception as exc:  # pragma: no cover - diagnostic script.
        errors.append(f"investigation failed: {exc}")

    observed = {call["tool"] for call in calls if call["ok"]}
    return {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "mode": settings.mode,
        "client": client.name,
        "mcp_url": _redact_url(settings.splunk_mcp_url),
        "required_tools": REQUIRED_TOOLS,
        "tools_listed": tool_names,
        "required_tools_observed": sorted(observed.intersection(REQUIRED_TOOLS)),
        "all_required_tools_observed": all(tool in observed for tool in REQUIRED_TOOLS),
        "calls": calls,
        "investigation": investigation_summary,
        "errors": errors,
    }


def _run_tool(tool_name: str, function: Any) -> dict[str, Any]:
    try:
        rows = function()
    except Exception as exc:  # pragma: no cover - diagnostic script.
        return {"tool": tool_name, "ok": False, "result_count": 0, "error": str(exc)}
    return {"tool": tool_name, "ok": True, "result_count": len(rows), "error": ""}


def _redact_url(value: str) -> str:
    return value.split("?", 1)[0] if value else ""


def _markdown_report(artifact: dict[str, Any]) -> str:
    lines = [
        "# BreachLens Live MCP Validation",
        "",
        f"Generated at: `{artifact['generated_at_utc']}`",
        f"Runtime: `{artifact['mode']}` / `{artifact['client']}`",
        f"MCP endpoint: `{artifact['mcp_url']}`",
        f"All required tools observed: `{artifact['all_required_tools_observed']}`",
        "",
        "## Required Tool Calls",
        "",
        "| Tool | OK | Result Count | Error |",
        "| --- | --- | ---: | --- |",
    ]
    for call in artifact["calls"]:
        lines.append(
            f"| `{call['tool']}` | {call['ok']} | {call['result_count']} | {str(call['error']).replace('|', '\\|')} |"
        )
    lines.extend(["", "## Investigation Proof", ""])
    if artifact["investigation"]:
        investigation = artifact["investigation"]
        lines.extend(
            [
                f"- Alert: `{investigation['alert_id']}`",
                f"- Investigation: `{investigation['investigation_id']}`",
                f"- Evidence items: `{investigation['evidence_count']}`",
                f"- Transcript transports: `{', '.join(investigation['transports'])}`",
                f"- Transcript tools: `{', '.join(investigation['tools'])}`",
                f"- Ledger claims: `{investigation['ledger_claim_count']}`",
            ]
        )
    else:
        lines.append("- No investigation proof generated.")
    if artifact["errors"]:
        lines.extend(["", "## Errors", ""])
        for error in artifact["errors"]:
            lines.append(f"- {error}")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
