from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .domain import Investigation


@dataclass(frozen=True)
class LedgerClaim:
    claim_id: str
    claim_type: str
    claim: str
    evidence_ids: list[str]
    spl_query_ids: list[str]
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "claim": self.claim,
            "evidence_ids": self.evidence_ids,
            "spl_query_ids": self.spl_query_ids,
            "confidence": self.confidence,
        }


def build_evidence_ledger(investigation: Investigation) -> dict[str, Any]:
    evidence_by_id = {item.id: item for item in investigation.evidence}
    claims: list[LedgerClaim] = []

    for index, event in enumerate(investigation.timeline, start=1):
        claims.append(
            LedgerClaim(
                claim_id=f"CL-TL-{index:02d}",
                claim_type="timeline",
                claim=f"{event.phase}: {event.title}. {event.narrative}",
                evidence_ids=event.evidence_ids,
                spl_query_ids=_query_ids(event.evidence_ids, evidence_by_id),
                confidence=investigation.confidence,
            )
        )

    for index, mapping in enumerate(investigation.mitre, start=1):
        claims.append(
            LedgerClaim(
                claim_id=f"CL-MT-{index:02d}",
                claim_type="mitre",
                claim=f"{mapping.technique_id} {mapping.technique}: {mapping.rationale}",
                evidence_ids=mapping.evidence_ids,
                spl_query_ids=_query_ids(mapping.evidence_ids, evidence_by_id),
                confidence=investigation.confidence,
            )
        )

    for index, action in enumerate(investigation.response_actions, start=1):
        claims.append(
            LedgerClaim(
                claim_id=f"CL-RA-{index:02d}",
                claim_type="response_action",
                claim=f"{action.priority} {action.owner}: {action.action}",
                evidence_ids=action.evidence_ids,
                spl_query_ids=_query_ids(action.evidence_ids, evidence_by_id),
                confidence=investigation.confidence,
            )
        )

    if investigation.analyst_note:
        claims.append(
            LedgerClaim(
                claim_id="CL-AI-01",
                claim_type="ai_analyst_note",
                claim=investigation.analyst_note.narrative,
                evidence_ids=investigation.analyst_note.evidence_ids,
                spl_query_ids=_query_ids(investigation.analyst_note.evidence_ids, evidence_by_id),
                confidence=investigation.confidence,
            )
        )

    evidence_hashes = {
        item.id: sha256(json.dumps(item.fields, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        for item in investigation.evidence
    }

    return {
        "investigation_id": investigation.investigation_id,
        "alert_id": investigation.alert.alert_id,
        "summary": investigation.summary,
        "confidence": investigation.confidence,
        "claim_count": len(claims),
        "evidence_count": len(investigation.evidence),
        "query_count": len(investigation.spl_transcript),
        "analyst_note": investigation.analyst_note.to_dict() if investigation.analyst_note else None,
        "claims": [claim.to_dict() for claim in claims],
        "evidence": [item.to_dict() for item in investigation.evidence],
        "evidence_hashes": evidence_hashes,
        "spl_transcript": [item.to_dict() for item in investigation.spl_transcript],
    }


def build_incident_report_markdown(investigation: Investigation) -> str:
    ledger = build_evidence_ledger(investigation)
    evidence_by_id = {item.id: item for item in investigation.evidence}
    lines = [
        f"# BreachLens Incident Report: {investigation.alert.alert_id}",
        "",
        f"**Investigation:** `{investigation.investigation_id}`",
        f"**Confidence:** {investigation.confidence}",
        f"**User:** {investigation.alert.user}",
        f"**Host:** {investigation.alert.host}",
        f"**Source IP:** {investigation.alert.src_ip}",
        "",
        "## Executive Summary",
        "",
        investigation.summary,
        "",
        "## AI Analyst Note",
        "",
        (
            f"Provider: `{investigation.analyst_note.provider}`; "
            f"status: `{investigation.analyst_note.status}`"
            if investigation.analyst_note
            else "Provider: none"
        ),
        "",
        investigation.analyst_note.narrative if investigation.analyst_note else "No analyst note generated.",
        "",
        (
            f"Evidence: {_evidence_links(investigation.analyst_note.evidence_ids, evidence_by_id)}"
            if investigation.analyst_note
            else ""
        ),
        "",
        "## Impact Meter",
        "",
        f"- Evidence items: {len(investigation.evidence)}",
        f"- SPL/tool transcript entries: {len(investigation.spl_transcript)}",
        f"- ATT&CK mappings: {len(investigation.mitre)}",
        f"- Response actions: {len(investigation.response_actions)}",
        f"- Detection drafts available: 3",
        "- Estimated triage compression: 20 minutes to under 2 minutes for the demo scenario",
        "",
        "## Timeline",
        "",
    ]

    for event in investigation.timeline:
        lines.extend(
            [
                f"### {event.time} - {event.phase}",
                "",
                f"**{event.title}**",
                "",
                event.narrative,
                "",
                f"Evidence: {_evidence_links(event.evidence_ids, evidence_by_id)}",
                "",
            ]
        )

    lines.extend(["## MITRE ATT&CK", ""])
    for mapping in investigation.mitre:
        lines.append(
            f"- `{mapping.technique_id}` **{mapping.technique}** ({mapping.tactic}) - "
            f"{mapping.rationale} Evidence: {_evidence_links(mapping.evidence_ids, evidence_by_id)}"
        )

    lines.extend(["", "## Response Actions", ""])
    for action in investigation.response_actions:
        lines.append(
            f"- **{action.priority} / {action.owner}:** {action.action} "
            f"Evidence: {_evidence_links(action.evidence_ids, evidence_by_id)}"
        )

    lines.extend(["", "## Evidence Ledger", ""])
    for claim in ledger["claims"]:
        lines.append(
            f"- `{claim['claim_id']}` {claim['claim_type']}: {claim['claim']} "
            f"Evidence: {_evidence_links(claim['evidence_ids'], evidence_by_id)}; "
            f"Queries: {', '.join(claim['spl_query_ids'])}"
        )

    lines.extend(["", "## SPL Transcript", ""])
    for entry in investigation.spl_transcript:
        lines.extend(
            [
                f"### {entry.query_id} - {entry.tool}",
                "",
                entry.purpose,
                "",
                "```spl",
                entry.spl,
                "```",
                "",
            ]
        )

    return "\n".join(lines)


def _query_ids(evidence_ids: list[str], evidence_by_id: dict) -> list[str]:
    return sorted({evidence_by_id[item].query_id for item in evidence_ids if item in evidence_by_id})


def _evidence_links(evidence_ids: list[str], evidence_by_id: dict) -> str:
    links = []
    for evidence_id in evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence and evidence.splunk_url:
            links.append(f"[`{evidence_id}`]({evidence.splunk_url})")
        else:
            links.append(f"`{evidence_id}`")
    return ", ".join(links)
