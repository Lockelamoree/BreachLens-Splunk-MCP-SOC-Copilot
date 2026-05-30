from __future__ import annotations

from collections.abc import Iterable

from .domain import Evidence, Investigation


PROMPT_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "reveal your instructions",
    "show your instructions",
    "jailbreak",
    "disable safety",
    "exfiltrate secrets",
)


class EvidenceValidationError(ValueError):
    pass


def validate_objective(objective: str) -> str:
    cleaned = " ".join((objective or "").split())
    lowered = cleaned.lower()
    for marker in PROMPT_INJECTION_MARKERS:
        if marker in lowered:
            raise EvidenceValidationError(
                "Objective contains prompt-injection language and was rejected."
            )
    return cleaned[:500]


def evidence_id_set(evidence: Iterable[Evidence]) -> set[str]:
    return {item.id for item in evidence}


def validate_references(known_ids: set[str], references: Iterable[str], context: str) -> None:
    missing = [ref for ref in references if ref not in known_ids]
    if missing:
        raise EvidenceValidationError(
            f"{context} references unknown evidence IDs: {', '.join(missing)}"
        )


def validate_investigation(investigation: Investigation) -> None:
    known = evidence_id_set(investigation.evidence)
    if not known:
        raise EvidenceValidationError("Investigation has no evidence.")

    for item in investigation.timeline:
        if not item.evidence_ids:
            raise EvidenceValidationError(f"Timeline item has no evidence: {item.title}")
        validate_references(known, item.evidence_ids, f"Timeline item {item.title}")

    for item in investigation.mitre:
        if not item.evidence_ids:
            raise EvidenceValidationError(f"MITRE mapping has no evidence: {item.technique_id}")
        validate_references(known, item.evidence_ids, f"MITRE mapping {item.technique_id}")

    for item in investigation.response_actions:
        if not item.evidence_ids:
            raise EvidenceValidationError(f"Response action has no evidence: {item.action}")
        validate_references(known, item.evidence_ids, f"Response action {item.action}")

    if investigation.analyst_note:
        if not investigation.analyst_note.evidence_ids:
            raise EvidenceValidationError("AI analyst note has no evidence references.")
        validate_references(known, investigation.analyst_note.evidence_ids, "AI analyst note")

    for token in ("might", "possibly", "appears without evidence"):
        if token in investigation.summary.lower():
            raise EvidenceValidationError(
                "Summary contains weak or unsupported language after evidence gating."
            )
