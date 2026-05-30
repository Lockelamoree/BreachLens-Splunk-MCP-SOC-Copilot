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
    evidence_by_id = {item.id: item for item in investigation.evidence}
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
        if not investigation.analyst_note.claims:
            raise EvidenceValidationError("AI analyst note has no claim field references.")
        for index, claim in enumerate(investigation.analyst_note.claims, start=1):
            claim_ids = [str(item) for item in claim.get("evidence_ids", [])]
            if not claim_ids:
                raise EvidenceValidationError(f"AI analyst note claim {index} has no evidence references.")
            validate_references(known, claim_ids, f"AI analyst note claim {index}")
            field_refs = [str(item) for item in claim.get("field_refs", [])]
            if not field_refs:
                raise EvidenceValidationError(f"AI analyst note claim {index} has no field references.")
            for field_ref in field_refs:
                if "." not in field_ref:
                    raise EvidenceValidationError(
                        f"AI analyst note claim {index} has invalid field reference: {field_ref}"
                    )
                evidence_id, field_name = field_ref.split(".", 1)
                evidence = evidence_by_id.get(evidence_id)
                if not evidence or field_name not in {"query_id", "time", "source", "title", "summary"} | set(evidence.fields):
                    raise EvidenceValidationError(
                        f"AI analyst note claim {index} has invalid field reference: {field_ref}"
                    )

    for token in ("might", "possibly", "appears without evidence"):
        if token in investigation.summary.lower():
            raise EvidenceValidationError(
                "Summary contains weak or unsupported language after evidence gating."
            )
