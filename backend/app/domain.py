from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class Alert:
    alert_id: str
    title: str
    severity: str
    severity_score: int
    status: str
    time: str
    user: str
    src_ip: str
    host: str
    asset: str
    description: str
    recommended_objective: str

    @classmethod
    def from_row(cls, row: JsonDict) -> "Alert":
        return cls(
            alert_id=str(row.get("alert_id", "")),
            title=str(row.get("title", "")),
            severity=str(row.get("severity", "unknown")),
            severity_score=int(row.get("severity_score", 0) or 0),
            status=str(row.get("status", "new")),
            time=str(row.get("time") or row.get("_time") or ""),
            user=str(row.get("user", "")),
            src_ip=str(row.get("src_ip", "")),
            host=str(row.get("host", "")),
            asset=str(row.get("asset", "")),
            description=str(row.get("description", "")),
            recommended_objective=str(row.get("recommended_objective", "")),
        )

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class QueryTranscript:
    query_id: str
    purpose: str
    spl: str
    result_count: int
    tool: str = "splunk_run_query"

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class Evidence:
    id: str
    query_id: str
    time: str
    source: str
    title: str
    summary: str
    fields: JsonDict
    splunk_url: str = ""

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class TimelineEvent:
    time: str
    phase: str
    title: str
    narrative: str
    evidence_ids: list[str]

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique: str
    tactic: str
    rationale: str
    evidence_ids: list[str]

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class ResponseAction:
    priority: str
    owner: str
    action: str
    evidence_ids: list[str]

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class DetectionDraft:
    detection_id: str
    title: str
    severity: str
    spl: str
    sigma: str
    evidence_ids: list[str]

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class AnalystNote:
    provider: str
    status: str
    narrative: str
    evidence_ids: list[str]

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class Investigation:
    investigation_id: str
    alert: Alert
    status: str
    summary: str
    confidence: str
    objective: str
    evidence: list[Evidence] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    mitre: list[MitreMapping] = field(default_factory=list)
    response_actions: list[ResponseAction] = field(default_factory=list)
    spl_transcript: list[QueryTranscript] = field(default_factory=list)
    analyst_note: AnalystNote | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonDict:
        return {
            "investigation_id": self.investigation_id,
            "alert": self.alert.to_dict(),
            "status": self.status,
            "summary": self.summary,
            "confidence": self.confidence,
            "objective": self.objective,
            "evidence": [item.to_dict() for item in self.evidence],
            "timeline": [item.to_dict() for item in self.timeline],
            "mitre": [item.to_dict() for item in self.mitre],
            "response_actions": [item.to_dict() for item in self.response_actions],
            "spl_transcript": [item.to_dict() for item in self.spl_transcript],
            "analyst_note": self.analyst_note.to_dict() if self.analyst_note else None,
            "warnings": self.warnings,
        }
