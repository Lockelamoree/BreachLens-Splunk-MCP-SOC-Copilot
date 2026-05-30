from __future__ import annotations

from hashlib import sha1
from typing import Any

from .domain import (
    Alert,
    AnalystNote,
    Evidence,
    Investigation,
    MitreMapping,
    QueryTranscript,
    ResponseAction,
    TimelineEvent,
)
from .evidence import EvidenceValidationError, validate_investigation, validate_objective
from .llm import DeterministicProvider, LLMProvider
from .spl import alert_list_query, build_investigation_queries
from .splunk_client import SplunkToolClient


def get_alerts(client: SplunkToolClient, index: str = "breachlens") -> list[Alert]:
    rows = client.run_query(alert_list_query(index))
    alerts = [Alert.from_row(row) for row in rows if row.get("alert_id")]
    return sorted(alerts, key=lambda item: item.severity_score, reverse=True)


def run_investigation(
    client: SplunkToolClient,
    alert_id: str,
    objective: str | None = None,
    index: str = "breachlens",
    llm_provider: LLMProvider | None = None,
) -> Investigation:
    cleaned_objective = validate_objective(objective or "")
    alerts = get_alerts(client, index)
    alert = next((item for item in alerts if item.alert_id == alert_id), None)
    if alert is None:
        raise EvidenceValidationError(f"Unknown alert_id: {alert_id}")

    if not cleaned_objective:
        cleaned_objective = alert.recommended_objective

    warnings: list[str] = []
    transcripts = _collect_context_transcripts(client, warnings)
    evidence: list[Evidence] = []

    for spec in build_investigation_queries(alert.to_dict(), index):
        rows = client.run_query(spec.spl)
        transcripts.append(
            QueryTranscript(
                query_id=spec.id,
                purpose=spec.purpose,
                spl=spec.spl,
                result_count=len(rows),
            )
        )
        for row in rows:
            evidence.append(_evidence_from_row(len(evidence) + 1, spec.id, row))

    timeline = _build_timeline(alert, evidence)
    mitre = _build_mitre(evidence)
    response_actions = _build_response_actions(alert, evidence)
    confidence = _confidence(timeline)
    summary = _summary(alert, timeline, confidence)
    analyst_note = _build_analyst_note(
        llm_provider or DeterministicProvider(),
        alert,
        cleaned_objective,
        evidence,
        timeline,
        warnings,
    )

    investigation = Investigation(
        investigation_id=_investigation_id(alert.alert_id, len(evidence)),
        alert=alert,
        status="complete",
        summary=summary,
        confidence=confidence,
        objective=cleaned_objective,
        evidence=evidence,
        timeline=timeline,
        mitre=mitre,
        response_actions=response_actions,
        spl_transcript=transcripts,
        analyst_note=analyst_note,
        warnings=warnings,
    )
    validate_investigation(investigation)
    return investigation


def _build_analyst_note(
    provider: LLMProvider,
    alert: Alert,
    objective: str,
    evidence: list[Evidence],
    timeline: list[TimelineEvent],
    warnings: list[str],
) -> AnalystNote:
    top_evidence = evidence[:12]
    fallback_ids = [item.id for item in top_evidence[:4]] or [evidence[0].id]
    fallback = AnalystNote(
        provider=provider.name,
        status="deterministic_fallback",
        narrative=(
            "The investigation used deterministic evidence-gated reasoning. Configure "
            "OLLAMA_BASE_URL or OPENAI_COMPATIBLE_BASE_URL plus OPENAI_API_KEY to add a live "
            "model-generated analyst note."
        ),
        evidence_ids=fallback_ids,
    )
    if provider.name == "deterministic":
        return fallback

    payload = {
        "objective": objective,
        "alert": alert.to_dict(),
        "timeline": [item.to_dict() for item in timeline],
        "evidence": [
            {
                "id": item.id,
                "title": item.title,
                "summary": item.summary,
                "source": item.source,
            }
            for item in top_evidence
        ],
    }
    result = provider.complete_json(
        (
            "You are a SOC analyst. Return JSON with keys status, narrative, and evidence_ids. "
            "Use only the provided evidence_ids. Do not introduce facts that are not supported "
            "by the provided evidence."
        ),
        payload,
    )
    if result.get("status") in {"error", "unparseable", "unexpected_type"}:
        warnings.append(f"AI analyst note fallback: {result.get('reason') or result.get('status')}")
        return fallback

    known = {item.id for item in evidence}
    cited_ids = [str(item) for item in result.get("evidence_ids", []) if str(item) in known]
    if not cited_ids:
        warnings.append("AI analyst note fallback: provider returned no valid evidence IDs.")
        return fallback

    narrative = str(result.get("narrative", "")).strip()
    if not narrative:
        warnings.append("AI analyst note fallback: provider returned an empty narrative.")
        return fallback

    return AnalystNote(
        provider=provider.name,
        status=str(result.get("status", "model_generated")),
        narrative=narrative[:1200],
        evidence_ids=cited_ids[:8],
    )


def _collect_context_transcripts(client: SplunkToolClient, warnings: list[str]) -> list[QueryTranscript]:
    transcripts: list[QueryTranscript] = []
    context_tools = (
        ("CTX-indexes", "splunk_get_indexes", "Confirm Splunk index access.", client.get_indexes),
        ("CTX-metadata", "splunk_get_metadata", "Inspect indexed sourcetypes and metadata.", client.get_metadata),
        (
            "CTX-knowledge",
            "splunk_get_knowledge_objects",
            "Inspect saved searches and knowledge objects.",
            client.get_knowledge_objects,
        ),
    )
    for query_id, tool, purpose, function in context_tools:
        try:
            rows = function()
            result_count = len(rows)
        except Exception as exc:  # pragma: no cover - defensive for external Splunk integrations.
            warnings.append(f"{tool} failed: {exc}")
            result_count = 0
        transcripts.append(
            QueryTranscript(
                query_id=query_id,
                purpose=purpose,
                spl=f"{tool}()",
                result_count=result_count,
                tool=tool,
            )
        )
    return transcripts


def _investigation_id(alert_id: str, evidence_count: int) -> str:
    digest = sha1(f"{alert_id}:{evidence_count}".encode("utf-8")).hexdigest()[:8]
    return f"INV-{digest.upper()}"


def _source_from_query(query_id: str) -> str:
    return {
        "Q-alert": "breachlens:alert",
        "Q-identity": "breachlens:auth",
        "Q-cloud": "breachlens:cloud",
        "Q-endpoint": "breachlens:edr",
        "Q-proxy": "breachlens:proxy",
    }.get(query_id, "splunk")


def _evidence_from_row(number: int, query_id: str, row: dict[str, Any]) -> Evidence:
    source = str(row.get("sourcetype") or _source_from_query(query_id))
    return Evidence(
        id=f"EV-{number:03d}",
        query_id=query_id,
        time=str(row.get("time") or row.get("_time") or ""),
        source=source,
        title=_evidence_title(source, row),
        summary=_evidence_summary(source, row),
        fields={key: value for key, value in row.items() if not key.startswith("__")},
    )


def _evidence_title(source: str, row: dict[str, Any]) -> str:
    if source.endswith(":alert"):
        return str(row.get("title", "Triggering alert"))
    if source.endswith(":auth"):
        return f"Auth {row.get('action', 'event')} for {row.get('user', 'unknown user')}"
    if source.endswith(":cloud"):
        return f"Cloud {row.get('action', 'event')} on {row.get('resource', 'resource')}"
    if source.endswith(":edr"):
        return f"Endpoint {row.get('action', 'event')} on {row.get('host', 'host')}"
    if source.endswith(":proxy"):
        return f"Proxy {row.get('action', 'event')} to {row.get('dest_domain', 'destination')}"
    return "Splunk evidence"


def _evidence_summary(source: str, row: dict[str, Any]) -> str:
    if source.endswith(":alert"):
        return str(row.get("description", "Alert context from Splunk."))
    if source.endswith(":auth"):
        return (
            f"{row.get('user')} had auth action={row.get('action')} from {row.get('src_ip')} "
            f"in {row.get('geo')} with reason={row.get('reason')}."
        )
    if source.endswith(":cloud"):
        return (
            f"{row.get('user')} performed {row.get('action')} against {row.get('resource')} "
            f"from {row.get('src_ip')} with outcome={row.get('outcome')}."
        )
    if source.endswith(":edr"):
        return (
            f"{row.get('process')} spawned from {row.get('parent_process')} on {row.get('host')} "
            f"with risk={row.get('risk')}."
        )
    if source.endswith(":proxy"):
        return (
            f"{row.get('host')} sent {row.get('bytes_out')} bytes to {row.get('dest_domain')} "
            f"with category={row.get('category')}."
        )
    return "Evidence returned from Splunk."


def _field(item: Evidence, key: str, default: Any = "") -> Any:
    return item.fields.get(key, default)


def _ids(evidence: list[Evidence], predicate) -> list[str]:
    return [item.id for item in evidence if predicate(item)]


def _first_time(evidence: list[Evidence], ids: list[str]) -> str:
    selected = [item.time for item in evidence if item.id in ids and item.time]
    return sorted(selected)[0] if selected else ""


def _build_timeline(alert: Alert, evidence: list[Evidence]) -> list[TimelineEvent]:
    timeline: list[TimelineEvent] = []

    spray_ids = _ids(
        evidence,
        lambda item: item.source.endswith(":auth")
        and _field(item, "action") == "failure"
        and _field(item, "src_ip") == alert.src_ip,
    )
    if len(spray_ids) >= 5:
        timeline.append(
            TimelineEvent(
                time=_first_time(evidence, spray_ids),
                phase="Initial access",
                title="Password spray targets multiple users",
                narrative=(
                    f"{alert.src_ip} generated repeated failed logins across multiple users before "
                    f"the alert for {alert.user}."
                ),
                evidence_ids=spray_ids[:6],
            )
        )

    normal_and_risky_success = _ids(
        evidence,
        lambda item: item.source.endswith(":auth")
        and _field(item, "user") == alert.user
        and _field(item, "action") == "success",
    )
    risky_success_ids = _ids(
        evidence,
        lambda item: item.source.endswith(":auth")
        and _field(item, "user") == alert.user
        and _field(item, "action") == "success"
        and _field(item, "src_ip") == alert.src_ip,
    )
    if len(normal_and_risky_success) >= 2:
        timeline.append(
            TimelineEvent(
                time=_first_time(evidence, risky_success_ids or normal_and_risky_success),
                phase="Credential access",
                title="Impossible travel login succeeds",
                narrative=(
                    f"{alert.user} authenticated successfully from different countries inside the "
                    "investigation window, including the suspicious source tied to the spray."
                ),
                evidence_ids=normal_and_risky_success,
            )
        )

    cloud_ids = _ids(
        evidence,
        lambda item: item.source.endswith(":cloud")
        and _field(item, "user") == alert.user
        and _field(item, "outcome") in {"success", "denied"},
    )
    if cloud_ids:
        timeline.append(
            TimelineEvent(
                time=_first_time(evidence, cloud_ids),
                phase="Cloud control plane",
                title="Programmatic cloud activity follows risky login",
                narrative=(
                    "Cloud API activity created programmatic access, performed discovery, accessed "
                    "sensitive objects, and attempted persistence."
                ),
                evidence_ids=cloud_ids,
            )
        )

    endpoint_ids = _ids(
        evidence,
        lambda item: item.source.endswith(":edr")
        and (
            "EncodedCommand" in str(_field(item, "command_line"))
            or _field(item, "process") in {"powershell.exe", "rclone.exe"}
        ),
    )
    if endpoint_ids:
        timeline.append(
            TimelineEvent(
                time=_first_time(evidence, endpoint_ids),
                phase="Execution",
                title="Endpoint executes encoded PowerShell and staging tool",
                narrative=(
                    f"{alert.host} executed encoded PowerShell from an Office parent process and "
                    "staged a transfer utility."
                ),
                evidence_ids=endpoint_ids,
            )
        )

    exfil_ids = _ids(
        evidence,
        lambda item: item.source.endswith(":proxy")
        and int(_field(item, "bytes_out", 0) or 0) > 50_000_000,
    )
    if exfil_ids:
        timeline.append(
            TimelineEvent(
                time=_first_time(evidence, exfil_ids),
                phase="Exfiltration",
                title="Large outbound transfer to file-sharing service",
                narrative=(
                    f"{alert.host} sent high-volume outbound PUT requests to file-sharing "
                    "infrastructure after the suspicious endpoint execution."
                ),
                evidence_ids=exfil_ids,
            )
        )

    return sorted(timeline, key=lambda item: item.time)


def _build_mitre(evidence: list[Evidence]) -> list[MitreMapping]:
    mappings: list[MitreMapping] = []
    spray_ids = _ids(evidence, lambda item: item.source.endswith(":auth") and _field(item, "action") == "failure")
    success_ids = _ids(evidence, lambda item: item.source.endswith(":auth") and _field(item, "action") == "success")
    cloud_ids = _ids(evidence, lambda item: item.source.endswith(":cloud") and _field(item, "action") in {"CreateAccessKey", "AssumeRole", "CreateLoginProfile"})
    powershell_ids = _ids(evidence, lambda item: item.source.endswith(":edr") and _field(item, "process") == "powershell.exe")
    exfil_ids = _ids(evidence, lambda item: item.source.endswith(":proxy") and int(_field(item, "bytes_out", 0) or 0) > 50_000_000)

    if spray_ids:
        mappings.append(
            MitreMapping(
                "T1110.003",
                "Password Spraying",
                "Credential Access",
                "Multiple failed logins from one source IP across distinct users.",
                spray_ids[:6],
            )
        )
    if success_ids:
        mappings.append(
            MitreMapping(
                "T1078",
                "Valid Accounts",
                "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                "A successful authentication occurred after the suspicious spray activity.",
                success_ids,
            )
        )
    if cloud_ids:
        mappings.append(
            MitreMapping(
                "T1098",
                "Account Manipulation",
                "Persistence, Privilege Escalation",
                "Cloud credential and role actions changed or attempted to change account access.",
                cloud_ids,
            )
        )
    if powershell_ids:
        mappings.append(
            MitreMapping(
                "T1059.001",
                "PowerShell",
                "Execution",
                "Encoded PowerShell executed from an Office parent process.",
                powershell_ids,
            )
        )
    if exfil_ids:
        mappings.append(
            MitreMapping(
                "T1567.002",
                "Exfiltration to Cloud Storage",
                "Exfiltration",
                "Large outbound file-sharing uploads followed endpoint staging activity.",
                exfil_ids,
            )
        )
    return mappings


def _build_response_actions(alert: Alert, evidence: list[Evidence]) -> list[ResponseAction]:
    identity_ids = _ids(evidence, lambda item: item.source.endswith(":auth") and _field(item, "user") == alert.user)
    cloud_ids = _ids(evidence, lambda item: item.source.endswith(":cloud") and _field(item, "user") == alert.user)
    endpoint_ids = _ids(evidence, lambda item: item.source.endswith(":edr") and _field(item, "host") == alert.host)
    proxy_ids = _ids(evidence, lambda item: item.source.endswith(":proxy") and _field(item, "host") == alert.host)

    actions: list[ResponseAction] = []
    if identity_ids:
        actions.append(
            ResponseAction(
                "P0",
                "Identity",
                f"Disable {alert.user}, revoke active sessions, and reset MFA enrollment after user verification.",
                identity_ids[:4],
            )
        )
    if cloud_ids:
        actions.append(
            ResponseAction(
                "P0",
                "Cloud",
                "Revoke newly created access keys, rotate affected credentials, and review assumed-role activity.",
                cloud_ids,
            )
        )
    if endpoint_ids:
        actions.append(
            ResponseAction(
                "P0",
                "Endpoint",
                f"Isolate {alert.host}, collect process/file artifacts, and quarantine the staged transfer utility.",
                endpoint_ids,
            )
        )
    if proxy_ids:
        actions.append(
            ResponseAction(
                "P1",
                "Network",
                "Block the suspicious source IP and file-sharing destination pending incident review.",
                proxy_ids,
            )
        )
    all_ids = [item.id for item in evidence[:8]]
    if all_ids:
        actions.append(
            ResponseAction(
                "P1",
                "Detection Engineering",
                "Promote the generated SPL into scheduled searches and tune thresholds against production baselines.",
                all_ids,
            )
        )
    return actions


def _confidence(timeline: list[TimelineEvent]) -> str:
    phases = {item.phase for item in timeline}
    if {"Initial access", "Credential access", "Cloud control plane", "Execution", "Exfiltration"}.issubset(phases):
        return "high"
    if len(phases) >= 3:
        return "medium"
    return "low"


def _summary(alert: Alert, timeline: list[TimelineEvent], confidence: str) -> str:
    phases = ", ".join(item.phase.lower() for item in timeline)
    return (
        f"Evidence supports a {confidence}-confidence compromise chain for {alert.user}: "
        f"{phases}. The investigation ties identity, cloud, endpoint, and proxy telemetry "
        "to the same alert context with explicit evidence IDs."
    )
