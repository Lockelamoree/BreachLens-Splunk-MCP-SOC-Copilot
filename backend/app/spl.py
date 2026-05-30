from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class QuerySpec:
    id: str
    purpose: str
    spl: str


def spl_string(value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def alert_list_query(index: str) -> str:
    return (
        f"search index={index} sourcetype=breachlens:alert "
        "| spath input=_raw path=host output=event_host "
        "| eval host=coalesce(event_host, host) "
        "| sort -severity_score "
        "| table _time time alert_id title severity severity_score status user src_ip host asset description recommended_objective"
    )


def build_investigation_queries(alert: dict[str, Any], index: str) -> list[QuerySpec]:
    alert_id = spl_string(alert.get("alert_id", ""))
    user = spl_string(alert.get("user", ""))
    src_ip = spl_string(alert.get("src_ip", ""))
    host = spl_string(alert.get("host", ""))

    return [
        QuerySpec(
            id="Q-alert",
            purpose="Load the triggering alert and starting context.",
            spl=(
                f"search index={index} sourcetype=breachlens:alert alert_id={alert_id} "
                "| spath input=_raw path=host output=event_host "
                "| eval host=coalesce(event_host, host) "
                "| table _time time alert_id title severity severity_score status user src_ip host asset description recommended_objective"
            ),
        ),
        QuerySpec(
            id="Q-identity",
            purpose="Pivot across authentication activity for the user and suspicious source IP.",
            spl=(
                f"search index={index} sourcetype=breachlens:auth (user={user} OR src_ip={src_ip}) "
                "| sort _time "
                "| table _time time event_id user src_ip action reason app geo country user_agent session_id"
            ),
        ),
        QuerySpec(
            id="Q-cloud",
            purpose="Check cloud API activity tied to the compromised user or suspicious source IP.",
            spl=(
                f"search index={index} sourcetype=breachlens:cloud (user={user} OR src_ip={src_ip}) "
                "| sort _time "
                "| table _time time event_id user src_ip provider account_id action resource region outcome user_agent session_id risk"
            ),
        ),
        QuerySpec(
            id="Q-endpoint",
            purpose="Inspect endpoint execution on the alerted host.",
            spl=(
                f"search index={index} sourcetype=breachlens:edr (host={host} OR user={user}) "
                "| spath input=_raw path=host output=event_host "
                "| eval host=coalesce(event_host, host) "
                "| sort _time "
                "| table _time time event_id host user src_ip action process parent_process command_line file_path sha256 severity sensor risk"
            ),
        ),
        QuerySpec(
            id="Q-proxy",
            purpose="Look for outbound transfer from the alerted host and user.",
            spl=(
                f"search index={index} sourcetype=breachlens:proxy (host={host} OR user={user}) "
                "| spath input=_raw path=host output=event_host "
                "| eval host=coalesce(event_host, host) "
                "| sort _time "
                "| table _time time event_id host user src_ip dest_domain dest_ip url http_method status bytes_in bytes_out category action risk"
            ),
        ),
    ]
