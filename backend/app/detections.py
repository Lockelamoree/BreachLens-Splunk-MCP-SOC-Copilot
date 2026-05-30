from __future__ import annotations

from textwrap import dedent

from .domain import DetectionDraft, Investigation


def generate_detection_drafts(investigation: Investigation) -> list[DetectionDraft]:
    known = {item.id for item in investigation.evidence}
    user = investigation.alert.user
    host = investigation.alert.host
    suspicious_ip = investigation.alert.src_ip

    identity_ids = _ids(investigation, "breachlens:auth")
    cloud_ids = _ids(investigation, "breachlens:cloud")
    endpoint_ids = _ids(investigation, "breachlens:edr")
    proxy_ids = _ids(investigation, "breachlens:proxy")

    drafts = [
        DetectionDraft(
            detection_id="DET-password-spray-success",
            title="Password spray followed by successful authentication",
            severity="high",
            evidence_ids=_bounded(identity_ids, known),
            spl=dedent(
                f"""
                `breachlens_index` sourcetype=breachlens:auth src_ip="{suspicious_ip}"
                | stats dc(user) as targeted_users count(eval(action="failure")) as failures count(eval(action="success")) as successes values(user) as users by src_ip
                | where targeted_users >= 5 AND failures >= 8 AND successes >= 1
                """
            ).strip(),
            sigma=dedent(
                f"""
                title: Password Spray Followed By Successful Authentication
                status: experimental
                logsource:
                  product: identity
                  service: okta
                detection:
                  selection:
                    src_ip: "{suspicious_ip}"
                  condition: selection
                fields:
                  - user
                  - src_ip
                  - action
                  - reason
                level: high
                """
            ).strip(),
        ),
        DetectionDraft(
            detection_id="DET-cloud-token-after-risky-login",
            title="Cloud credential activity after risky login",
            severity="critical",
            evidence_ids=_bounded(identity_ids[:3] + cloud_ids, known),
            spl=dedent(
                f"""
                `breachlens_index` (sourcetype=breachlens:auth OR sourcetype=breachlens:cloud) user="{user}"
                | eval identity_risk=if(sourcetype="breachlens:auth" AND src_ip="{suspicious_ip}" AND action="success", 1, 0)
                | eval cloud_risk=if(sourcetype="breachlens:cloud" AND action IN ("CreateAccessKey","AssumeRole","CreateLoginProfile"), 1, 0)
                | stats max(identity_risk) as identity_risk max(cloud_risk) as cloud_risk values(action) as actions values(resource) as resources by user src_ip
                | where identity_risk=1 AND cloud_risk=1
                """
            ).strip(),
            sigma=dedent(
                f"""
                title: Cloud Credential Activity After Risky Login
                status: experimental
                logsource:
                  product: cloud
                  service: aws
                detection:
                  selection_user:
                    user: "{user}"
                  selection_actions:
                    action:
                      - CreateAccessKey
                      - AssumeRole
                      - CreateLoginProfile
                  condition: selection_user and selection_actions
                fields:
                  - user
                  - src_ip
                  - action
                  - resource
                level: critical
                """
            ).strip(),
        ),
        DetectionDraft(
            detection_id="DET-exec-then-large-upload",
            title="Encoded PowerShell followed by large file-sharing upload",
            severity="critical",
            evidence_ids=_bounded(endpoint_ids + proxy_ids, known),
            spl=dedent(
                f"""
                `breachlens_index` (sourcetype=breachlens:edr OR sourcetype=breachlens:proxy) host="{host}"
                | eval encoded_ps=if(sourcetype="breachlens:edr" AND process="powershell.exe" AND like(command_line, "%EncodedCommand%"), 1, 0)
                | eval large_upload=if(sourcetype="breachlens:proxy" AND bytes_out>50000000 AND category="file_sharing", 1, 0)
                | stats max(encoded_ps) as encoded_ps max(large_upload) as large_upload sum(bytes_out) as total_bytes values(dest_domain) as dest_domains by host user
                | where encoded_ps=1 AND large_upload=1 AND total_bytes>100000000
                """
            ).strip(),
            sigma=dedent(
                f"""
                title: Encoded PowerShell Followed By Large Upload
                status: experimental
                logsource:
                  product: windows
                  category: process_creation
                detection:
                  selection:
                    Image|endswith: "\\\\powershell.exe"
                    CommandLine|contains: "EncodedCommand"
                  condition: selection
                fields:
                  - host
                  - user
                  - parent_process
                  - command_line
                level: critical
                """
            ).strip(),
        ),
    ]
    return drafts


def _ids(investigation: Investigation, source: str) -> list[str]:
    return [item.id for item in investigation.evidence if item.source == source]


def _bounded(ids: list[str], known: set[str]) -> list[str]:
    return [item for item in ids if item in known]

