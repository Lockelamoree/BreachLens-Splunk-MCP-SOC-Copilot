from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import Settings


class SplunkClientError(RuntimeError):
    pass


class SplunkToolClient(Protocol):
    name: str

    def run_query(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        ...

    def get_indexes(self) -> list[dict]:
        ...

    def get_metadata(self) -> list[dict]:
        ...

    def get_knowledge_objects(self) -> list[dict]:
        ...


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


@dataclass
class SampleDataClient:
    sample_data_dir: Path
    index: str = "breachlens"
    name: str = "sample_data"

    def run_query(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        sourcetype_file = {
            "sourcetype=breachlens:alert": "alerts.jsonl",
            "sourcetype=breachlens:auth": "auth.jsonl",
            "sourcetype=breachlens:cloud": "cloud.jsonl",
            "sourcetype=breachlens:edr": "edr.jsonl",
            "sourcetype=breachlens:proxy": "proxy.jsonl",
        }
        for marker, filename in sourcetype_file.items():
            if marker in spl:
                rows = _load_jsonl(self.sample_data_dir / filename)
                return self._filter_rows(spl, rows)
        return []

    def get_indexes(self) -> list[dict]:
        return [{"title": self.index, "currentDBSizeMB": 1, "source": "sample"}]

    def get_metadata(self) -> list[dict]:
        return [
            {"sourcetype": "breachlens:alert", "events": 3},
            {"sourcetype": "breachlens:auth", "events": 11},
            {"sourcetype": "breachlens:cloud", "events": 5},
            {"sourcetype": "breachlens:edr", "events": 3},
            {"sourcetype": "breachlens:proxy", "events": 3},
        ]

    def get_knowledge_objects(self) -> list[dict]:
        return [
            {"name": "BreachLens - Password Spray Detection", "type": "saved_search"},
            {"name": "BreachLens - Impossible Travel Detection", "type": "saved_search"},
            {"name": "BreachLens - Cloud Token Abuse Detection", "type": "saved_search"},
            {"name": "BreachLens - Encoded PowerShell From Office", "type": "saved_search"},
            {"name": "BreachLens - Suspicious Exfil Upload", "type": "saved_search"},
        ]

    @staticmethod
    def _filter_rows(spl: str, rows: list[dict]) -> list[dict]:
        filtered = rows
        for key in ("alert_id", "user", "src_ip", "host"):
            needle = f'{key}="'
            if needle in spl:
                value = spl.split(needle, 1)[1].split('"', 1)[0]
                if value and value != "multiple":
                    filtered = [row for row in filtered if str(row.get(key, "")) == value]
        if "OR src_ip=" in spl and 'src_ip="' in spl:
            src_ip = spl.split('src_ip="', 1)[1].split('"', 1)[0]
            user = ""
            if 'user="' in spl:
                user = spl.split('user="', 1)[1].split('"', 1)[0]
            host = ""
            if 'host="' in spl:
                host = spl.split('host="', 1)[1].split('"', 1)[0]
            filtered = [
                row
                for row in rows
                if (user and row.get("user") == user)
                or (src_ip and row.get("src_ip") == src_ip)
                or (host and row.get("host") == host)
            ]
        return sorted(filtered, key=lambda row: str(row.get("time") or row.get("_time") or ""))


@dataclass
class McpSplunkClient:
    url: str
    token: str
    name: str = "splunk_mcp"

    def run_query(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        return self._call_tool(
            "splunk_run_query",
            {"query": spl, "earliest_time": earliest, "latest_time": latest},
        )

    def get_indexes(self) -> list[dict]:
        return self._call_tool("splunk_get_indexes", {})

    def get_metadata(self) -> list[dict]:
        return self._call_tool("splunk_get_metadata", {})

    def get_knowledge_objects(self) -> list[dict]:
        return self._call_tool("splunk_get_knowledge_objects", {})

    def _call_tool(self, name: str, arguments: dict) -> list[dict]:
        payload = {
            "jsonrpc": "2.0",
            "id": f"breachlens-{name}",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                body = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise SplunkClientError(f"MCP tool call failed for {name}: {exc}") from exc
        return _extract_tool_results(body)


@dataclass
class RestSplunkClient:
    base_url: str
    username: str
    password: str
    token: str
    verify_tls: bool
    name: str = "splunk_rest"

    def run_query(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        endpoint = f"{self.base_url}/services/search/jobs/export"
        body = urllib.parse.urlencode(
            {
                "search": spl if spl.startswith("search ") else f"search {spl}",
                "output_mode": "json",
                "earliest_time": earliest,
                "latest_time": latest,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers=self._headers(),
            method="POST",
        )
        context = None if self.verify_tls else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=45, context=context) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise SplunkClientError(f"Splunk REST query failed: {exc}") from exc
        results = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if "result" in item:
                results.append(item["result"])
        return results

    def get_indexes(self) -> list[dict]:
        return self._get_json("/services/data/indexes")

    def get_metadata(self) -> list[dict]:
        return self._get_json("/services/admin/sourcetypes")

    def get_knowledge_objects(self) -> list[dict]:
        return self._get_json("/servicesNS/-/-/saved/searches")

    def _get_json(self, path: str) -> list[dict]:
        request = urllib.request.Request(
            f"{self.base_url}{path}?output_mode=json",
            headers=self._headers(),
            method="GET",
        )
        context = None if self.verify_tls else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise SplunkClientError(f"Splunk REST metadata request failed: {exc}") from exc
        return payload.get("entry", [])

    def _headers(self) -> dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        if not self.password:
            raise SplunkClientError("SPLUNK_PASSWORD or SPLUNK_TOKEN is required for REST mode.")
        encoded = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}


def _extract_tool_results(body: str) -> list[dict]:
    if body.startswith("event:") or "\ndata:" in body:
        data_lines = [line.removeprefix("data:").strip() for line in body.splitlines() if line.startswith("data:")]
        body = data_lines[-1] if data_lines else "{}"
    payload = json.loads(body)
    if "error" in payload:
        raise SplunkClientError(str(payload["error"]))
    result = payload.get("result", payload)
    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]
    if isinstance(result, dict):
        for key in ("results", "rows", "data", "content"):
            value = result.get(key)
            if isinstance(value, list):
                parsed = []
                for item in value:
                    if isinstance(item, dict):
                        parsed.append(item)
                    elif isinstance(item, str):
                        try:
                            parsed.append(json.loads(item))
                        except json.JSONDecodeError:
                            parsed.append({"text": item})
                return parsed
        return [result]
    return [{"text": str(result)}]


def make_splunk_client(settings: Settings) -> SplunkToolClient:
    if settings.mode == "mcp":
        if not settings.splunk_mcp_url or not settings.splunk_mcp_token:
            raise SplunkClientError("SPLUNK_MCP_URL and SPLUNK_MCP_TOKEN are required for MCP mode.")
        return McpSplunkClient(settings.splunk_mcp_url, settings.splunk_mcp_token)
    if settings.mode == "rest":
        return RestSplunkClient(
            settings.splunk_base_url,
            settings.splunk_username,
            settings.splunk_password,
            settings.splunk_token,
            settings.splunk_verify_tls,
        )
    return SampleDataClient(settings.sample_data_dir, settings.splunk_index)
