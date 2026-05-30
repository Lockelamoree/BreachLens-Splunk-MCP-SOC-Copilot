from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
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
    verify_tls: bool
    name: str = "splunk_mcp"
    session_id: str = field(default="", init=False)
    tool_names: set[str] = field(default_factory=set, init=False)
    tools_loaded: bool = field(default=False, init=False)

    def run_query(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        tool_name = self._resolve_tool_name("splunk_run_query", "run_query")
        arguments = {"query": spl}
        if tool_name == "splunk_run_query":
            arguments.update({"earliest_time": earliest, "latest_time": latest})
        return self._call_tool(
            tool_name,
            arguments,
        )

    def get_indexes(self) -> list[dict]:
        return self._call_tool(self._resolve_tool_name("splunk_get_indexes", "get_indexes"), {})

    def get_metadata(self) -> list[dict]:
        tool_name = self._resolve_tool_name("splunk_get_metadata", "get_metadata")
        arguments = {} if tool_name == "splunk_get_metadata" else {"type": "sourcetypes", "index": "*"}
        return self._call_tool(tool_name, arguments)

    def get_knowledge_objects(self) -> list[dict]:
        tool_name = self._resolve_tool_name("splunk_get_knowledge_objects", "get_knowledge_objects")
        arguments = {} if tool_name == "splunk_get_knowledge_objects" else {"type": "saved_searches"}
        return self._call_tool(tool_name, arguments)

    def list_tools(self) -> list[dict]:
        self._ensure_initialized()
        payload = self._post_json_rpc(
            {
                "jsonrpc": "2.0",
                "id": "breachlens-tools-list",
                "method": "tools/list",
                "params": {},
            }
        )
        tools = payload.get("result", {}).get("tools", [])
        parsed = [item for item in tools if isinstance(item, dict)]
        self.tool_names = {str(item.get("name", "")) for item in parsed if item.get("name")}
        self.tools_loaded = True
        return parsed

    def _resolve_tool_name(self, legacy_name: str, current_name: str) -> str:
        names = self._available_tool_names()
        for candidate in (legacy_name, current_name):
            if candidate in names:
                return candidate
        return legacy_name

    def _call_tool(self, name: str, arguments: dict) -> list[dict]:
        self._ensure_initialized()
        payload = {
            "jsonrpc": "2.0",
            "id": f"breachlens-{name}",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        return _extract_tool_results_from_payload(self._post_json_rpc(payload))

    def _available_tool_names(self) -> set[str]:
        if not self.tools_loaded:
            try:
                self.list_tools()
            except SplunkClientError:
                self.tools_loaded = True
        return self.tool_names

    def _ensure_initialized(self) -> None:
        if self.session_id:
            return
        self._post_json_rpc(
            {
                "jsonrpc": "2.0",
                "id": "breachlens-initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "breachlens", "version": "0.1.0"},
                },
            }
        )
        self._post_json_rpc(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

    def _post_json_rpc(self, payload: dict) -> dict:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        context = None if self.verify_tls else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=45, context=context) as response:
                body = response.read().decode("utf-8")
                session_id = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
                if session_id:
                    self.session_id = session_id
        except urllib.error.URLError as exc:
            method = payload.get("method", "unknown")
            raise SplunkClientError(f"MCP request failed for {method}: {exc}") from exc
        if not body.strip():
            return {}
        return _load_json_rpc_payload(body)


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


def _load_json_rpc_payload(body: str) -> dict:
    if body.startswith("event:") or "\ndata:" in body:
        data_lines = [line.removeprefix("data:").strip() for line in body.splitlines() if line.startswith("data:")]
        body = data_lines[-1] if data_lines else "{}"
    payload = json.loads(body)
    if "error" in payload:
        raise SplunkClientError(str(payload["error"]))
    return payload


def _extract_tool_results_from_payload(payload: dict) -> list[dict]:
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
                        expanded = _expand_mcp_content_item(item)
                        if expanded is not None:
                            return expanded
                        parsed.append(item)
                    elif isinstance(item, str):
                        try:
                            expanded = _expand_text_payload(item)
                            if expanded is not None:
                                return expanded
                            parsed.append(json.loads(item))
                        except json.JSONDecodeError:
                            parsed.append({"text": item})
                return parsed
        return [result]
    return [{"text": str(result)}]


def _expand_mcp_content_item(item: dict) -> list[dict] | None:
    if item.get("type") != "text" or not isinstance(item.get("text"), str):
        return None
    return _expand_text_payload(item["text"])


def _expand_text_payload(text: str) -> list[dict] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        for key in ("results", "rows", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return None


def make_splunk_client(settings: Settings) -> SplunkToolClient:
    if settings.mode == "mcp":
        if not settings.splunk_mcp_url or not settings.splunk_mcp_token:
            raise SplunkClientError("SPLUNK_MCP_URL and SPLUNK_MCP_TOKEN are required for MCP mode.")
        return McpSplunkClient(
            settings.splunk_mcp_url,
            settings.splunk_mcp_token,
            settings.splunk_mcp_verify_tls,
        )
    if settings.mode == "rest":
        return RestSplunkClient(
            settings.splunk_base_url,
            settings.splunk_username,
            settings.splunk_password,
            settings.splunk_token,
            settings.splunk_verify_tls,
        )
    return SampleDataClient(settings.sample_data_dir, settings.splunk_index)
