from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .config import Settings


class LLMProvider(Protocol):
    name: str

    def complete_json(self, system_prompt: str, payload: dict) -> dict:
        ...


@dataclass
class DeterministicProvider:
    name: str = "deterministic"

    def complete_json(self, system_prompt: str, payload: dict) -> dict:
        return {"provider": self.name, "status": "skipped", "reason": "No live LLM configured."}


@dataclass
class OllamaProvider:
    base_url: str
    model: str
    timeout_seconds: int = 120
    name: str = "ollama"

    def complete_json(self, system_prompt: str, payload: dict) -> dict:
        body = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload)},
            ],
            "format": "json",
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=max(1, self.timeout_seconds)) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return {"provider": self.name, "status": "error", "reason": str(exc)}
        content = result.get("message", {}).get("content", "{}")
        return _parse_json_object(content)


@dataclass
class OpenAICompatibleProvider:
    base_url: str
    api_key: str
    model: str
    name: str = "openai_compatible"

    def complete_json(self, system_prompt: str, payload: dict) -> dict:
        body = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload)},
            ],
        }
        request = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return {"provider": self.name, "status": "error", "reason": str(exc)}
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        return _parse_json_object(content)


def make_llm_provider(settings: Settings) -> LLMProvider:
    if settings.openai_compatible_base_url and settings.openai_api_key:
        return OpenAICompatibleProvider(
            settings.openai_compatible_base_url,
            settings.openai_api_key,
            settings.openai_model,
        )
    if settings.ollama_base_url:
        return OllamaProvider(
            settings.ollama_base_url,
            settings.ollama_model,
            settings.ollama_timeout_seconds,
        )
    return DeterministicProvider()


def _parse_json_object(content: str) -> dict:
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return {"status": "unparseable", "raw": content[:1000]}
    return value if isinstance(value, dict) else {"status": "unexpected_type", "raw": value}
