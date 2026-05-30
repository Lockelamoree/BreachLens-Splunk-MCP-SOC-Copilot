from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_dotenv(path: Path | None = None) -> None:
    env_path = path or repo_root() / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass(frozen=True)
class Settings:
    mode: str
    cors_origins: list[str]
    splunk_index: str
    splunk_base_url: str
    splunk_ui_url: str
    splunk_username: str
    splunk_password: str
    splunk_token: str
    splunk_verify_tls: bool
    splunk_mcp_url: str
    splunk_mcp_token: str
    sample_data_dir: Path
    ollama_base_url: str
    ollama_model: str
    ollama_timeout_seconds: int
    openai_compatible_base_url: str
    openai_api_key: str
    openai_model: str


def _bool_from_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_from_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _csv_env(name: str, default: str) -> list[str]:
    return [part.strip() for part in os.getenv(name, default).split(",") if part.strip()]


def load_settings() -> Settings:
    load_dotenv()
    root = repo_root()
    return Settings(
        mode=os.getenv("BREACHLENS_MODE", "sample").strip().lower(),
        cors_origins=_csv_env(
            "BREACHLENS_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ),
        splunk_index=os.getenv("SPLUNK_INDEX", "breachlens"),
        splunk_base_url=os.getenv("SPLUNK_BASE_URL", "https://localhost:18089").rstrip("/"),
        splunk_ui_url=os.getenv("SPLUNK_UI_URL", "http://127.0.0.1:18000").rstrip("/"),
        splunk_username=os.getenv("SPLUNK_USERNAME", "admin"),
        splunk_password=os.getenv("SPLUNK_PASSWORD", ""),
        splunk_token=os.getenv("SPLUNK_TOKEN", ""),
        splunk_verify_tls=_bool_from_env("SPLUNK_VERIFY_TLS", False),
        splunk_mcp_url=os.getenv("SPLUNK_MCP_URL", ""),
        splunk_mcp_token=os.getenv("SPLUNK_MCP_TOKEN", ""),
        sample_data_dir=Path(os.getenv("BREACHLENS_SAMPLE_DATA_DIR", root / "sample_data")),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "").rstrip("/"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1"),
        ollama_timeout_seconds=_int_from_env("OLLAMA_TIMEOUT_SECONDS", 120),
        openai_compatible_base_url=os.getenv("OPENAI_COMPATIBLE_BASE_URL", "").rstrip("/"),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
    )
