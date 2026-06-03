from __future__ import annotations

import os
import json
from pathlib import Path

from pydantic import BaseModel, Field


def load_dotenv(dotenv_path: str | Path = ".env") -> None:
    path = Path(dotenv_path)
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_dotenv()


def load_project_config(config_path: str | Path = "project_config.json") -> dict:
    path = Path(config_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return data


PROJECT_CONFIG = load_project_config()


def config_value(key: str, default=None):
    if key in PROJECT_CONFIG and PROJECT_CONFIG[key] not in (None, ""):
        return PROJECT_CONFIG[key]
    return os.getenv(key.upper(), default)


class Settings(BaseModel):
    provider: str = Field(default_factory=lambda: config_value("provider", "mock"))
    openai_api_key: str | None = Field(default_factory=lambda: config_value("openai_api_key"))
    openai_model: str = Field(default_factory=lambda: config_value("openai_model", "gpt-4.1-mini"))
    anthropic_api_key: str | None = Field(default_factory=lambda: config_value("anthropic_api_key"))
    anthropic_model: str = Field(default_factory=lambda: config_value("anthropic_model", "claude-3-5-sonnet-latest"))
    openrouter_api_key: str | None = Field(default_factory=lambda: config_value("openrouter_api_key"))
    openrouter_model: str = Field(default_factory=lambda: config_value("openrouter_model", "openai/gpt-4.1-mini"))
    openrouter_base_url: str = Field(default_factory=lambda: config_value("openrouter_base_url", "https://openrouter.ai/api/v1"))
    openrouter_site_url: str | None = Field(default_factory=lambda: config_value("openrouter_site_url"))
    openrouter_app_name: str | None = Field(default_factory=lambda: config_value("openrouter_app_name", "ai-vuln-analyzer"))
    max_rounds: int = Field(default_factory=lambda: int(config_value("max_rounds", 3)))
    confidence_threshold: float = Field(default_factory=lambda: float(config_value("confidence_threshold", 0.8)))
    output_path: Path = Field(default_factory=lambda: Path(config_value("output_path", "report.md")))
    json_output_path: Path = Field(default_factory=lambda: Path(config_value("json_output_path", "report.json")))
    verbose: bool = Field(default_factory=lambda: str(config_value("verbose", "false")).lower() == "true")
    web_host: str = Field(default_factory=lambda: config_value("web_host", "127.0.0.1"))
    web_port: int = Field(default_factory=lambda: int(config_value("web_port", 8000)))

    @property
    def provider_normalized(self) -> str:
        return self.provider.lower().strip()
