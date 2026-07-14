from __future__ import annotations

import time
from collections.abc import Callable

from ai_vuln_analyzer.llm.base import LLMClient


class ResilientLLMClient(LLMClient):
    """Retries transient provider failures and preserves static analysis on outage."""

    def __init__(
        self,
        client: LLMClient,
        max_retries: int = 2,
        base_delay_seconds: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.max_retries = max(0, max_retries)
        self.base_delay_seconds = max(0.0, base_delay_seconds)
        self.sleep = sleep
        self.last_error: str | None = None

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        for attempt in range(self.max_retries + 1):
            try:
                return self.client.complete(system_prompt, user_prompt)
            except Exception as exc:  # Provider SDKs expose different exception trees.
                self.last_error = str(exc).strip() or exc.__class__.__name__
                if attempt >= self.max_retries or not self._is_transient(exc):
                    return ""
                self.sleep(self._retry_delay(exc, attempt))
        return ""

    def _is_transient(self, exc: Exception) -> bool:
        status = getattr(exc, "status_code", None)
        if status in {408, 409, 429} or isinstance(status, int) and status >= 500:
            return True
        name = exc.__class__.__name__.lower()
        message = str(exc).lower()
        return any(token in f"{name} {message}" for token in {
            "timeout", "connection", "rate limit", "rate-limit", "temporarily", "429",
        })

    def _retry_delay(self, exc: Exception, attempt: int) -> float:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None) or getattr(exc, "headers", None)
        if headers:
            retry_after = headers.get("retry-after") or headers.get("Retry-After")
            try:
                return max(0.0, min(float(retry_after), 30.0))
            except (TypeError, ValueError):
                pass
        return min(self.base_delay_seconds * (2**attempt), 30.0)
