from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app = FastAPI(title="AI Vulnerability Analyzer")


def allowed_suffix(filename: str) -> bool:
    return Path(filename).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def build_pipeline(provider: str, max_rounds: int, confidence_threshold: float) -> VulnerabilityPipeline:
    base_settings = Settings()
    settings = Settings(
        provider=provider or base_settings.provider,
        max_rounds=max_rounds,
        confidence_threshold=confidence_threshold,
    )
    return VulnerabilityPipeline(settings)


def render_index(
    request: Request,
    *,
    report=None,
    error: str | None = None,
    provider: str,
    max_rounds: int,
    confidence_threshold: float,
    status_code: int = 200,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "report": report,
            "error": error,
            "provider": provider,
            "max_rounds": max_rounds,
            "confidence_threshold": confidence_threshold,
        },
        status_code=status_code,
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    settings = Settings()
    return render_index(
        request,
        report=None,
        error=None,
        provider=settings.provider,
        max_rounds=settings.max_rounds,
        confidence_threshold=settings.confidence_threshold,
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    files: list[UploadFile] | None = File(default=None),
    pasted_code: str = Form(default=""),
    filename: str = Form(default="snippet.c"),
    provider: str = Form(default=""),
    max_rounds: int = Form(default=3),
    confidence_threshold: float = Form(default=0.8),
) -> HTMLResponse:
    default_settings = Settings()
    effective_provider = provider or default_settings.provider
    incoming_files = files or []
    if not incoming_files and not pasted_code.strip():
        return render_index(
            request,
            report=None,
            error="업로드한 파일이 없고 붙여넣은 코드도 비어 있습니다.",
            provider=effective_provider,
            max_rounds=max_rounds,
            confidence_threshold=confidence_threshold,
            status_code=400,
        )

    with tempfile.TemporaryDirectory(prefix="ai-vuln-analyzer-") as temp_dir:
        temp_path = Path(temp_dir)
        saved_files: list[str] = []

        for uploaded in incoming_files:
            if not uploaded.filename:
                continue
            if not allowed_suffix(uploaded.filename):
                continue
            destination = temp_path / Path(uploaded.filename).name
            with destination.open("wb") as handle:
                shutil.copyfileobj(uploaded.file, handle)
            saved_files.append(str(destination))

        if pasted_code.strip():
            safe_name = Path(filename).name or "snippet.c"
            if not allowed_suffix(safe_name):
                safe_name = f"{Path(safe_name).stem or 'snippet'}.c"
            destination = temp_path / safe_name
            destination.write_text(pasted_code, encoding="utf-8")
            saved_files.append(str(destination))

        if not saved_files:
            return render_index(
                request,
                report=None,
                error="지원되는 C/C++ 파일 확장자만 업로드할 수 있습니다.",
                provider=effective_provider,
                max_rounds=max_rounds,
                confidence_threshold=confidence_threshold,
                status_code=400,
            )

        try:
            pipeline = build_pipeline(effective_provider, max_rounds, confidence_threshold)
            report = pipeline.run(temp_path)
        except Exception as exc:
            message = str(exc).strip() or exc.__class__.__name__
            if "Connection error" in message or "APIConnectionError" in exc.__class__.__name__:
                message = (
                    "LLM provider 연결에 실패했습니다. OpenRouter/OpenAI 네트워크 접근, 키 값, 모델명, 방화벽 설정을 확인하세요."
                )
            return render_index(
                request,
                report=None,
                error=f"분석 중 오류가 발생했습니다: {message}",
                provider=effective_provider,
                max_rounds=max_rounds,
                confidence_threshold=confidence_threshold,
                status_code=500,
            )

    return render_index(
        request,
        report=report.model_dump(mode="json"),
        error=None,
        provider=effective_provider,
        max_rounds=max_rounds,
        confidence_threshold=confidence_threshold,
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


def main() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Install the 'web' extra to run the website: pip install -e .[web]") from exc
    settings = Settings()
    uvicorn.run("ai_vuln_analyzer.web.app:app", host=settings.web_host, port=settings.web_port, reload=False)


if __name__ == "__main__":
    main()
