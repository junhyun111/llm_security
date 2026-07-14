from __future__ import annotations

import asyncio
import multiprocessing
import queue
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ai_vuln_analyzer.analysis.dangerous_api import CPP_EXTENSIONS
from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline
from ai_vuln_analyzer.core.schemas import FinalReport

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app = FastAPI(title="AI Vulnerability Analyzer")
_SCAN_SEMAPHORE = asyncio.Semaphore(max(1, Settings().web_max_concurrent_scans))
CHUNK_SIZE = 64 * 1024


class UploadValidationError(ValueError):
    pass


class ScanTimeoutError(TimeoutError):
    pass


def allowed_suffix(filename: str) -> bool:
    return Path(filename).suffix.lower() in CPP_EXTENSIONS


def safe_upload_name(filename: str) -> str:
    if not filename or filename in {".", ".."}:
        raise UploadValidationError("파일 이름이 비어 있습니다.")
    if "/" in filename or "\\" in filename or Path(filename).name != filename:
        raise UploadValidationError("경로가 포함된 파일 이름은 허용되지 않습니다.")
    if not allowed_suffix(filename):
        raise UploadValidationError("C/C++ 소스 및 헤더 파일만 업로드할 수 있습니다.")
    return filename


async def save_upload_limited(
    uploaded: UploadFile,
    destination: Path,
    per_file_limit: int,
    remaining_total: int,
) -> int:
    written = 0
    with destination.open("wb") as handle:
        while chunk := await uploaded.read(CHUNK_SIZE):
            written += len(chunk)
            if written > per_file_limit:
                raise UploadValidationError(f"{destination.name} 파일이 크기 제한을 초과했습니다.")
            if written > remaining_total:
                raise UploadValidationError("전체 업로드 용량 제한을 초과했습니다.")
            handle.write(chunk)
    return written


def build_scan_settings(provider: str, max_rounds: int, confidence_threshold: float) -> Settings:
    base_settings = Settings()
    settings = Settings(
        provider=provider or base_settings.provider,
        max_rounds=max(1, max_rounds),
        confidence_threshold=max(0.0, min(confidence_threshold, 1.0)),
    )
    return settings


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
    settings = Settings()
    effective_provider = provider or settings.provider
    incoming_files = [file for file in (files or []) if file.filename]
    if not incoming_files and not pasted_code.strip():
        return _error_response(
            request, "업로드한 파일과 붙여넣은 코드가 모두 비어 있습니다.",
            effective_provider, max_rounds, confidence_threshold, 400,
        )
    if len(incoming_files) > settings.web_max_files:
        return _error_response(
            request, f"파일은 최대 {settings.web_max_files}개까지 업로드할 수 있습니다.",
            effective_provider, max_rounds, confidence_threshold, 413,
        )

    pasted_bytes = pasted_code.encode("utf-8")
    if len(pasted_bytes) > settings.web_max_file_bytes:
        return _error_response(
            request, "붙여넣은 코드가 파일 크기 제한을 초과했습니다.",
            effective_provider, max_rounds, confidence_threshold, 413,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="ai-vuln-analyzer-") as temp_dir:
            temp_path = Path(temp_dir)
            total_bytes = 0
            saved_names: set[str] = set()
            for uploaded in incoming_files:
                safe_name = safe_upload_name(uploaded.filename or "")
                if safe_name in saved_names:
                    raise UploadValidationError(f"중복된 파일 이름입니다: {safe_name}")
                destination = temp_path / safe_name
                try:
                    total_bytes += await save_upload_limited(
                        uploaded, destination, settings.web_max_file_bytes,
                        settings.web_max_total_bytes - total_bytes,
                    )
                finally:
                    await uploaded.close()
                saved_names.add(safe_name)

            if pasted_code.strip():
                safe_name = safe_upload_name(filename or "snippet.c")
                if safe_name in saved_names:
                    raise UploadValidationError(f"중복된 파일 이름입니다: {safe_name}")
                if total_bytes + len(pasted_bytes) > settings.web_max_total_bytes:
                    raise UploadValidationError("전체 업로드 용량 제한을 초과했습니다.")
                (temp_path / safe_name).write_bytes(pasted_bytes)

            scan_settings = build_scan_settings(effective_provider, max_rounds, confidence_threshold)
            report = await _run_pipeline_limited(
                scan_settings, temp_path, settings.web_scan_timeout_seconds,
            )
    except UploadValidationError as exc:
        return _error_response(
            request, str(exc), effective_provider, max_rounds, confidence_threshold, 413,
        )
    except ScanTimeoutError:
        return _error_response(
            request, "분석 제한 시간을 초과했습니다.",
            effective_provider, max_rounds, confidence_threshold, 504,
        )
    except Exception as exc:
        message = str(exc).strip() or exc.__class__.__name__
        return _error_response(
            request, f"분석 중 오류가 발생했습니다: {message}",
            effective_provider, max_rounds, confidence_threshold, 500,
        )

    return render_index(
        request,
        report=report.model_dump(mode="json"),
        provider=effective_provider,
        max_rounds=max_rounds,
        confidence_threshold=confidence_threshold,
    )


async def _run_pipeline_limited(
    settings: Settings, temp_path: Path, timeout_seconds: int
) -> FinalReport:
    async with _SCAN_SEMAPHORE:
        return await asyncio.to_thread(
            _run_pipeline_process, settings.model_dump(mode="json"), str(temp_path), timeout_seconds
        )


def _run_pipeline_process(settings_data: dict, target_path: str, timeout_seconds: int) -> FinalReport:
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_pipeline_worker,
        args=(settings_data, target_path, result_queue),
        daemon=True,
    )
    process.start()
    try:
        status, payload = result_queue.get(timeout=max(1, timeout_seconds))
    except queue.Empty as exc:
        timed_out = process.is_alive()
        if timed_out:
            process.terminate()
            process.join(5)
        result_queue.close()
        if not timed_out:
            raise RuntimeError(
                f"Analysis process exited without a result (exit code {process.exitcode})."
            ) from exc
        raise ScanTimeoutError("Analysis process exceeded its time limit.") from exc
    process.join(5)
    if process.is_alive():
        process.terminate()
        process.join(5)
    result_queue.close()
    if status == "error":
        raise RuntimeError(payload)
    return FinalReport.model_validate(payload)


def _pipeline_worker(settings_data: dict, target_path: str, result_queue) -> None:
    try:
        report = VulnerabilityPipeline(Settings.model_validate(settings_data)).run(target_path)
        result_queue.put(("ok", report.model_dump(mode="json")))
    except Exception as exc:
        result_queue.put(("error", str(exc).strip() or exc.__class__.__name__))


def _error_response(
    request: Request,
    message: str,
    provider: str,
    max_rounds: int,
    confidence_threshold: float,
    status_code: int,
) -> HTMLResponse:
    return render_index(
        request,
        error=message,
        provider=provider,
        max_rounds=max_rounds,
        confidence_threshold=confidence_threshold,
        status_code=status_code,
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
