from __future__ import annotations

import argparse
from pathlib import Path

from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline
from ai_vuln_analyzer.output.json_writer import write_json_report
from ai_vuln_analyzer.output.markdown_writer import write_markdown_report

def scan(
    target_path: str,
    provider: str | None = None,
    max_rounds: int | None = None,
    confidence_threshold: float | None = None,
    output: Path | None = None,
    json_output: Path | None = None,
    verbose: bool | None = None,
) -> None:
    overrides = {}
    if provider is not None:
        overrides["provider"] = provider
    if max_rounds is not None:
        overrides["max_rounds"] = max_rounds
    if confidence_threshold is not None:
        overrides["confidence_threshold"] = confidence_threshold
    if output is not None:
        overrides["output_path"] = output
    if json_output is not None:
        overrides["json_output_path"] = json_output
    if verbose is not None:
        overrides["verbose"] = verbose
    settings = Settings(**overrides)
    pipeline = VulnerabilityPipeline(settings)
    report = pipeline.run(target_path)
    write_markdown_report(settings.output_path, report)
    write_json_report(settings.json_output_path, report)
    print(f"Markdown report: {settings.output_path}")
    print(f"JSON report: {settings.json_output_path}")
    print(f"Findings: {report.summary['total_findings']}")


def app() -> None:
    parser = argparse.ArgumentParser(description="C/C++ AI vulnerability analysis and verification CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a C/C++ file or directory")
    scan_parser.add_argument("target_path")
    scan_parser.add_argument("--provider", default=None, choices=["mock", "openai", "anthropic", "openrouter"])
    scan_parser.add_argument("--max-rounds", type=int, default=None)
    scan_parser.add_argument("--confidence-threshold", type=float, default=None)
    scan_parser.add_argument("--output", type=Path, default=None)
    scan_parser.add_argument("--json-output", type=Path, default=None)
    scan_parser.add_argument("--verbose", action="store_true", default=None)

    serve_parser = subparsers.add_parser("serve", help="Run the web interface")
    serve_parser.add_argument("--host", default=None)
    serve_parser.add_argument("--port", type=int, default=None)

    args = parser.parse_args()
    if args.command == "scan":
        scan(
            target_path=args.target_path,
            provider=args.provider,
            max_rounds=args.max_rounds,
            confidence_threshold=args.confidence_threshold,
            output=args.output,
            json_output=args.json_output,
            verbose=args.verbose,
        )
    if args.command == "serve":
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError("Install the 'web' extra to use the web UI: pip install -e .[web]") from exc
        from ai_vuln_analyzer.config import Settings

        settings = Settings()
        uvicorn.run(
            "ai_vuln_analyzer.web.app:app",
            host=args.host or settings.web_host,
            port=args.port or settings.web_port,
            reload=False,
        )


if __name__ == "__main__":
    app()
