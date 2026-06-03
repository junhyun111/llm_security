from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.schemas import AnalysisBundle, PipelineArtifacts


class PipelineContext(BaseModel):
    root_path: Path
    settings: Settings
    analysis: AnalysisBundle = Field(default_factory=AnalysisBundle)
    artifacts: PipelineArtifacts | None = None
