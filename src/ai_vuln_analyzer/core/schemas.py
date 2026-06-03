from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CodeLocation(BaseModel):
    file: str
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None


class FunctionSummary(BaseModel):
    file: str
    name: str
    line_start: int
    line_end: int
    calls: list[str] = Field(default_factory=list)
    locals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AstAnalysis(BaseModel):
    file: str
    language: str
    parser: str
    functions: list[FunctionSummary] = Field(default_factory=list)
    dangerous_calls: list[dict] = Field(default_factory=list)


class CfgNode(BaseModel):
    id: str
    label: str
    line_start: int | None = None
    line_end: int | None = None


class CfgEdge(BaseModel):
    source: str
    target: str
    kind: Literal["flow", "branch", "call"] = "flow"


class CfgAnalysis(BaseModel):
    file: str
    nodes: list[CfgNode] = Field(default_factory=list)
    edges: list[CfgEdge] = Field(default_factory=list)


class PlannerDecision(BaseModel):
    candidate_cwes: list[str] = Field(default_factory=list)
    rationale: str = ""
    related_files: list[str] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    id: str
    cwe: str
    vulnerability_type: str
    location: CodeLocation
    source: str | None = None
    sink: str | None = None
    evidence: str
    agent_name: str
    confidence: float
    status: Literal["candidate", "verified", "rejected", "patched", "unresolved"] = "candidate"
    root_cause: str | None = None


class PatchSuggestion(BaseModel):
    finding_id: str
    explanation: str
    original_code: str
    patched_code: str
    diff: str | None = None
    confidence: float


class VerificationResult(BaseModel):
    finding_id: str
    verified: bool
    confidence: float
    reason: str
    rerun_agents: list[str] = Field(default_factory=list)
    remaining_risks: list[str] = Field(default_factory=list)


class AnalysisBundle(BaseModel):
    ast: list[AstAnalysis] = Field(default_factory=list)
    cfg: list[CfgAnalysis] = Field(default_factory=list)


class PipelineArtifacts(BaseModel):
    analyzed_files: list[str] = Field(default_factory=list)
    planner_decision: PlannerDecision
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    patches: list[PatchSuggestion] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    rounds: int = 1


class FinalReport(BaseModel):
    summary: dict
    artifacts: PipelineArtifacts
