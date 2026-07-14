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
    parameters: list[str] = Field(default_factory=list)
    array_sizes: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class SemanticEvent(BaseModel):
    kind: Literal["call", "assignment", "declaration", "condition", "return"]
    line_start: int
    line_end: int
    function: str | None = None
    text: str
    callee: str | None = None
    arguments: list[str] = Field(default_factory=list)
    target: str | None = None
    identifiers: list[str] = Field(default_factory=list)
    tainted_arguments: list[int] = Field(default_factory=list)
    taint_sources: list[str] = Field(default_factory=list)
    control_kind: Literal["if", "for", "while", "do", "switch"] | None = None
    scope_end_line: int | None = None


class DataFlowEdge(BaseModel):
    source: str
    target: str
    line: int
    function: str | None = None
    kind: Literal["assignment", "copy", "input", "return", "call", "global", "alias"]


class AstAnalysis(BaseModel):
    file: str
    language: str
    parser: str
    functions: list[FunctionSummary] = Field(default_factory=list)
    dangerous_calls: list[dict] = Field(default_factory=list)
    events: list[SemanticEvent] = Field(default_factory=list)
    data_flow_edges: list[DataFlowEdge] = Field(default_factory=list)
    parse_errors: int = 0


class CfgNode(BaseModel):
    id: str
    label: str
    line_start: int | None = None
    line_end: int | None = None


class CfgEdge(BaseModel):
    source: str
    target: str
    kind: Literal["flow", "branch", "loop", "call", "return"] = "flow"


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
    finding_role: Literal["primary", "secondary"] = "primary"
    related_finding_id: str | None = None


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
    parse_succeeded: bool | None = None
    compile_succeeded: bool | None = None
    vulnerability_re_detected: bool | None = None
    compiler_output: str | None = None
    introduced_identifiers: list[str] = Field(default_factory=list)


class PatchConflict(BaseModel):
    file: str
    line_start: int
    line_end: int
    finding_ids: list[str] = Field(default_factory=list)
    reason: str


class IntegratedPatchVerification(BaseModel):
    applied_finding_ids: list[str] = Field(default_factory=list)
    skipped_finding_ids: list[str] = Field(default_factory=list)
    conflicts: list[PatchConflict] = Field(default_factory=list)
    parse_succeeded: bool
    compile_succeeded: bool | None = None
    re_detected_finding_ids: list[str] = Field(default_factory=list)
    verified: bool = False
    reason: str
    compiler_output: str | None = None


class AnalysisFailure(BaseModel):
    file: str
    stage: Literal["ast", "cfg"]
    error: str


class AnalysisBundle(BaseModel):
    ast: list[AstAnalysis] = Field(default_factory=list)
    cfg: list[CfgAnalysis] = Field(default_factory=list)


class PipelineArtifacts(BaseModel):
    analyzed_files: list[str] = Field(default_factory=list)
    planner_decision: PlannerDecision
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    patches: list[PatchSuggestion] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    integrated_verification: IntegratedPatchVerification | None = None
    analysis_failures: list[AnalysisFailure] = Field(default_factory=list)
    llm_warning: str | None = None
    rounds: int = 1


class FinalReport(BaseModel):
    summary: dict
    artifacts: PipelineArtifacts
