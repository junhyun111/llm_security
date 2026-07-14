from __future__ import annotations

from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.core.schemas import CodeLocation, PatchSuggestion, VulnerabilityFinding
from ai_vuln_analyzer.llm.mock_client import MockLLMClient
from ai_vuln_analyzer.verifier.integrated_patch import IntegratedPatchValidator
from ai_vuln_analyzer.verifier.real_patch import RealPatchValidator


def _finding(path: str, finding_id: str, function: str, line: int) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id=finding_id, cwe="CWE-121", vulnerability_type="Buffer Overflow",
        location=CodeLocation(file=path, function=function, line_start=line, line_end=line),
        source="parameter:input", sink="strcpy", evidence="unbounded copy",
        agent_name="bof_oob_agent", confidence=0.9,
    )


def _patch(finding_id: str, target: str) -> PatchSuggestion:
    return PatchSuggestion(
        finding_id=finding_id, explanation="bounded copy", original_code="",
        patched_code=f'    snprintf({target}, sizeof({target}), "%s", input);', confidence=0.82,
    )


def _validator():
    ast = AstAnalyzer()
    cfg = CfgAnalyzer(ast)
    real = RealPatchValidator(ast, cfg)
    return IntegratedPatchValidator(ast, cfg, real)


def test_integrated_patch_merges_non_overlapping_edits(tmp_path):
    source = tmp_path / "multiple.c"
    source.write_text(r'''#include <stdio.h>
#include <string.h>
void first(char *input) {
    char first_buffer[8];
    strcpy(first_buffer, input);
}
void second(char *input) {
    char second_buffer[8];
    strcpy(second_buffer, input);
}
''', encoding="utf-8")
    findings = [
        _finding(str(source), "first", "first", 5),
        _finding(str(source), "second", "second", 9),
    ]
    patches = [_patch("first", "first_buffer"), _patch("second", "second_buffer")]
    agent = BofOobAgent(MockLLMClient())

    result = _validator().validate(findings, patches, [source], [agent])

    assert result.applied_finding_ids == ["first", "second"]
    assert result.conflicts == []
    assert result.parse_succeeded is True
    assert result.re_detected_finding_ids == []


def test_integrated_patch_reports_overlapping_rewrites(tmp_path):
    source = tmp_path / "conflict.c"
    source.write_text("void run(char *input) {\n    strcpy(buffer, input);\n}\n", encoding="utf-8")
    findings = [
        _finding(str(source), "one", "run", 2),
        _finding(str(source), "two", "run", 2),
    ]
    patches = [_patch("one", "buffer"), PatchSuggestion(
        finding_id="two", explanation="different", original_code="",
        patched_code="    return;", confidence=0.5,
    )]

    result = _validator().validate(findings, patches, [source], [])

    assert len(result.conflicts) == 1
    assert result.applied_finding_ids == []
    assert result.skipped_finding_ids == ["one", "two"]
