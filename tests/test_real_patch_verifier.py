from __future__ import annotations

from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
from ai_vuln_analyzer.agents.verifier import Verifier
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
from ai_vuln_analyzer.core.schemas import CodeLocation, PatchSuggestion, VulnerabilityFinding
from ai_vuln_analyzer.llm.mock_client import MockLLMClient
from ai_vuln_analyzer.verifier.real_patch import RealPatchValidator


def _finding(path: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id="bof", cwe="CWE-121", vulnerability_type="Buffer Overflow",
        location=CodeLocation(file=path, function="copy_value", line_start=5, line_end=5),
        source="parameter:input", sink="strcpy", evidence="unbounded copy",
        agent_name="bof_oob_agent", confidence=0.9,
    )


def _patch() -> PatchSuggestion:
    return PatchSuggestion(
        finding_id="bof", explanation="bounded copy",
        original_code="    strcpy(buffer, input);",
        patched_code='    snprintf(buffer, sizeof(buffer), "%s", input);',
        confidence=0.82,
    )


def test_real_patch_is_applied_parsed_and_reanalyzed(tmp_path):
    source = tmp_path / "copy.c"
    source.write_text(r'''#include <stdio.h>
#include <string.h>
void copy_value(char *input) {
    char buffer[8];
    strcpy(buffer, input);
}
''', encoding="utf-8")
    ast = AstAnalyzer()
    cfg = CfgAnalyzer(ast)
    agent = BofOobAgent(MockLLMClient())

    result = RealPatchValidator(ast, cfg).validate(_finding(str(source)), _patch(), [agent])

    assert result.parse_succeeded is True
    assert result.vulnerability_re_detected is False
    assert result.compile_succeeded in {True, None}


def test_verifier_requires_compile_and_clean_agent_rerun(tmp_path, monkeypatch):
    source = tmp_path / "copy.c"
    source.write_text(r'''#include <stdio.h>
#include <string.h>
void copy_value(char *input) {
    char buffer[8];
    strcpy(buffer, input);
}
''', encoding="utf-8")
    agent = BofOobAgent(MockLLMClient())
    verifier = Verifier([agent], confidence_threshold=0.8)
    monkeypatch.setattr(
        verifier.real_patch_validator,
        "_compile_pair",
        lambda original_path, original_code, patched_path: (True, None),
    )

    result = verifier.verify([_finding(str(source))], [_patch()])[0]

    assert result.verified is True
    assert result.compile_succeeded is True
    assert result.vulnerability_re_detected is False
