from __future__ import annotations

from ai_vuln_analyzer.agents.student import Student
from ai_vuln_analyzer.core.schemas import CodeLocation, PatchSuggestion, VulnerabilityFinding
from ai_vuln_analyzer.llm.mock_client import MockLLMClient


def _finding(path: str, *, cwe: str, sink: str, source: str = "name") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id="finding", cwe=cwe, vulnerability_type="test",
        location=CodeLocation(file=path, line_start=1, line_end=1),
        source=source, sink=sink, evidence="test", agent_name="test", confidence=0.9,
    )


def test_strcpy_patch_preserves_original_identifiers(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("strcpy(users[user_count].name, name);\n", encoding="utf-8")

    patch = Student(MockLLMClient()).generate_patches([
        _finding(str(source), cwe="CWE-121", sink="strcpy")
    ])[0]

    assert "input" not in patch.patched_code
    assert "users[user_count].name" in patch.patched_code
    assert "name" in patch.patched_code


def test_uaf_patch_uses_finding_pointer_name(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text('free(scores);\nprintf("%d", scores[0]);\n', encoding="utf-8")

    patch = Student(MockLLMClient()).generate_patches([
        VulnerabilityFinding(
            id="finding", cwe="CWE-416", vulnerability_type="Use-After-Free",
            location=CodeLocation(file=str(source), line_start=1, line_end=2),
            source="scores", sink="free/use", evidence="test", agent_name="test", confidence=0.9,
        )
    ])[0]

    assert "p =" not in patch.patched_code
    assert "scores = NULL;" in patch.patched_code
    assert "scores[0]" not in patch.patched_code


def test_patch_validator_rejects_new_unknown_identifier(tmp_path):
    from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
    from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
    from ai_vuln_analyzer.analysis.cfg_analyzer import CfgAnalyzer
    from ai_vuln_analyzer.verifier.real_patch import RealPatchValidator

    source = tmp_path / "sample.c"
    source.write_text("void copy(char *name) {\n    char buffer[8];\n    strcpy(buffer, name);\n}\n", encoding="utf-8")
    finding = VulnerabilityFinding(
        id="bad", cwe="CWE-121", vulnerability_type="Buffer Overflow",
        location=CodeLocation(file=str(source), function="copy", line_start=3, line_end=3),
        source="parameter:name", sink="strcpy", evidence="test", agent_name="test", confidence=0.9,
    )
    patch = PatchSuggestion(
        finding_id="bad", explanation="bad", original_code="strcpy(buffer, name);",
        patched_code='snprintf(buffer, sizeof(buffer), "%s", input);', confidence=0.5,
    )
    ast = AstAnalyzer()
    validator = RealPatchValidator(ast, CfgAnalyzer(ast))

    result = validator.validate(finding, patch, [BofOobAgent(MockLLMClient())])

    assert result.introduced_identifiers == ("input",)
