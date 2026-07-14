from __future__ import annotations

from ai_vuln_analyzer.agents.integer_agent import IntegerAgent
from ai_vuln_analyzer.agents.null_uninit_agent import NullUninitAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.llm.mock_client import MockLLMClient


def test_integer_and_null_agents_use_semantic_events(tmp_path):
    source = tmp_path / "memory.c"
    source.write_text(r'''
        #include <stdlib.h>
        #include <string.h>
        void copy_values(size_t count, int *input) {
            int *values = malloc(count * sizeof(int));
            memcpy(values, input, count * sizeof(int));
        }
    ''', encoding="utf-8")
    analysis = AstAnalyzer().analyze(source)
    llm = MockLLMClient()

    integer_findings = IntegerAgent(llm).run([analysis], [])
    null_findings = NullUninitAgent(llm).run([analysis], [])

    assert any(finding.cwe == "CWE-190" for finding in integer_findings)
    assert any(finding.cwe == "CWE-476" for finding in null_findings)


def test_null_agent_understands_guard_control_flow(tmp_path):
    source = tmp_path / "guarded.c"
    source.write_text(r'''
        #include <stdlib.h>
        void guarded(void) {
            int *value = malloc(sizeof(int));
            if (value == NULL) return;
            *value = 1;
        }
    ''', encoding="utf-8")
    analysis = AstAnalyzer().analyze(source)

    findings = NullUninitAgent(MockLLMClient()).run([analysis], [])

    assert not findings
