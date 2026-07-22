from __future__ import annotations

from ai_vuln_analyzer.agents.semantic_agents import (
    CommandInjectionAgent,
    FormatStringAgent,
    OffByOneAgent,
    PathTraversalAgent,
    UnsafeInputAgent,
    WeakRandomAgent,
)
from ai_vuln_analyzer.agents.bof_oob_agent import BofOobAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.config import Settings
from ai_vuln_analyzer.core.pipeline import VulnerabilityPipeline
from ai_vuln_analyzer.llm.mock_client import MockLLMClient


SAMPLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_admin_task(char *task) {
    char command[64];
    strcpy(command, "echo Running task: ");
    strcat(command, task);
    system(command);
}

void print_user(char *name) {
    printf(name);
}

void read_user_file(char *name) {
    FILE *fp = fopen(name, "r");
    if (fp) fclose(fp);
}

void read_line(void) {
    char value[16];
    gets(value);
}

int make_password(void) {
    int password = rand();
    return password;
}

void fill(void) {
    int values[10];
    for (int i = 0; i <= 10; ++i) {
        values[i] = i;
    }
}
'''


def test_tree_sitter_builds_semantic_ir_and_taint(tmp_path):
    source = tmp_path / "vulnerable.c"
    source.write_text(SAMPLE, encoding="utf-8")

    analysis = AstAnalyzer().analyze(source)

    assert analysis.parser == "tree-sitter"
    assert {function.name for function in analysis.functions} >= {
        "run_admin_task", "print_user", "read_user_file"
    }
    system_call = next(event for event in analysis.events if event.callee == "system")
    assert system_call.tainted_arguments == [0]
    assert "parameter:task" in system_call.taint_sources
    assert any(edge.target == "command" and edge.kind == "copy" for edge in analysis.data_flow_edges)


def test_semantic_agents_cover_non_memory_vulnerabilities(tmp_path):
    source = tmp_path / "vulnerable.c"
    source.write_text(SAMPLE, encoding="utf-8")
    analysis = AstAnalyzer().analyze(source)
    llm = MockLLMClient()
    agents = [
        CommandInjectionAgent(llm),
        FormatStringAgent(llm),
        PathTraversalAgent(llm),
        UnsafeInputAgent(llm),
        WeakRandomAgent(llm),
        OffByOneAgent(llm),
    ]

    cwes = {finding.cwe for agent in agents for finding in agent.run([analysis], [])}

    assert {"CWE-78", "CWE-134", "CWE-22", "CWE-242", "CWE-338", "CWE-193"} <= cwes


def test_safe_literal_copy_is_not_reported_as_the_admin_task_root_cause(tmp_path):
    source = tmp_path / "vulnerable.c"
    source.write_text(SAMPLE, encoding="utf-8")
    analysis = AstAnalyzer().analyze(source)

    findings = BofOobAgent(MockLLMClient()).run([analysis], [])
    lines = {finding.location.line_start for finding in findings}

    assert 8 not in lines
    assert 9 in lines


def test_pipeline_does_not_filter_unpredicted_agent_families(tmp_path):
    source = tmp_path / "vulnerable.c"
    source.write_text(SAMPLE, encoding="utf-8")

    report = VulnerabilityPipeline(Settings(provider="mock")).run(source)
    cwes = {finding.cwe for finding in report.artifacts.findings}

    assert {"CWE-78", "CWE-134", "CWE-22", "CWE-242", "CWE-338", "CWE-193"} <= cwes
