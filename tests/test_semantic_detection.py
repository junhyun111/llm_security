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
from ai_vuln_analyzer.agents.uaf_df_agent import UafDfAgent
from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer
from ai_vuln_analyzer.analysis.program_flow import link_program_taint
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


def test_program_flow_links_shared_fields_and_function_returns(tmp_path):
    source = tmp_path / "interprocedural.c"
    source.write_text(r'''
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        typedef struct { char name[32]; } User;
        User users[1];
        void save(char *name) { strcpy(users[0].name, name); }
        void show(void) { printf(users[0].name); }
        char *identity(char *value) { return value; }
        void execute(char *input) {
            char *command = identity(input);
            system(command);
        }
    ''', encoding="utf-8")

    analysis = link_program_taint([AstAnalyzer().analyze(source)])[0]
    printf_call = next(event for event in analysis.events if event.callee == "printf")
    system_call = next(event for event in analysis.events if event.callee == "system")

    assert printf_call.tainted_arguments == [0]
    assert "parameter:name" in printf_call.taint_sources
    assert system_call.tainted_arguments == [0]
    assert "parameter:input" in system_call.taint_sources


def test_uaf_tracks_pointer_aliases(tmp_path):
    source = tmp_path / "alias.c"
    source.write_text(r'''
        #include <stdlib.h>
        int read_after_free(void) {
            int *p = malloc(sizeof(int));
            int *q = p;
            free(q);
            return *p;
        }
    ''', encoding="utf-8")
    analysis = AstAnalyzer().analyze(source)

    findings = UafDfAgent(MockLLMClient()).run([analysis], [])

    assert any(finding.cwe == "CWE-416" and finding.source == "p" for finding in findings)


def test_program_flow_links_shared_storage_across_files(tmp_path):
    writer = tmp_path / "writer.c"
    reader = tmp_path / "reader.c"
    writer.write_text(r'''
        #include <string.h>
        char stored_name[32];
        void save_name(char *name) { strcpy(stored_name, name); }
    ''', encoding="utf-8")
    reader.write_text(r'''
        #include <stdio.h>
        extern char stored_name[32];
        void show_name(void) { printf(stored_name); }
    ''', encoding="utf-8")

    analyses = link_program_taint([
        AstAnalyzer().analyze(writer), AstAnalyzer().analyze(reader)
    ])
    printf_call = next(
        event for analysis in analyses for event in analysis.events if event.callee == "printf"
    )

    assert printf_call.tainted_arguments == [0]
    assert "parameter:name" in printf_call.taint_sources


def test_pipeline_does_not_filter_unpredicted_agent_families(tmp_path):
    source = tmp_path / "vulnerable.c"
    source.write_text(SAMPLE, encoding="utf-8")

    report = VulnerabilityPipeline(Settings(provider="mock")).run(source)
    cwes = {finding.cwe for finding in report.artifacts.findings}

    assert {"CWE-78", "CWE-134", "CWE-22", "CWE-242", "CWE-338", "CWE-193"} <= cwes
    command = next(finding for finding in report.artifacts.findings if finding.cwe == "CWE-78")
    related_bof = next(
        finding for finding in report.artifacts.findings
        if finding.cwe in {"CWE-121", "CWE-787"}
        and finding.location.function == "run_admin_task"
        and finding.finding_role == "secondary"
    )
    assert related_bof.related_finding_id == command.id
