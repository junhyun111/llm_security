from __future__ import annotations

import re

from ai_vuln_analyzer.agents.base import BaseAgent
from ai_vuln_analyzer.core.schemas import AstAnalysis, CfgAnalysis, SemanticEvent, VulnerabilityFinding


def _api(event: SemanticEvent) -> str:
    return (event.callee or "").split("::")[-1].split("->")[-1].split(".")[-1]


class CommandInjectionAgent(BaseAgent):
    agent_name = "command_injection_agent"
    covered_cwes = ("CWE-78",)

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            for event in item.events:
                if event.kind == "call" and _api(event) in {"system", "popen"} and 0 in event.tainted_arguments:
                    findings.append(self._finding(item, event))
        return findings

    def _finding(self, item: AstAnalysis, event: SemanticEvent) -> VulnerabilityFinding:
        api = _api(event)
        return self._build_finding(
            finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
            cwe="CWE-78", vulnerability_type="OS Command Injection", file=item.file,
            function=event.function, line_start=event.line_start, line_end=event.line_end,
            source=", ".join(event.taint_sources), sink=api,
            evidence=f"Untrusted data reaches {api}'s command argument: {event.text.strip()}", confidence=0.93,
        )


class FormatStringAgent(BaseAgent):
    agent_name = "format_string_agent"
    covered_cwes = ("CWE-134",)
    FORMAT_INDEX = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            for event in item.events:
                api = _api(event)
                if event.kind != "call" or api not in self.FORMAT_INDEX:
                    continue
                index = self.FORMAT_INDEX[api]
                if index >= len(event.arguments):
                    continue
                argument = event.arguments[index].strip()
                if argument.startswith('"'):
                    continue
                is_tainted = index in event.tainted_arguments
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-134", vulnerability_type="Externally Controlled Format String",
                    file=item.file, function=event.function, line_start=event.line_start, line_end=event.line_end,
                    source=", ".join(event.taint_sources) or "non-literal format expression", sink=api,
                    evidence=(f"{'Tainted' if is_tainted else 'Non-literal'} expression '{argument}' "
                              f"is used as the {api} format string."),
                    confidence=0.94 if is_tainted else 0.76,
                ))
        return findings


class PathTraversalAgent(BaseAgent):
    agent_name = "path_traversal_agent"
    covered_cwes = ("CWE-22",)
    PATH_INDEX = {"fopen": 0, "open": 0, "remove": 0, "unlink": 0, "rename": 0}

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            for event in item.events:
                api = _api(event)
                index = self.PATH_INDEX.get(api)
                if event.kind != "call" or index is None or index >= len(event.arguments):
                    continue
                path_argument = event.arguments[index].strip()
                if path_argument.startswith('"'):
                    continue
                is_tainted = index in event.tainted_arguments
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-22", vulnerability_type="Path Traversal",
                    file=item.file, function=event.function, line_start=event.line_start, line_end=event.line_end,
                    source=", ".join(event.taint_sources) or "non-literal path expression", sink=api,
                    evidence=f"A {'tainted' if is_tainted else 'non-literal'} path reaches {api} without a visible canonicalization or base-directory check.",
                    confidence=0.86 if is_tainted else 0.68,
                ))
        return findings


class UnsafeInputAgent(BaseAgent):
    agent_name = "unsafe_input_agent"
    covered_cwes = ("CWE-120", "CWE-242")

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            for event in item.events:
                api = _api(event)
                unsafe = api == "gets" or (api in {"scanf", "fscanf"} and self._has_unbounded_string(event))
                if event.kind != "call" or not unsafe:
                    continue
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-242" if api == "gets" else "CWE-120", vulnerability_type="Use of Inherently Unsafe Input API",
                    file=item.file, function=event.function, line_start=event.line_start, line_end=event.line_end,
                    source=api, sink=api, evidence=f"{api} accepts a string without a destination bound: {event.text.strip()}",
                    confidence=0.98 if api == "gets" else 0.88,
                ))
        return findings

    def _has_unbounded_string(self, event: SemanticEvent) -> bool:
        format_index = 0 if _api(event) == "scanf" else 1
        if format_index >= len(event.arguments):
            return False
        format_text = event.arguments[format_index]
        return bool(re.search(r"%(?!\d+)[^%]*s", format_text))


class WeakRandomAgent(BaseAgent):
    agent_name = "weak_random_agent"
    covered_cwes = ("CWE-338",)

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            for event in item.events:
                api = _api(event)
                if event.kind != "call" or api not in {"rand", "srand"}:
                    continue
                context = f"{event.target or ''} {event.text}".lower()
                security_context = any(word in context for word in {"password", "passwd", "token", "secret", "key", "otp", "nonce"})
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-338", vulnerability_type="Cryptographically Weak PRNG",
                    file=item.file, function=event.function, line_start=event.line_start, line_end=event.line_end,
                    source=api, sink=event.target or api,
                    evidence=f"{api} is predictable and is used{' in security-sensitive context' if security_context else ''}: {event.text.strip()}",
                    confidence=0.9 if security_context else 0.72,
                ))
        return findings


class OffByOneAgent(BaseAgent):
    agent_name = "off_by_one_agent"
    covered_cwes = ("CWE-193",)

    def run(self, ast: list[AstAnalysis], cfg: list[CfgAnalysis]) -> list[VulnerabilityFinding]:
        findings = []
        for item in ast:
            functions = {function.name: function for function in item.functions}
            for event in item.events:
                if event.kind != "condition" or "<=" not in event.text:
                    continue
                function = functions.get(event.function or "")
                if not function or not function.array_sizes:
                    continue
                arrays_used = [name for name in function.array_sizes if any(
                    name in candidate.text and "[" in candidate.text
                    for candidate in item.events
                    if candidate.function == event.function
                )]
                if not arrays_used:
                    continue
                findings.append(self._build_finding(
                    finding_id=f"{self.agent_name}:{self._file_name(item.file)}:{event.line_start}",
                    cwe="CWE-193", vulnerability_type="Potential Off-by-One Error", file=item.file,
                    function=event.function, line_start=event.line_start, line_end=event.line_end,
                    source=event.text, sink=", ".join(arrays_used),
                    evidence=f"Inclusive loop bound may permit an index equal to the array length: {event.text.strip()}",
                    confidence=0.7,
                ))
        return findings
