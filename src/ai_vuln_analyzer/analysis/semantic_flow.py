from __future__ import annotations

import re
from collections import defaultdict

from ai_vuln_analyzer.core.schemas import DataFlowEdge, FunctionSummary, SemanticEvent

INPUT_BUFFER_APIS = {"gets": 0, "fgets": 0, "read": 1, "recv": 1, "scanf": 1, "fscanf": 2}
INPUT_RETURN_APIS = {"getenv", "getpass"}
COPY_APIS = {
    "strcpy": (0, 1), "strncpy": (0, 1), "strcat": (0, 1), "strncat": (0, 1),
    "memcpy": (0, 1), "memmove": (0, 1),
}

IDENTIFIER_PATTERN = re.compile(r"\b[A-Za-z_]\w*\b")
STRING_PATTERN = re.compile(r'"(?:\\.|[^"\\])*"')
IGNORED_IDENTIFIERS = {
    "char", "const", "double", "else", "float", "for", "if", "int", "long",
    "return", "short", "signed", "sizeof", "static", "struct", "unsigned", "void", "while",
}


def identifiers(expression: str) -> set[str]:
    without_strings = STRING_PATTERN.sub("", expression)
    return {name for name in IDENTIFIER_PATTERN.findall(without_strings) if name not in IGNORED_IDENTIFIERS}


def base_identifier(expression: str) -> str | None:
    without_strings = STRING_PATTERN.sub("", expression)
    match = IDENTIFIER_PATTERN.search(without_strings)
    return match.group(0) if match else None


def annotate_taint(
    events: list[SemanticEvent], functions: list[FunctionSummary]
) -> tuple[list[SemanticEvent], list[DataFlowEdge]]:
    by_function: dict[str | None, list[SemanticEvent]] = defaultdict(list)
    for event in events:
        by_function[event.function].append(event)

    parameters = {function.name: function.parameters for function in functions}
    enriched: list[SemanticEvent] = []
    edges: list[DataFlowEdge] = []

    for function_name, function_events in by_function.items():
        taint: dict[str, set[str]] = {
            parameter: {f"parameter:{parameter}"}
            for parameter in parameters.get(function_name or "", [])
        }
        for event in sorted(function_events, key=lambda item: (item.line_start, item.line_end)):
            event_sources: set[str] = set()
            tainted_arguments: list[int] = []
            for index, argument in enumerate(event.arguments):
                sources = _sources_for_expression(argument, taint)
                if sources:
                    tainted_arguments.append(index)
                    event_sources.update(sources)

            if event.kind in {"assignment", "declaration"} and event.target:
                sources = _sources_for_expression(event.text.split("=", 1)[-1], taint)
                if sources:
                    target = base_identifier(event.target)
                    if target:
                        taint[target] = set(sources)
                        for source in sources:
                            edges.append(DataFlowEdge(
                                source=source,
                                target=target,
                                line=event.line_start,
                                function=function_name,
                                kind="assignment",
                            ))

            if event.kind == "return":
                sources = _sources_for_expression(event.text.removeprefix("return"), taint)
                event_sources.update(sources)
                for source in sources:
                    edges.append(DataFlowEdge(
                        source=source,
                        target=f"return:{function_name}",
                        line=event.line_start,
                        function=function_name,
                        kind="return",
                    ))

            if event.kind == "call" and event.callee:
                callee = event.callee.split("::")[-1]
                if callee in INPUT_BUFFER_APIS:
                    index = INPUT_BUFFER_APIS[callee]
                    if index < len(event.arguments):
                        target = base_identifier(event.arguments[index])
                        if target:
                            source = f"input:{callee}@{event.line_start}"
                            taint[target] = {source}
                            event_sources.add(source)
                            edges.append(DataFlowEdge(
                                source=source,
                                target=target,
                                line=event.line_start,
                                function=function_name,
                                kind="input",
                            ))
                if callee in INPUT_RETURN_APIS and event.target:
                    target = base_identifier(event.target)
                    if target:
                        source = f"input:{callee}@{event.line_start}"
                        taint[target] = {source}
                        event_sources.add(source)
                        edges.append(DataFlowEdge(
                            source=source,
                            target=target,
                            line=event.line_start,
                            function=function_name,
                            kind="input",
                        ))
                if callee in COPY_APIS:
                    destination_index, source_index = COPY_APIS[callee]
                    if source_index < len(event.arguments) and destination_index < len(event.arguments):
                        sources = _sources_for_expression(event.arguments[source_index], taint)
                        target = base_identifier(event.arguments[destination_index])
                        if sources and target:
                            taint[target] = set(sources)
                            event_sources.update(sources)
                            for source in sources:
                                edges.append(DataFlowEdge(
                                    source=source,
                                    target=target,
                                    line=event.line_start,
                                    function=function_name,
                                    kind="copy",
                                ))

            enriched.append(event.model_copy(update={
                "tainted_arguments": tainted_arguments,
                "taint_sources": sorted(event_sources),
            }))

    enriched.sort(key=lambda item: (item.line_start, item.line_end, item.kind))
    return enriched, edges


def _sources_for_expression(expression: str, taint: dict[str, set[str]]) -> set[str]:
    sources: set[str] = set()
    for name in identifiers(expression):
        sources.update(taint.get(name, set()))
    return sources
