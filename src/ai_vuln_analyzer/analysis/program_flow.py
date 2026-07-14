from __future__ import annotations

import re
from collections import defaultdict

from ai_vuln_analyzer.analysis.semantic_flow import COPY_APIS, base_identifier, identifiers
from ai_vuln_analyzer.core.schemas import AstAnalysis, DataFlowEdge, FunctionSummary, SemanticEvent

INDEX_PATTERN = re.compile(r"\[[^\]]*\]")


def canonical_location(expression: str) -> str | None:
    text = expression.strip().replace("->", ".")
    text = re.sub(r"^[&*()\s]+|[()\s]+$", "", text)
    text = INDEX_PATTERN.sub("[]", text)
    match = re.search(r"[A-Za-z_]\w*(?:\[\])?(?:\.[A-Za-z_]\w*(?:\[\])?)*", text)
    return match.group(0) if match else None


def link_program_taint(analyses: list[AstAnalysis]) -> list[AstAnalysis]:
    """Connect function returns and shared storage using a conservative fixed point."""

    functions: dict[str, FunctionSummary] = {
        function.name: function
        for analysis in analyses
        for function in analysis.functions
    }
    events_by_function: dict[str, list[tuple[int, SemanticEvent]]] = defaultdict(list)
    for analysis_index, analysis in enumerate(analyses):
        for event in analysis.events:
            if event.function:
                events_by_function[event.function].append((analysis_index, event))

    local_origins: dict[str, dict[str, set[str]]] = {}
    for name, function in functions.items():
        local_origins[name] = {
            parameter: {f"parameter:{parameter}"}
            for parameter in function.parameters
        }
    global_origins: dict[str, set[str]] = defaultdict(set)
    return_origins: dict[str, set[str]] = defaultdict(set)
    extra_edges: dict[int, list[DataFlowEdge]] = defaultdict(list)

    for _ in range(20):
        changed = False
        for function_name, indexed_events in events_by_function.items():
            function = functions[function_name]
            locals_for_function = local_origins[function_name]
            for analysis_index, event in sorted(indexed_events, key=lambda pair: _event_order(pair[1])):
                argument_sources = [
                    _expression_sources(argument, locals_for_function, global_origins)
                    for argument in event.arguments
                ]
                sources = set().union(*argument_sources) if argument_sources else set()

                if event.kind in {"assignment", "declaration"} and event.target:
                    rhs = event.text.split("=", 1)[-1]
                    rhs_sources = _expression_sources(rhs, locals_for_function, global_origins)
                    changed |= _write_location(
                        event.target, rhs_sources, function, locals_for_function, global_origins,
                        extra_edges[analysis_index], event, "assignment",
                    )

                if event.kind == "call" and event.callee:
                    api = event.callee.split("::")[-1]
                    if api in COPY_APIS:
                        destination_index, source_index = COPY_APIS[api]
                        if destination_index < len(event.arguments) and source_index < len(argument_sources):
                            changed |= _write_location(
                                event.arguments[destination_index], argument_sources[source_index],
                                function, locals_for_function, global_origins,
                                extra_edges[analysis_index], event, "copy",
                            )
                    if event.target and api in return_origins:
                        mapped = _map_parameter_sources(
                            return_origins[api], functions.get(api), argument_sources
                        )
                        changed |= _write_location(
                            event.target, mapped, function, locals_for_function, global_origins,
                            extra_edges[analysis_index], event, "call",
                        )

                if event.kind == "return":
                    expression = event.text.removeprefix("return").rstrip("; ")
                    return_sources = _expression_sources(expression, locals_for_function, global_origins)
                    before = len(return_origins[function_name])
                    return_origins[function_name].update(return_sources)
                    changed |= len(return_origins[function_name]) != before
        if not changed:
            break

    linked: list[AstAnalysis] = []
    for analysis_index, analysis in enumerate(analyses):
        enriched_events: list[SemanticEvent] = []
        for event in analysis.events:
            local = local_origins.get(event.function or "", {})
            argument_sources = [
                _expression_sources(argument, local, global_origins)
                for argument in event.arguments
            ]
            tainted_arguments = sorted({
                *event.tainted_arguments,
                *(index for index, sources in enumerate(argument_sources) if sources),
            })
            sources = set(event.taint_sources)
            for argument_source in argument_sources:
                sources.update(argument_source)
            enriched_events.append(event.model_copy(update={
                "tainted_arguments": tainted_arguments,
                "taint_sources": sorted(sources),
            }))
        edges = _deduplicate_edges([*analysis.data_flow_edges, *extra_edges[analysis_index]])
        linked.append(analysis.model_copy(update={"events": enriched_events, "data_flow_edges": edges}))
    return linked


def _expression_sources(
    expression: str,
    local_origins: dict[str, set[str]],
    global_origins: dict[str, set[str]],
) -> set[str]:
    sources: set[str] = set()
    location = canonical_location(expression)
    if location:
        sources.update(global_origins.get(location, set()))
        sources.update(local_origins.get(location, set()))
    for name in identifiers(expression):
        sources.update(local_origins.get(name, set()))
    return sources


def _write_location(
    expression: str,
    sources: set[str],
    function: FunctionSummary,
    local_origins: dict[str, set[str]],
    global_origins: dict[str, set[str]],
    edges: list[DataFlowEdge],
    event: SemanticEvent,
    edge_kind: str,
) -> bool:
    if not sources:
        return False
    location = canonical_location(expression)
    if not location:
        return False
    root = base_identifier(location)
    local_names = {*function.parameters, *function.locals, *function.array_sizes}
    storage = local_origins if root in local_names else global_origins
    before = len(storage[location]) if location in storage else 0
    storage.setdefault(location, set()).update(sources)
    for source in sources:
        edges.append(DataFlowEdge(
            source=source, target=location, line=event.line_start,
            function=event.function,
            kind="global" if storage is global_origins else edge_kind,
        ))
    return len(storage[location]) != before


def _map_parameter_sources(
    summary_sources: set[str],
    function: FunctionSummary | None,
    argument_sources: list[set[str]],
) -> set[str]:
    mapped: set[str] = set()
    for source in summary_sources:
        if source.startswith("parameter:") and function:
            parameter = source.split(":", 1)[1]
            if parameter in function.parameters:
                index = function.parameters.index(parameter)
                if index < len(argument_sources):
                    mapped.update(argument_sources[index])
        else:
            mapped.add(source)
    return mapped


def _event_order(event: SemanticEvent) -> tuple[int, int, int]:
    priority = {"declaration": 0, "assignment": 1, "call": 2, "return": 3}.get(event.kind, 4)
    return event.line_start, event.line_end, priority


def _deduplicate_edges(edges: list[DataFlowEdge]) -> list[DataFlowEdge]:
    unique = {}
    for edge in edges:
        key = (edge.source, edge.target, edge.line, edge.function, edge.kind)
        unique[key] = edge
    return list(unique.values())
