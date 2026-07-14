from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

from ai_vuln_analyzer.analysis.dangerous_api import DANGEROUS_APIS
from ai_vuln_analyzer.analysis.semantic_flow import annotate_taint, identifiers
from ai_vuln_analyzer.core.schemas import AstAnalysis, FunctionSummary, SemanticEvent

FUNCTION_PATTERN = re.compile(
    r"^\s*([A-Za-z_][\w:\s\*<>]*?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)
CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\((.*)\)")
ARRAY_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]]+)\s*\]")


class AstAnalyzer:
    def analyze(self, file_path: str | Path) -> AstAnalysis:
        path = Path(file_path)
        code = path.read_text(encoding="utf-8")
        try:
            functions, events, parse_errors = self._analyze_tree_sitter(path, code)
            parser_name = "tree-sitter"
        except (ImportError, ModuleNotFoundError):
            functions, events = self._analyze_fallback(path, code)
            parser_name = "regex-fallback"
            parse_errors = 0

        events, data_flow_edges = annotate_taint(events, functions)
        dangerous_calls = []
        for event in events:
            api = self._simple_callee(event.callee)
            if event.kind == "call" and api in DANGEROUS_APIS:
                dangerous_calls.append({
                    "api": api,
                    "line": event.line_start,
                    "content": event.text.strip(),
                    "cwes": DANGEROUS_APIS[api]["cwes"],
                    "arguments": event.arguments,
                    "tainted_arguments": event.tainted_arguments,
                })
        return AstAnalysis(
            file=str(path),
            language="cpp" if path.suffix.lower() != ".c" else "c",
            parser=parser_name,
            functions=functions,
            dangerous_calls=dangerous_calls,
            events=events,
            data_flow_edges=data_flow_edges,
            parse_errors=parse_errors,
        )

    def _analyze_tree_sitter(
        self, path: Path, code: str
    ) -> tuple[list[FunctionSummary], list[SemanticEvent], int]:
        from tree_sitter import Language, Parser

        if path.suffix.lower() == ".c":
            import tree_sitter_c as grammar
        else:
            import tree_sitter_cpp as grammar

        language = Language(grammar.language())
        try:
            parser = Parser(language)
        except TypeError:  # tree-sitter 0.22 compatibility
            parser = Parser()
            parser.set_language(language)
        source = code.encode("utf-8")
        tree = parser.parse(source)
        functions: list[FunctionSummary] = []
        events: list[SemanticEvent] = []

        for node in self._walk(tree.root_node):
            if node.type != "function_definition":
                continue
            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            name = self._declarator_name(declarator, source) or "<anonymous>"
            parameters = self._parameters(declarator, source)
            function_events = self._function_events(body, source, name)
            calls = sorted({self._simple_callee(event.callee) for event in function_events if event.callee})
            local_names = sorted({event.target for event in function_events if event.kind == "declaration" and event.target})
            arrays = self._array_sizes(body, source)
            functions.append(FunctionSummary(
                file=str(path),
                name=name,
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                calls=calls,
                locals=local_names,
                parameters=parameters,
                array_sizes=arrays,
                notes=[],
            ))
            events.extend(function_events)
        parse_errors = sum(1 for node in self._walk(tree.root_node) if node.type == "ERROR")
        if tree.root_node.has_error and parse_errors == 0:
            parse_errors = 1
        return functions, events, parse_errors

    def _function_events(self, body: Any, source: bytes, function: str) -> list[SemanticEvent]:
        events: list[SemanticEvent] = []
        if body is None:
            return events
        for node in self._walk(body):
            text = self._text(node, source)
            common = {
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "function": function,
                "text": text,
            }
            if node.type == "call_expression":
                function_node = node.child_by_field_name("function")
                arguments_node = node.child_by_field_name("arguments")
                args = [self._text(child, source) for child in (arguments_node.named_children if arguments_node else [])]
                events.append(SemanticEvent(
                    kind="call",
                    callee=self._text(function_node, source) if function_node else None,
                    arguments=args,
                    target=self._enclosing_target(node, source),
                    identifiers=sorted(identifiers(text)),
                    **common,
                ))
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                events.append(SemanticEvent(
                    kind="assignment",
                    target=self._text(left, source) if left else None,
                    identifiers=sorted(identifiers(text)),
                    **common,
                ))
            elif node.type == "init_declarator":
                declarator = node.child_by_field_name("declarator")
                events.append(SemanticEvent(
                    kind="declaration",
                    target=self._declarator_name(declarator, source),
                    identifiers=sorted(identifiers(text)),
                    **common,
                ))
            elif node.type in {"if_statement", "for_statement", "while_statement", "do_statement", "switch_statement"}:
                condition = node.child_by_field_name("condition")
                if condition:
                    condition_text = self._text(condition, source)
                    events.append(SemanticEvent(
                        kind="condition",
                        text=condition_text,
                        identifiers=sorted(identifiers(condition_text)),
                        control_kind=node.type.removesuffix("_statement"),
                        scope_end_line=node.end_point[0] + 1,
                        **{key: value for key, value in common.items() if key != "text"},
                    ))
            elif node.type == "return_statement":
                events.append(SemanticEvent(kind="return", identifiers=sorted(identifiers(text)), **common))
        return events

    def _analyze_fallback(self, path: Path, code: str) -> tuple[list[FunctionSummary], list[SemanticEvent]]:
        functions: list[FunctionSummary] = []
        events: list[SemanticEvent] = []
        lines = code.splitlines()
        for match in FUNCTION_PATTERN.finditer(code):
            name = match.group(2)
            start_line = code[: match.start()].count("\n") + 1
            end_line = self._find_block_end(lines, start_line)
            parameters = self._parameter_names(match.group(3))
            snippet = "\n".join(lines[start_line - 1:end_line])
            arrays = {name_: size for name_, size in ARRAY_PATTERN.findall(snippet)}
            function_events = self._fallback_events(lines, start_line, end_line, name)
            functions.append(FunctionSummary(
                file=str(path), name=name, line_start=start_line, line_end=end_line,
                calls=sorted({self._simple_callee(event.callee) for event in function_events if event.callee}),
                locals=sorted({event.target for event in function_events if event.target}),
                parameters=parameters, array_sizes=arrays, notes=["parsed without tree-sitter"],
            ))
            events.extend(function_events)
        return functions, events

    def _fallback_events(
        self, lines: list[str], start: int, end: int, function: str
    ) -> list[SemanticEvent]:
        events: list[SemanticEvent] = []
        for line_number in range(start, end + 1):
            text = lines[line_number - 1].strip()
            call = CALL_PATTERN.search(text.rstrip(";"))
            if call:
                args = self._split_arguments(call.group(2))
                target = text.split("=", 1)[0].split()[-1].strip("*") if "=" in text[:call.start()] else None
                events.append(SemanticEvent(
                    kind="call", line_start=line_number, line_end=line_number, function=function,
                    text=text, callee=call.group(1), arguments=args, target=target,
                    identifiers=sorted(identifiers(text)),
                ))
            if "=" in text and "==" not in text and not text.startswith(("if", "for", "while")):
                left = text.split("=", 1)[0].split()[-1].strip("* ")
                events.append(SemanticEvent(
                    kind="assignment", line_start=line_number, line_end=line_number,
                    function=function, text=text, target=left, identifiers=sorted(identifiers(text)),
                ))
            if text.startswith(("if", "for", "while", "switch")):
                events.append(SemanticEvent(
                    kind="condition", line_start=line_number, line_end=line_number,
                    function=function, text=text, identifiers=sorted(identifiers(text)),
                ))
        return events

    def _walk(self, node: Any) -> Iterator[Any]:
        yield node
        for child in node.named_children:
            yield from self._walk(child)

    def _text(self, node: Any, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _declarator_name(self, node: Any, source: bytes) -> str | None:
        if node is None:
            return None
        if node.type in {"identifier", "field_identifier"}:
            return self._text(node, source)
        declarator = node.child_by_field_name("declarator")
        if declarator:
            return self._declarator_name(declarator, source)
        for child in node.named_children:
            name = self._declarator_name(child, source)
            if name:
                return name
        return None

    def _parameters(self, declarator: Any, source: bytes) -> list[str]:
        if declarator is None:
            return []
        for node in self._walk(declarator):
            if node.type == "parameter_list":
                return [
                    name for child in node.named_children
                    if child.type in {"parameter_declaration", "optional_parameter_declaration"}
                    for name in [self._declarator_name(child.child_by_field_name("declarator"), source)]
                    if name
                ]
        return []

    def _array_sizes(self, body: Any, source: bytes) -> dict[str, str]:
        arrays: dict[str, str] = {}
        if body is None:
            return arrays
        for node in self._walk(body):
            if node.type != "array_declarator":
                continue
            declarator = node.child_by_field_name("declarator")
            size = node.child_by_field_name("size")
            name = self._declarator_name(declarator, source)
            if name and size:
                arrays[name] = self._text(size, source)
        return arrays

    def _enclosing_target(self, node: Any, source: bytes) -> str | None:
        parent = node.parent
        while parent is not None and parent.type not in {"expression_statement", "declaration"}:
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                return self._text(left, source) if left else None
            if parent.type == "init_declarator":
                declarator = parent.child_by_field_name("declarator")
                return self._declarator_name(declarator, source)
            parent = parent.parent
        return None

    def _find_block_end(self, lines: list[str], start_line: int) -> int:
        depth = 0
        started = False
        for index in range(start_line - 1, len(lines)):
            depth += lines[index].count("{")
            started = started or "{" in lines[index]
            depth -= lines[index].count("}")
            if started and depth == 0:
                return index + 1
        return len(lines)

    def _parameter_names(self, text: str) -> list[str]:
        return [part.strip().split()[-1].strip("*&[]") for part in text.split(",") if part.strip() and part.strip() != "void"]

    def _split_arguments(self, text: str) -> list[str]:
        arguments: list[str] = []
        current = []
        depth = 0
        in_string = False
        escaped = False
        for char in text:
            if char == '"' and not escaped:
                in_string = not in_string
            if not in_string:
                depth += char in "([{"
                depth -= char in ")] }".replace(" ", "")
            if char == "," and depth == 0 and not in_string:
                arguments.append("".join(current).strip())
                current = []
            else:
                current.append(char)
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
        if current:
            arguments.append("".join(current).strip())
        return arguments

    def _simple_callee(self, callee: str | None) -> str:
        if not callee:
            return ""
        return callee.split("::")[-1].split(".")[-1].split("->")[-1]
