from ai_vuln_analyzer.analysis.ast_analyzer import AstAnalyzer


def test_ast_analyzer_detects_functions_and_calls():
    analysis = AstAnalyzer().analyze("examples/vulnerable/bof.c")
    assert analysis.functions
    assert analysis.functions[0].name == "copy_input"
    assert any(call["api"] == "strcpy" for call in analysis.dangerous_calls)
