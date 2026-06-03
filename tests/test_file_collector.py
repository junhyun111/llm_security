from ai_vuln_analyzer.analysis.file_collector import collect_cpp_files


def test_collect_cpp_files():
    files = collect_cpp_files("examples/vulnerable")
    names = {file.name for file in files}
    assert {"bof.c", "uaf.c", "integer_overflow.c", "null_deref.c"} <= names
