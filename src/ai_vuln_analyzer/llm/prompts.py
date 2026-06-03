from __future__ import annotations


def planner_prompt(summary: str) -> tuple[str, str]:
    return (
        "You are a security planning model that prioritizes C/C++ CWE candidates.",
        summary,
    )


def agent_prompt(agent_name: str, code_summary: str) -> tuple[str, str]:
    return (
        f"You are {agent_name}. Return only JSON vulnerability findings.",
        code_summary,
    )


def teacher_prompt(finding_summary: str) -> tuple[str, str]:
    return (
        "You explain root cause of a C/C++ vulnerability in concise technical prose.",
        finding_summary,
    )


def student_prompt(finding_summary: str) -> tuple[str, str]:
    return (
        "You generate a safer C/C++ patch. Return JSON.",
        finding_summary,
    )
