from __future__ import annotations

DANGEROUS_APIS = {
    "strcpy": {"cwes": ["CWE-121", "CWE-122", "CWE-787"], "type": "buffer-copy"},
    "strncpy": {"cwes": ["CWE-787"], "type": "buffer-copy"},
    "strcat": {"cwes": ["CWE-121", "CWE-787"], "type": "buffer-copy"},
    "strncat": {"cwes": ["CWE-787"], "type": "buffer-copy"},
    "memcpy": {"cwes": ["CWE-787", "CWE-190"], "type": "memory-copy"},
    "memmove": {"cwes": ["CWE-787"], "type": "memory-copy"},
    "sprintf": {"cwes": ["CWE-121", "CWE-122"], "type": "format-copy"},
    "snprintf": {"cwes": ["CWE-787"], "type": "format-copy"},
    "malloc": {"cwes": ["CWE-190", "CWE-476"], "type": "allocation"},
    "calloc": {"cwes": ["CWE-190", "CWE-476"], "type": "allocation"},
    "free": {"cwes": ["CWE-415", "CWE-416"], "type": "deallocation"},
    "delete": {"cwes": ["CWE-415", "CWE-416"], "type": "deallocation"},
    "gets": {"cwes": ["CWE-242", "CWE-121"], "type": "unbounded-input"},
    "scanf": {"cwes": ["CWE-120"], "type": "formatted-input"},
    "fscanf": {"cwes": ["CWE-120"], "type": "formatted-input"},
    "system": {"cwes": ["CWE-78"], "type": "command-execution"},
    "popen": {"cwes": ["CWE-78"], "type": "command-execution"},
    "printf": {"cwes": ["CWE-134"], "type": "format-output"},
    "fprintf": {"cwes": ["CWE-134"], "type": "format-output"},
    "syslog": {"cwes": ["CWE-134"], "type": "format-output"},
    "fopen": {"cwes": ["CWE-22"], "type": "file-path"},
    "open": {"cwes": ["CWE-22"], "type": "file-path"},
    "remove": {"cwes": ["CWE-22"], "type": "file-path"},
    "unlink": {"cwes": ["CWE-22"], "type": "file-path"},
    "rename": {"cwes": ["CWE-22"], "type": "file-path"},
    "rand": {"cwes": ["CWE-338"], "type": "weak-random"},
    "srand": {"cwes": ["CWE-338"], "type": "weak-random"},
}

CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
