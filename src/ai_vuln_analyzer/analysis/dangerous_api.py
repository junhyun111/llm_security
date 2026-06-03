from __future__ import annotations

DANGEROUS_APIS = {
    "strcpy": {"cwes": ["CWE-121", "CWE-122", "CWE-787"], "type": "buffer-copy"},
    "strncpy": {"cwes": ["CWE-787"], "type": "buffer-copy"},
    "memcpy": {"cwes": ["CWE-787", "CWE-190"], "type": "memory-copy"},
    "memmove": {"cwes": ["CWE-787"], "type": "memory-copy"},
    "sprintf": {"cwes": ["CWE-121", "CWE-122"], "type": "format-copy"},
    "snprintf": {"cwes": ["CWE-787"], "type": "format-copy"},
    "malloc": {"cwes": ["CWE-190", "CWE-476"], "type": "allocation"},
    "calloc": {"cwes": ["CWE-190", "CWE-476"], "type": "allocation"},
    "free": {"cwes": ["CWE-415", "CWE-416"], "type": "deallocation"},
    "delete": {"cwes": ["CWE-415", "CWE-416"], "type": "deallocation"},
}

CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
