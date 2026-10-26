"""Fail-closed lexical helpers shared by the runner and mutation gate."""
from __future__ import annotations

def code_mask(source: str, *, strings: bool = False) -> str:
    """Keep offsets while masking nested comments and optionally quoted terms."""
    result = list(source)
    pos = 0
    depth = 0
    quote = None
    while pos < len(source):
        char = source[pos]
        following = source[pos:pos + 2]
        if depth:
            if following == "/*":
                depth += 1
                result[pos:pos + 2] = "  "
                pos += 2
                continue
            if following == "*/":
                depth -= 1
                result[pos:pos + 2] = "  "
                pos += 2
                continue
            if char != "\n":
                result[pos] = " "
        elif quote:
            if char == "\\" and pos + 1 < len(source):
                if strings:
                    result[pos:pos + 2] = "  "
                pos += 2
                continue
            if strings and char != "\n":
                result[pos] = " "
            if char == quote:
                quote = None
        elif following == "/*":
            depth = 1
            result[pos:pos + 2] = "  "
            pos += 2
            continue
        elif following == "//":
            finish = source.find("\n", pos)
            finish = len(source) if finish < 0 else finish
            result[pos:finish] = " " * (finish - pos)
            pos = finish
            continue
        elif char in ("'", '"'):
            quote = char
            if strings:
                result[pos] = " "
        pos += 1
    if depth or quote:
        raise ValueError("Unterminated comment or quoted text")
    return "".join(result)
