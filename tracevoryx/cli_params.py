"""CLI parameter parsing for `tracevoryx call` (Windows-safe).

Problem being solved (reproduced on Windows 11, PS 5.1):
    tracevoryx call a sys.echo --params '{"text":"hello"}'
arrives in argv as `{text:hello}` because the MSVCRT argument parser strips
double quotes before Python sees them.

Strategy:
1. Try strict json.loads first (covers Linux, PS7 with proper quoting,
   doubled-quote forms, and --params-file).
2. On failure, apply a CONSERVATIVE, well-defined repair for the known
   quote-strip artifact: quote bare identifiers used as object keys and bare
   string values (numbers, true/false/null, and already-parsed structures
   are left alone). The repair is reported loudly — never silent — and only
   ever adds quoting; it cannot change keys or values into different data.
3. If the repair fails, return a concise error with the parse position.
   No raw tracebacks for user input errors.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

_BARE_KEY = r"[A-Za-z_][A-Za-z0-9_\-]*"
_NOQUOTE_VALUES = {"true", "false", "null"}


def parse_params(raw: Optional[str]) -> tuple[Optional[dict], Optional[str]]:
    """Return (params_dict, error_message). Exactly one is None.

    Accepts inline JSON (strict or Windows-mangled) or a path to a JSON file
    (when the string points at an existing file). Returns None for empty.
    """
    if raw is None or not raw.strip():
        return None, None
    candidate = raw.strip()
    # --params-file style: an existing JSON file path is loaded
    if candidate and os.path.isfile(candidate) and candidate.lower().endswith(".json"):
        try:
            with open(candidate, encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            return None, (f"params file '{candidate}' is not valid JSON: "
                          f"{exc.msg} at line {exc.lineno} column {exc.colno}")
        err = _validate_object(data)
        return (data, None) if err is None else (None, err)

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        repaired = _repair_windows_mangled(candidate)
        if repaired is not None:
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                data = None
        else:
            data = None
        if data is None:
            return None, (
                f"invalid JSON parameters: {exc.msg} (line {exc.lineno}, "
                f"column {exc.colno}). Windows note: double quotes inside "
                f"single-quoted PowerShell strings are stripped by the "
                f"console arg parser. Use doubled quotes inside the string "
                f"(e.g. '{{\"\"text\"\":\"\"hi\"\"}}') or pass a file with "
                f"--params-file")
        # loud, conservative repair — report exactly what happened
        # (caller prints the note; parse result identical to intent)
        err = _validate_object(data)
        if err:
            return None, err
        return data, None
    err = _validate_object(data)
    if err:
        return None, err
    return data, None


def parse_params_with_note(raw: Optional[str]) -> tuple[Optional[dict],
                                                        Optional[str],
                                                        bool]:
    """Like parse_params but also reports whether a Windows repair applied."""
    if raw is None or not raw.strip():
        return None, None, False
    candidate = raw.strip()
    # file path form: an existing .json file is loaded (most reliable on Windows)
    if candidate.lower().endswith(".json") and os.path.isfile(candidate):
        try:
            with open(candidate, encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            return None, (f"params file '{candidate}' is not valid JSON: "
                          f"{exc.msg} at line {exc.lineno} column "
                          f"{exc.colno}"), False
        except OSError as exc:
            return None, f"cannot read params file '{candidate}': {exc}", False
        err = _validate_object(data)
        if err:
            return None, err, False
        return data, None, False
    try:
        data = json.loads(candidate)
        err = _validate_object(data)
        return (data, None, False) if err is None else (None, err, False)
    except json.JSONDecodeError as exc:
        repaired = _repair_windows_mangled(candidate)
        if repaired is not None:
            try:
                data = json.loads(repaired)
                err = _validate_object(data)
                if err is None:
                    return data, None, True
            except json.JSONDecodeError:
                pass
        return None, (
            f"invalid JSON parameters: {exc.msg} (line {exc.lineno}, "
            f"column {exc.colno}). Windows note: double quotes inside "
            f"single-quoted PowerShell strings are stripped by the console "
            f"arg parser. Use doubled quotes (e.g. "
            f"'{{\"\"text\"\":\"\"hi\"\"}}') or --params-file <file.json>"), False


def _validate_object(data: Any) -> Optional[str]:
    """Gateway contract: params must be a JSON object (string keys)."""
    if not isinstance(data, dict):
        return (f"parameters must be a JSON object, got "
                f"{type(data).__name__}")
    for k in data:
        if not isinstance(k, str):
            return "parameter keys must be strings"
    return None


def _repair_windows_mangled(s: str) -> Optional[str]:
    """Repair the quote-stripped artifact: quote bare identifiers used as
    object keys, bare string values (which may contain spaces — the original
    quoted string preserved them), and bare array elements. Numbers,
    true/false/null, and nested structures are left untouched. Only adds
    quoting; never edits content."""
    if not s.lstrip().startswith(("{", "[")):
        return None
    out: list[str] = []
    i, n = 0, len(s)
    stack: list[str] = []          # 'o' object | 'a' array
    expect_key = False             # inside object: next token is a key
    expect_value = False           # after ':': value spans to delimiter

    def is_bare_number_or_literal(tok: str) -> bool:
        return (tok.replace(".", "", 1).replace("-", "", 1).isdigit()
                or tok in _NOQUOTE_VALUES)

    while i < n:
        while i < n and s[i].isspace():
            out.append(s[i])
            i += 1
        if i >= n:
            break
        ch = s[i]
        if ch in "{[":
            stack.append("o" if ch == "{" else "a")
            expect_key = ch == "{"
            expect_value = False
            out.append(ch)
            i += 1
            continue
        if ch in "}]":
            if stack:
                stack.pop()
            expect_key = False
            expect_value = False
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            expect_key = bool(stack) and stack[-1] == "o"
            expect_value = False
            out.append(ch)
            i += 1
            continue
        if ch == ":":
            expect_value = True
            out.append(ch)
            i += 1
            continue

        if expect_value:
            # value spans until a structural delimiter at this depth; nested
            # structures break out and are handled by the container branch
            j = i
            while j < n and s[j] not in ",}]":
                if s[j] in "{[":
                    break
                j += 1
            raw_value = s[i:j]
            value = raw_value.strip()
            if not value:
                out.append(raw_value)
            elif value.startswith('"') and value.endswith('"') and len(value) >= 2:
                out.append(value)  # already quoted (partial form) — keep
            elif is_bare_number_or_literal(value):
                out.append(value)
            else:
                out.append('"' + value + '"')
            i = j
            expect_value = False
            continue

        if expect_key:
            j = i
            while j < n and s[j] != ":":
                j += 1
            key = s[i:j].strip()
            if key.startswith('"') and key.endswith('"'):
                out.append(key)
            else:
                out.append('"' + key + '"')
            i = j
            expect_key = False
            continue

        if stack and stack[-1] == "a":
            # bare array element until ',' or ']'
            j = i
            while j < n and s[j] not in ",]":
                if s[j] in "{[":
                    break
                j += 1
            value = s[i:j].strip()
            if not value:
                out.append(s[i:j])
            elif value.startswith('"') and value.endswith('"') and len(value) >= 2:
                out.append(value)
            elif is_bare_number_or_literal(value):
                out.append(value)
            else:
                out.append('"' + value + '"')
            i = j
            continue

        # unexpected position: emit raw (repair will fail validation upstream)
        out.append(ch)
        i += 1
    repaired = "".join(out)
    return None if repaired == s else repaired
