from __future__ import annotations

import ast


class TomlCompatError(ValueError):
    pass


def _decode_basic_string(text: str) -> str:
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        raise TomlCompatError("invalid basic string")
    try:
        return ast.literal_eval(text)
    except (SyntaxError, ValueError) as exc:
        raise TomlCompatError("invalid basic string") from exc


def _decode_literal_string(text: str) -> str:
    if len(text) < 2 or text[0] != "'" or text[-1] != "'":
        raise TomlCompatError("invalid literal string")
    return text[1:-1]


def _split_items(text: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    square_depth = 0
    curly_depth = 0
    quote: str | None = None
    escape = False
    for char in text:
        if quote is not None:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
            continue
        if char == "[":
            square_depth += 1
            current.append(char)
            continue
        if char == "]":
            square_depth -= 1
            if square_depth < 0:
                raise TomlCompatError("unbalanced array")
            current.append(char)
            continue
        if char == "{":
            curly_depth += 1
            current.append(char)
            continue
        if char == "}":
            curly_depth -= 1
            if curly_depth < 0:
                raise TomlCompatError("unbalanced inline table")
            current.append(char)
            continue
        if char == "," and square_depth == 0 and curly_depth == 0:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(char)
    if quote is not None:
        raise TomlCompatError("unterminated string")
    if square_depth != 0:
        raise TomlCompatError("unbalanced array")
    if curly_depth != 0:
        raise TomlCompatError("unbalanced inline table")
    item = "".join(current).strip()
    if item:
        items.append(item)
    return items


def _strip_comment(text: str) -> str:
    quote: str | None = None
    escape = False
    result: list[str] = []
    for char in text:
        if quote is not None:
            result.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            result.append(char)
            continue
        if char == "#":
            break
        result.append(char)
    return "".join(result)


def _split_top_level_once(text: str, separator: str) -> tuple[str, str]:
    square_depth = 0
    curly_depth = 0
    quote: str | None = None
    escape = False
    for index, char in enumerate(text):
        if quote is not None:
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char == "[":
            square_depth += 1
            continue
        if char == "]":
            square_depth -= 1
            continue
        if char == "{":
            curly_depth += 1
            continue
        if char == "}":
            curly_depth -= 1
            continue
        if char == separator and square_depth == 0 and curly_depth == 0:
            return text[:index], text[index + 1:]
    raise TomlCompatError(f"missing separator: {separator}")


def _parse_key_path(text: str) -> list[str]:
    parts = _split_dotted_key(text)
    keys: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            raise TomlCompatError("empty key")
        if part[0] in "\"'":
            key = _parse_scalar(part)
            if not isinstance(key, str):
                raise TomlCompatError("quoted key must be a string")
            keys.append(key)
        else:
            keys.append(part)
    return keys


def _split_dotted_key(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    for char in text:
        if quote is not None:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
            continue
        if char == ".":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if quote is not None:
        raise TomlCompatError("unterminated quoted key")
    parts.append("".join(current).strip())
    return parts


def _assign_value(table: dict[str, object], key_path: list[str], value: object) -> None:
    if not key_path:
        raise TomlCompatError("empty key")
    node = table
    for key in key_path[:-1]:
        child = node.get(key)
        if child is None:
            child = {}
            node[key] = child
        if not isinstance(child, dict):
            raise TomlCompatError(f"key conflict at {key}")
        node = child
    node[key_path[-1]] = value


def _parse_scalar(text: str):
    value = text.strip()
    if not value:
        raise TomlCompatError("empty scalar")
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith('"'):
        return _decode_basic_string(value)
    if value.startswith("'"):
        return _decode_literal_string(value)
    if value.startswith("[") and value.endswith("]"):
        return _parse_array(value[1:-1])
    if value.startswith("{") and value.endswith("}"):
        return _parse_inline_table(value[1:-1])
    if value[0] in "+-0123456789":
        try:
            if any(marker in value for marker in (".", "e", "E")):
                return float(value)
            return int(value, 10)
        except ValueError as exc:
            raise TomlCompatError("invalid number") from exc
    raise TomlCompatError(f"unsupported scalar: {value}")


def _parse_array(text: str):
    if not text.strip():
        return []
    return [_parse_value(item) for item in _split_items(text)]


def _parse_value(text: str):
    value = text.strip()
    if value.startswith("[") and value.endswith("]"):
        return _parse_array(value[1:-1])
    if value.startswith("{") and value.endswith("}"):
        return _parse_inline_table(value[1:-1])
    return _parse_scalar(value)


def _parse_inline_table(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    if not text.strip():
        return result
    for item in _split_items(text):
        key, value = _split_top_level_once(item, "=")
        _assign_value(result, _parse_key_path(key), _parse_value(value))
    return result


def _bracket_balance(text: str) -> int:
    square_depth = 0
    curly_depth = 0
    quote: str | None = None
    escape = False
    for char in text:
        if quote is not None:
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            continue
        if char == "[":
            square_depth += 1
        elif char == "]":
            square_depth -= 1
        elif char == "{":
            curly_depth += 1
        elif char == "}":
            curly_depth -= 1
    return square_depth + curly_depth


def loads(text: str) -> dict[str, object]:
    root: dict[str, object] = {}
    current = root
    current_path: list[str] = []
    pending_key_path: list[str] | None = None
    pending_parts: list[str] = []

    def ensure_table(path: list[str]) -> dict[str, object]:
        node = root
        for key in path:
            child = node.get(key)
            if child is None:
                child = {}
                node[key] = child
            if not isinstance(child, dict):
                raise TomlCompatError(f"table conflict at {key}")
            node = child
        return node

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).rstrip()
        if not line:
            if pending_key_path is not None:
                pending_parts.append("")
            continue
        if pending_key_path is not None:
            pending_parts.append(line)
            pending_text = "\n".join(pending_parts)
            if _bracket_balance(pending_text) != 0:
                continue
            _assign_value(current, pending_key_path, _parse_value(pending_text))
            pending_key_path = None
            pending_parts = []
            continue
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            if line.startswith("[[") and line.endswith("]]"):
                raise TomlCompatError("array tables are not supported")
            header = line[1:-1].strip()
            if not header:
                raise TomlCompatError("empty table header")
            current_path = _parse_key_path(header)
            current = ensure_table(current_path)
            continue
        try:
            key, value = _split_top_level_once(line, "=")
        except TomlCompatError as exc:
            raise TomlCompatError(f"missing assignment: {line}")
        key_path = _parse_key_path(key)
        if _bracket_balance(value) > 0:
            pending_key_path = key_path
            pending_parts = [value.strip()]
            continue
        _assign_value(current, key_path, _parse_value(value))
    if pending_key_path is not None:
        raise TomlCompatError(f"unterminated array for {'.'.join(pending_key_path)}")
    return root
