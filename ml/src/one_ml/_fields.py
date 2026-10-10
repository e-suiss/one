"""Typed accessors for values parsed from TOML documents."""

from __future__ import annotations

import re
import tomllib
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
LANGUAGES = frozenset({"tr", "en"})


class DocumentError(ValueError):
    """A TOML document is missing a field or holds a value of the wrong shape."""


def load_toml(path: Path) -> dict[str, object]:
    """Read a TOML file, turning parse failures into `DocumentError`."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError as exc:
        msg = f"{path}: file not found"
        raise DocumentError(msg) from exc
    except tomllib.TOMLDecodeError as exc:
        msg = f"{path}: invalid TOML: {exc}"
        raise DocumentError(msg) from exc


def check_keys(data: Mapping[str, object], allowed: frozenset[str], where: str) -> None:
    """Reject keys that the schema does not define."""
    unknown = sorted(set(data) - allowed)
    if unknown:
        msg = f"{where}: unknown field(s): {', '.join(unknown)}"
        raise DocumentError(msg)


def req_str(data: Mapping[str, object], key: str, where: str) -> str:
    """Return a required non-empty string field."""
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        msg = f"{where}: field '{key}' must be a non-empty string"
        raise DocumentError(msg)
    return value


def opt_str(data: Mapping[str, object], key: str, where: str) -> str | None:
    """Return an optional non-empty string field."""
    if key not in data:
        return None
    return req_str(data, key, where)


def req_bool(data: Mapping[str, object], key: str, where: str) -> bool:
    """Return a required boolean field."""
    value = data.get(key)
    if not isinstance(value, bool):
        msg = f"{where}: field '{key}' must be a boolean"
        raise DocumentError(msg)
    return value


def req_int(data: Mapping[str, object], key: str, where: str) -> int:
    """Return a required non-negative integer field."""
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"{where}: field '{key}' must be a non-negative integer"
        raise DocumentError(msg)
    return value


def req_str_list(data: Mapping[str, object], key: str, where: str) -> tuple[str, ...]:
    """Return a required non-empty list of non-empty strings."""
    value = data.get(key)
    if not isinstance(value, list) or not value:
        msg = f"{where}: field '{key}' must be a non-empty list of strings"
        raise DocumentError(msg)
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            msg = f"{where}: field '{key}' must contain only non-empty strings"
            raise DocumentError(msg)
        items.append(item)
    return tuple(items)


def req_table(data: Mapping[str, object], key: str, where: str) -> dict[str, object]:
    """Return a required TOML table."""
    value = data.get(key)
    if not isinstance(value, dict):
        msg = f"{where}: field '{key}' must be a table"
        raise DocumentError(msg)
    return {str(k): v for k, v in value.items()}


def table_list(data: Mapping[str, object], key: str, where: str) -> list[dict[str, object]]:
    """Return a list of TOML tables, empty when the key is absent."""
    value = data.get(key, [])
    if not isinstance(value, list):
        msg = f"{where}: field '{key}' must be an array of tables"
        raise DocumentError(msg)
    tables: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            msg = f"{where}: field '{key}' must be an array of tables"
            raise DocumentError(msg)
        tables.append({str(k): v for k, v in item.items()})
    return tables


def req_match(value: str, pattern: re.Pattern[str], key: str, where: str) -> str:
    """Require a string to match a pattern."""
    if pattern.fullmatch(value) is None:
        msg = f"{where}: field '{key}' has invalid value '{value}'"
        raise DocumentError(msg)
    return value


def req_choice(value: str, choices: frozenset[str], key: str, where: str) -> str:
    """Require a string to be one of a fixed set of choices."""
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        msg = f"{where}: field '{key}' must be one of: {allowed} (got '{value}')"
        raise DocumentError(msg)
    return value


def req_languages(data: Mapping[str, object], key: str, where: str) -> tuple[str, ...]:
    """Return a required list of supported language codes without duplicates."""
    languages = req_str_list(data, key, where)
    for language in languages:
        req_choice(language, LANGUAGES, key, where)
    if len(set(languages)) != len(languages):
        msg = f"{where}: field '{key}' contains duplicates"
        raise DocumentError(msg)
    return languages


@contextmanager
def as_error(error: type[DocumentError]) -> Iterator[None]:
    """Re-raise any `DocumentError` raised in the block as `error`."""
    try:
        yield
    except error:
        raise
    except DocumentError as exc:
        raise error(str(exc)) from exc
