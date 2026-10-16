"""Shared fixtures for the ml/ test suite."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from one_ml.manifest import LicenseEntry, load_licenses

ML_ROOT = Path(__file__).resolve().parents[1]

type TomlWriter = Callable[[Path, Mapping[str, object]], Path]
type DatasetFactory = Callable[..., tuple[Path, Path]]


def _value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    raise TypeError(type(value))


def dumps(data: Mapping[str, object]) -> str:
    """Serialise flat values, one-level tables and arrays of tables as TOML."""
    lines: list[str] = []
    tail: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            tail.append(f"\n[{key}]")
            tail.extend(f"{k} = {_value(v)}" for k, v in value.items())
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            for table in value:
                tail.append(f"\n[[{key}]]")
                tail.extend(f"{k} = {_value(v)}" for k, v in table.items())
        else:
            lines.append(f"{key} = {_value(value)}")
    return "\n".join(lines + tail) + "\n"


@pytest.fixture
def write_toml() -> TomlWriter:
    def write(path: Path, data: Mapping[str, object]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dumps(data), encoding="utf-8")
        return path

    return write


@pytest.fixture
def licenses() -> dict[str, LicenseEntry]:
    return load_licenses(ML_ROOT / "licenses.toml")


@pytest.fixture
def ml_root() -> Path:
    return ML_ROOT


def _manifest_data(**overrides: object) -> dict[str, object]:
    """Return a valid manifest document, with top-level fields replaced or removed (None)."""
    data: dict[str, object] = {
        "name": "one-tasks-synth",
        "version": "0.1.0",
        "source": "Suiss synthetic",
        "license": "LicenseRef-Suiss-Proprietary",
        "file": "one_tasks/v0.1.0.jsonl",
        "content_sha256": "0" * 64,
        "languages": ["tr", "en"],
        "usage": "train",
        "production": {
            "method": "synthetic",
            "generator_model": "Qwen3.5",
            "prompt_version": "p-0.1.0",
        },
        "personal_data_scan": {"result": "none_found", "tool": "synthetic-pii-scan-0.1.0"},
    }
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


@pytest.fixture
def manifest_data() -> Callable[..., dict[str, object]]:
    return _manifest_data


@pytest.fixture
def make_dataset(tmp_path: Path, write_toml: TomlWriter) -> DatasetFactory:
    """Create a data file and a manifest describing it; return (manifest path, data root)."""

    def make(
        samples: list[dict[str, object]], *, name: str = "set-a", **overrides: object
    ) -> tuple[Path, Path]:
        data_root = tmp_path / "data"
        relative = f"{name}/v0.1.0.jsonl"
        data_file = data_root / relative
        data_file.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in samples)
        data_file.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(data_file.read_bytes()).hexdigest()
        fields: dict[str, object] = {"name": name, "file": relative, "content_sha256": digest}
        fields.update(overrides)
        manifest = write_toml(tmp_path / "manifests" / f"{name}.toml", _manifest_data(**fields))
        return manifest, data_root

    return make
