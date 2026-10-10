from __future__ import annotations

import io
import re
import tokenize
import tomllib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

SPEC_ID_COMMENT = re.compile(r"^# [A-Z]{1,4}-\d+(?: \(\d+\))?$")
TOOL_DIRECTIVE = re.compile(r"^# (?:type: ignore\[[a-z-, ]+\]|noqa: [A-Z0-9, ]+)$")
TOML_STRING = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'")
SKIPPED = {".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache", "__pycache__", "data", "runs"}


def _load(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _table(data: dict[str, object], *keys: str) -> dict[str, object]:
    current: object = data
    for key in keys:
        assert isinstance(current, dict)
        current = current[key]
    assert isinstance(current, dict)
    return current


def _files(ml_root: Path, suffix: str) -> list[Path]:
    return [
        p
        for p in sorted(ml_root.rglob(f"*{suffix}"))
        if not SKIPPED & set(p.relative_to(ml_root).parts) and p.name != "uv.lock"
    ]


def test_t_39_4_dependencies_are_exact_pins(ml_root: Path) -> None:
    pyproject = _load(ml_root / "pyproject.toml")
    project = _table(pyproject, "project")
    groups = _table(pyproject, "dependency-groups")
    runtime = project["dependencies"]
    dev = groups["dev"]
    assert isinstance(runtime, list)
    assert isinstance(dev, list)
    requirements = [*runtime, *dev]
    assert requirements
    for requirement in requirements:
        assert isinstance(requirement, str)
        assert re.fullmatch(r"[a-z0-9-]+==[0-9][0-9A-Za-z.]*", requirement), requirement


def test_t_39_4_resolution_cooldown_and_wheels_only(ml_root: Path) -> None:
    uv = _table(_load(ml_root / "pyproject.toml"), "tool", "uv")
    assert uv["exclude-newer"] == "2026-10-03T00:00:00Z"
    assert uv["no-build"] is True


def test_t_39_4_lock_is_hashed_and_wheel_only(ml_root: Path) -> None:
    lock = _load(ml_root / "uv.lock")
    options = _table(lock, "options")
    assert options["exclude-newer"] == "2026-10-03T00:00:00Z"
    packages = lock["package"]
    assert isinstance(packages, list)
    for package in packages:
        assert isinstance(package, dict)
        if "registry" not in package["source"]:
            continue
        wheels = package.get("wheels", [])
        assert wheels, package["name"]
        for wheel in wheels:
            assert str(wheel["hash"]).startswith("sha256:"), package["name"]


def test_t_28_10_python_is_pinned(ml_root: Path) -> None:
    pinned = (ml_root / ".python-version").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"3\.13\.\d+", pinned)
    assert _table(_load(ml_root / "pyproject.toml"), "project")["requires-python"] == "==3.13.*"


def test_t_28_10_strict_tooling(ml_root: Path) -> None:
    tool = _table(_load(ml_root / "pyproject.toml"), "tool")
    assert _table(tool, "mypy")["strict"] is True
    assert _table(tool, "ruff", "lint")["select"] == ["ALL"]
    pytest_ini = _table(tool, "pytest", "ini_options")
    assert pytest_ini["filterwarnings"] == ["error"]


def _comment_ok(text: str, *, first_line: bool) -> bool:
    if first_line and text.startswith("#!"):
        return True
    return bool(SPEC_ID_COMMENT.match(text) or TOOL_DIRECTIVE.match(text))


def test_t_47_python_has_no_explanatory_comments(ml_root: Path) -> None:
    offenders: list[str] = []
    for path in _files(ml_root, ".py"):
        source = path.read_text(encoding="utf-8")
        offenders.extend(
            f"{path}:{token.start[0]}: {token.string}"
            for token in tokenize.generate_tokens(io.StringIO(source).readline)
            if token.type == tokenize.COMMENT
            and not _comment_ok(token.string, first_line=token.start[0] == 1)
        )
    assert offenders == []


def test_t_47_toml_has_no_explanatory_comments(ml_root: Path) -> None:
    offenders: list[str] = []
    for path in _files(ml_root, ".toml"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = TOML_STRING.sub('""', line)
            if "#" in code:
                comment = code[code.index("#") :].strip()
                if not _comment_ok(comment, first_line=False) or code.strip() != comment:
                    offenders.append(f"{path}:{number}: {line}")
    assert offenders == []
