"""Static guard for ml/ against network access, remote code, unsafe loading and pickle files.

Run as `python -m one_ml.guard [--root PATH]`; it exits non-zero and lists every violation found.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path

NETWORK_MODULES = frozenset(
    {
        "requests",
        "httpx",
        "urllib.request",
        "urllib3",
        "http.client",
        "aiohttp",
        "socket",
        "ftplib",
        "huggingface_hub",
        "datasets",
    }
)
PICKLE_MODULES = frozenset(
    {"pickle", "_pickle", "cPickle", "cloudpickle", "dill", "joblib", "shelve"}
)
PICKLE_SUFFIXES = frozenset({".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib"})
SKIPPED_DIRS = frozenset(
    {".venv", ".git", ".mypy_cache", ".ruff_cache", ".pytest_cache", "__pycache__"}
)
_DYNAMIC_IMPORTERS = frozenset({"__import__", "importlib.import_module"})


@dataclass(frozen=True, slots=True, order=True)
class Violation:
    """A single guard finding."""

    path: Path
    line: int
    rule: str

    def __str__(self) -> str:
        """Render as `path:line: rule`."""
        return f"{self.path}:{self.line}: {self.rule}"


def _module_rule(module: str) -> str | None:
    parts = module.split(".")
    prefixes = {".".join(parts[: i + 1]) for i in range(len(parts))}
    if prefixes & NETWORK_MODULES:
        return f"network import '{module}'"
    if prefixes & PICKLE_MODULES:
        return f"pickle-family import '{module}'"
    return None


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.found: list[Violation] = []

    def _add(self, node: ast.stmt | ast.expr, rule: str) -> None:
        self.found.append(Violation(self.path, node.lineno, rule))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            rule = _module_rule(alias.name)
            if rule is not None:
                self._add(node, rule)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module is not None:
            for alias in node.names:
                rule = _module_rule(node.module) or _module_rule(f"{node.module}.{alias.name}")
                if rule is not None:
                    self._add(node, rule)
                elif node.module == "torch" and alias.name == "load":
                    self._add(node, "importing torch.load directly hides weights_only")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        for keyword in node.keywords:
            if keyword.arg == "trust_remote_code" and _is_true(keyword.value):
                self._add(node, "trust_remote_code=True")
        if name is not None and (name == "torch.load" or name.endswith(".torch.load")):
            weights_only = any(k.arg == "weights_only" and _is_true(k.value) for k in node.keywords)
            if not weights_only:
                self._add(node, "torch.load without weights_only=True")
        if name in _DYNAMIC_IMPORTERS and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                rule = _module_rule(first.value)
                if rule is not None:
                    self._add(node, f"dynamic {rule}")
        self.generic_visit(node)


def scan_source(path: Path, source: str) -> list[Violation]:
    """Return the violations in one Python source file."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [Violation(path, exc.lineno or 0, "file does not parse")]
    visitor = _Visitor(path)
    visitor.visit(tree)
    return visitor.found


def _walk(root: Path) -> list[Path]:
    files: list[Path] = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if entry.name not in SKIPPED_DIRS:
                files.extend(_walk(entry))
        elif entry.is_file():
            files.append(entry)
    return files


def scan_tree(root: Path) -> tuple[int, list[Violation]]:
    """Scan every file under `root`; return the number of Python files and all violations."""
    violations: list[Violation] = []
    python_files = 0
    for path in _walk(root):
        relative = path.relative_to(root)
        if path.suffix.lower() in PICKLE_SUFFIXES:
            violations.append(Violation(relative, 0, f"pickle-family file '{path.suffix}'"))
        if path.suffix == ".py":
            python_files += 1
            violations.extend(scan_source(relative, path.read_text(encoding="utf-8")))
    return python_files, sorted(violations)


def main(argv: list[str] | None = None) -> int:
    """Run the guard and return the process exit code."""
    parser = argparse.ArgumentParser(prog="python -m one_ml.guard")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    root: Path = args.root
    count, violations = scan_tree(root)
    for violation in violations:
        sys.stderr.write(f"{violation}\n")
    if violations:
        sys.stderr.write(f"guard: {len(violations)} violation(s)\n")
        return 1
    sys.stdout.write(f"guard: ok ({count} Python files scanned under {root})\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
