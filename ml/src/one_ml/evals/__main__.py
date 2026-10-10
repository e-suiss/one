"""Command line entry point for evaluation runs.

Usage: `python -m one_ml.evals run --set PATH --model ID --code-version V --out PATH`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from one_ml.evals import EvalSetError, check_published, load_eval_set


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m one_ml.evals")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run an evaluation set against a model")
    run.add_argument("--set", dest="set_path", type=Path, required=True)
    run.add_argument("--model", required=True)
    run.add_argument("--code-version", required=True)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--published", type=Path, default=None)
    return parser


def refusal(
    set_path: Path, model: str, code_version: str, out: Path, published: Path | None
) -> str:
    """Validate a run request and return why it cannot run yet."""
    if not model.strip() or not code_version.strip():
        msg = "--model and --code-version must not be empty"
        raise EvalSetError(msg)
    eval_set = load_eval_set(set_path)
    registry = published if published is not None else set_path.parent.parent / "published.toml"
    if registry.is_file():
        check_published(eval_set, set_path, registry)
    label = f"{eval_set.name}@{eval_set.version}"
    if out.exists():
        return f"output {out} already exists; run records are never overwritten"
    built = eval_set.built_sections
    if not built:
        pending = ", ".join(s.id for s in eval_set.sections)
        return f"eval set {label} has no built sections (not built: {pending})"
    return f"eval set {label}: no runner is implemented for {', '.join(s.id for s in built)}"


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = _parser().parse_args(argv)
    try:
        reason = refusal(args.set_path, args.model, args.code_version, args.out, args.published)
    except EvalSetError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stderr.write(f"refused: {reason}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
