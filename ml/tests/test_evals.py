from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from one_ml.evals import (
    REQUIRED_SECTIONS,
    Environment,
    EvalSetError,
    JudgeCalibration,
    Reproduction,
    RunRecord,
    SectionStatus,
    check_published,
    load_eval_set,
)
from one_ml.evals.__main__ import main

type Writer = Callable[[Path, Mapping[str, object]], Path]


def _set_doc(ml_root: Path) -> dict[str, object]:
    with (ml_root / "evals" / "tr_en" / "set.toml").open("rb") as handle:
        return tomllib.load(handle)


def _sections(doc: dict[str, object]) -> list[dict[str, object]]:
    sections = doc["section"]
    assert isinstance(sections, list)
    return [dict(s) for s in sections]


def test_mf_51_repository_set_is_unbuilt_skeleton(ml_root: Path) -> None:
    eval_set = load_eval_set(ml_root / "evals" / "tr_en" / "set.toml")
    assert (eval_set.name, eval_set.version) == ("tr_en", "0.1.0")
    assert eval_set.languages == ("tr", "en")
    assert tuple(s.id for s in eval_set.sections) == REQUIRED_SECTIONS
    assert all(s.status is SectionStatus.NOT_BUILT for s in eval_set.sections)
    assert eval_set.sections[0].sources == ("Cetvel", "TurkBench subset")


def test_mf_51_repository_published_registry_is_consistent(ml_root: Path) -> None:
    set_path = ml_root / "evals" / "tr_en" / "set.toml"
    check_published(load_eval_set(set_path), set_path, ml_root / "evals" / "published.toml")


def test_mf_51_set_with_user_data_is_rejected(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    doc = _set_doc(ml_root)
    doc["contains_user_data"] = True
    with pytest.raises(EvalSetError, match="user data"):
        load_eval_set(write_toml(tmp_path / "set.toml", doc))


def test_mf_51_set_missing_a_section_is_rejected(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    doc = _set_doc(ml_root)
    doc["section"] = _sections(doc)[:-1]
    with pytest.raises(EvalSetError, match="sections must be exactly"):
        load_eval_set(write_toml(tmp_path / "set.toml", doc))


def test_mf_51_built_section_requires_manifests(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    doc = _set_doc(ml_root)
    sections = _sections(doc)
    sections[0]["status"] = "built"
    doc["section"] = sections
    with pytest.raises(EvalSetError, match="must list its dataset manifests"):
        load_eval_set(write_toml(tmp_path / "set.toml", doc))


def _published(tmp_path: Path, write_toml: Writer, sha256: str) -> Path:
    entry = {"name": "tr_en", "version": "0.1.0", "sha256": sha256}
    return write_toml(tmp_path / "published.toml", {"published": [entry]})


def test_mf_51_published_set_version_never_changes(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    set_path = write_toml(tmp_path / "set.toml", _set_doc(ml_root))
    original = hashlib.sha256(set_path.read_bytes()).hexdigest()
    registry = _published(tmp_path, write_toml, original)
    eval_set = load_eval_set(set_path)
    assert check_published(eval_set, set_path, registry)
    doc = _set_doc(ml_root)
    doc["languages"] = ["en", "tr"]
    write_toml(set_path, doc)
    with pytest.raises(EvalSetError, match="has changed"):
        check_published(load_eval_set(set_path), set_path, registry)


def test_mf_51_unpublished_version_is_not_reported_published(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    set_path = ml_root / "evals" / "tr_en" / "set.toml"
    registry = write_toml(tmp_path / "published.toml", {"published": []})
    assert not check_published(load_eval_set(set_path), set_path, registry)


def _cli(ml_root: Path, out: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--set",
        str(ml_root / "evals" / "tr_en" / "set.toml"),
        "--model",
        "qwen3.5-4b@unreleased",
        "--code-version",
        "0.1.0",
        "--out",
        str(out),
        *extra,
    ]


def test_inv_39_cli_refuses_set_without_built_sections(
    tmp_path: Path, ml_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "run.json"
    assert main(_cli(ml_root, out)) == 1
    assert "tr_en@0.1.0 has no built sections" in capsys.readouterr().err
    assert not out.exists()


def test_mf_51_cli_refuses_to_overwrite_output(
    tmp_path: Path, ml_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "run.json"
    out.write_text("{}", encoding="utf-8")
    assert main(_cli(ml_root, out)) == 1
    assert "never overwritten" in capsys.readouterr().err


def test_mf_51_cli_reports_invalid_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "set.toml"
    bad.write_text("name = 1\n", encoding="utf-8")
    assert (
        main(["run", "--set", str(bad), "--model", "m", "--code-version", "v", "--out", "o"]) == 2
    )
    assert capsys.readouterr().err.startswith("error:")


def test_mf_51_cli_runs_as_module(tmp_path: Path, ml_root: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "one_ml.evals", *_cli(ml_root, tmp_path / "run.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "refused:" in result.stderr


def _record(overrides: Mapping[str, Any] | None = None) -> RunRecord:
    base = RunRecord(
        set_name="tr_en",
        set_version="0.1.0",
        eval_code_version="0.1.0",
        model_version="qwen3.5-4b@unreleased",
        adapter_version=None,
        dataset_versions={"one-tasks-synth": "0.1.0"},
        run_command="python -m one_ml.evals run --set evals/tr_en/set.toml",
        raw_output="runs/example/raw.jsonl",
        environment=Environment(
            device="test-device",
            os="test-os",
            quantization="none",
            context_length=8192,
            temperature=0.0,
            sustained_load=False,
        ),
        full_context_baseline="runs/example/full_context.jsonl",
        judge=None,
    )
    return replace(base, **(overrides or {}))


def test_f_21_run_record_defaults_to_reproduction_pending() -> None:
    assert _record().reproduction is Reproduction.PENDING


@pytest.mark.parametrize(
    "overrides",
    [
        {"model_version": " "},
        {"eval_code_version": ""},
        {"run_command": ""},
        {"raw_output": ""},
        {"full_context_baseline": ""},
        {"set_version": "latest"},
        {"dataset_versions": {}},
        {
            "environment": Environment(
                device="d",
                os="o",
                quantization="q4",
                context_length=0,
                temperature=0.0,
                sustained_load=True,
            )
        },
        {
            "environment": Environment(
                device="",
                os="o",
                quantization="q4",
                context_length=1,
                temperature=0.0,
                sustained_load=True,
            )
        },
    ],
)
def test_f_21_incomplete_run_record_is_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(EvalSetError):
        _record(overrides)


def test_f_21_run_record_serialises_every_field() -> None:
    judge = JudgeCalibration("judge-model", "0.1.0", "runs/example/judge.jsonl")
    data = json.loads(_record({"judge": judge}).to_json())
    assert data["reproduction"] == "reproduction_pending"
    assert data["set_version"] == "0.1.0"
    assert data["judge"]["calibration_set_version"] == "0.1.0"
    assert set(data["environment"]) == {
        "device",
        "os",
        "quantization",
        "context_length",
        "temperature",
        "sustained_load",
    }
