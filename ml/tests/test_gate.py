"""No-regression gate and source licences of the TR+EN set (MF-51, MF-45, T-33)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from one_ml.evals import EvalSetError, Gate, load_eval_set
from one_ml.evals.gate import check_sources, compare
from one_ml.manifest import load_licenses

if TYPE_CHECKING:
    from pathlib import Path

GATE = Gate(metric_delta_tolerance=0.01, confidence=0.95, resamples=2000, seed=0)


def test_mf_51_equal_scores_pass_the_gate() -> None:
    scores = {f"q{i}": float(i % 2) for i in range(200)}
    result = compare(scores, dict(scores), GATE)
    assert result.passed
    assert result.mean_delta == 0.0


def test_mf_51_clear_regression_fails_the_gate() -> None:
    baseline = {f"q{i}": 1.0 for i in range(200)}
    candidate = {f"q{i}": 0.0 if i % 10 == 0 else 1.0 for i in range(200)}
    result = compare(baseline, candidate, GATE)
    assert not result.passed
    assert result.mean_delta == pytest.approx(-0.1)


def test_mf_51_gate_is_deterministic_for_a_seed() -> None:
    baseline = {f"q{i}": float(i % 3 == 0) for i in range(300)}
    candidate = {f"q{i}": float(i % 4 == 0) for i in range(300)}
    assert compare(baseline, candidate, GATE) == compare(baseline, candidate, GATE)


def test_mf_51_unpaired_items_are_rejected() -> None:
    with pytest.raises(EvalSetError, match="same"):
        compare({"a": 1.0}, {"b": 1.0}, GATE)


def test_mf_45_repository_set_sources_are_licensed(ml_root: Path) -> None:
    eval_set = load_eval_set(ml_root / "evals" / "tr_en" / "set.toml")
    licenses = load_licenses(ml_root / "licenses.toml")
    check_sources(eval_set, licenses)
    assert eval_set.gate.metric_delta_tolerance == pytest.approx(0.01)


def test_t_33_non_commercial_source_is_rejected(ml_root: Path) -> None:
    eval_set = load_eval_set(ml_root / "evals" / "tr_en" / "set.toml")
    licenses = load_licenses(ml_root / "licenses.toml")
    general = eval_set.sections[0]
    bad = type(eval_set)(
        eval_set.name,
        eval_set.version,
        eval_set.languages,
        eval_set.gate,
        (type(general)(general.id, general.title, general.status, ("XNLI",), general.manifests),),
    )
    with pytest.raises(EvalSetError, match="forbidden"):
        check_sources(bad, licenses)
