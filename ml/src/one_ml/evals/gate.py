"""No-regression comparison on paired per-item scores and the licence check of set sources."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from one_ml.evals import EvalSet, EvalSetError, Gate
from one_ml.manifest import LicenseStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

    from one_ml.manifest import LicenseEntry


@dataclass(frozen=True, slots=True)
class Comparison:
    """The paired bootstrap result for one section."""

    mean_delta: float
    lower_bound: float
    passed: bool


def compare(
    baseline: Mapping[str, float], candidate: Mapping[str, float], gate: Gate
) -> Comparison:
    """Compare scores paired by item id; fail when the lower bound is below -tolerance."""
    if set(baseline) != set(candidate) or not baseline:
        msg = "baseline and candidate must score the same, non-empty set of items"
        raise EvalSetError(msg)
    items = sorted(baseline)
    deltas = [candidate[i] - baseline[i] for i in items]
    n = len(deltas)
    rng = random.Random(gate.seed)  # noqa: S311
    means = sorted(sum(rng.choices(deltas, k=n)) / n for _ in range(gate.resamples))
    index = int((1.0 - gate.confidence) / 2.0 * gate.resamples)
    lower = means[min(index, len(means) - 1)]
    mean = sum(deltas) / n
    return Comparison(mean, lower, lower >= -gate.metric_delta_tolerance)


def check_sources(eval_set: EvalSet, licenses: Mapping[str, LicenseEntry]) -> None:
    """Every section source has a licence entry that is neither forbidden nor unverified."""
    for section in eval_set.sections:
        for source in section.sources:
            entry = licenses.get(source)
            if entry is None:
                msg = f"section '{section.id}': source '{source}' has no entry in licenses.toml"
                raise EvalSetError(msg)
            if entry.status in {LicenseStatus.FORBIDDEN, LicenseStatus.UNVERIFIED}:
                status = entry.status.value
                msg = f"section '{section.id}': source '{source}' is {status} ({entry.license})"
                raise EvalSetError(msg)
