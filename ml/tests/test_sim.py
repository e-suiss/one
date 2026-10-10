from __future__ import annotations

import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from one_ml.sim import EventKind, ScenarioError, SimulatorClass, load_scenario

type Writer = Callable[[Path, Mapping[str, object]], Path]

EXAMPLE = Path("sim") / "scenarios" / "preference_drift_001.toml"


def _doc(ml_root: Path) -> dict[str, object]:
    with (ml_root / EXAMPLE).open("rb") as handle:
        return tomllib.load(handle)


def _events(doc: dict[str, object]) -> list[dict[str, object]]:
    events = doc["event"]
    assert isinstance(events, list)
    return [dict(e) for e in events]


def test_mf_54_example_scenario_covers_life_changes(ml_root: Path) -> None:
    scenario = load_scenario(ml_root / EXAMPLE)
    kinds = {e.kind for e in scenario.events}
    assert {
        EventKind.PREFERENCE_CHANGE,
        EventKind.DEVICE_CHANGE,
        EventKind.CONTRADICTION,
        EventKind.CHANGE_OF_MIND,
    } <= kinds
    assert scenario.duration_days >= 90
    assert scenario.simulator_class is SimulatorClass.SCRIPTED
    assert scenario.usage == "simulation_only"


def test_mf_54_repository_scenarios_are_valid(ml_root: Path) -> None:
    paths = sorted((ml_root / "sim" / "scenarios").glob("*.toml"))
    assert paths
    for path in paths:
        load_scenario(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("synthetic", False, "purely synthetic"),
        ("contains_user_data", True, "user data"),
        ("usage", "train", "usage"),
        ("simulator_class", "LiveUser", "simulator_class"),
        ("languages", ["de"], "languages"),
        ("duration_days", 10, "beyond duration_days"),
        ("unexpected", "x", "unknown field"),
    ],
)
def test_mf_54_invalid_scenario_header_is_rejected(
    tmp_path: Path, ml_root: Path, write_toml: Writer, field: str, value: object, message: str
) -> None:
    doc = _doc(ml_root)
    doc[field] = value
    with pytest.raises(ScenarioError, match=message):
        load_scenario(write_toml(tmp_path / "s.toml", doc))


def _mutate(index: int, field: str, value: object) -> Callable[[list[dict[str, object]]], None]:
    def apply(events: list[dict[str, object]]) -> None:
        if value is None:
            events[index].pop(field, None)
        else:
            events[index][field] = value

    return apply


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (_mutate(3, "refs", None), "must reference an earlier event"),
        (_mutate(3, "refs", ["e05"]), "refs must point to earlier events"),
        (_mutate(2, "device", "phone-1"), "different device"),
        (_mutate(1, "device", "phone-9"), "without a device_change"),
        (_mutate(2, "day", 5), "out of order"),
        (_mutate(1, "id", "e01"), "duplicate event id"),
        (_mutate(0, "kind", "telepathy"), "kind"),
        (_mutate(0, "lang", "fr"), "lang"),
    ],
)
def test_mf_54_inconsistent_timeline_is_rejected(
    tmp_path: Path,
    ml_root: Path,
    write_toml: Writer,
    mutation: Callable[[list[dict[str, object]]], None],
    message: str,
) -> None:
    doc = _doc(ml_root)
    events = _events(doc)
    mutation(events)
    doc["event"] = events
    with pytest.raises(ScenarioError, match=message):
        load_scenario(write_toml(tmp_path / "s.toml", doc))


def test_mf_54_expectation_must_follow_known_event(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    doc = _doc(ml_root)
    doc["expectation"] = [{"after": "e99", "holds": "anything"}]
    with pytest.raises(ScenarioError, match="unknown event"):
        load_scenario(write_toml(tmp_path / "s.toml", doc))


def test_mf_54_scenario_without_events_is_rejected(
    tmp_path: Path, ml_root: Path, write_toml: Writer
) -> None:
    doc = _doc(ml_root)
    del doc["event"]
    del doc["expectation"]
    with pytest.raises(ScenarioError, match="at least one event"):
        load_scenario(write_toml(tmp_path / "s.toml", doc))
