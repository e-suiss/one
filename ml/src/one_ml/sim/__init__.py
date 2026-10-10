"""Synthetic user simulation scenarios: schema, loader and validator.

Scenarios describe months-long lives of purely synthetic users, including preference changes, device
changes, contradictions and changes of mind; they are used for evaluation and simulation only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from one_ml._fields import (
    IDENTIFIER,
    SEMVER,
    DocumentError,
    as_error,
    check_keys,
    load_toml,
    req_bool,
    req_choice,
    req_int,
    req_languages,
    req_match,
    req_str,
    req_table,
    table_list,
)

if TYPE_CHECKING:
    from pathlib import Path


class ScenarioError(DocumentError):
    """A scenario does not follow the schema or its timeline is inconsistent."""


class EventKind(StrEnum):
    """Kinds of life events in a scenario."""

    MESSAGE = "message"
    PREFERENCE_STATED = "preference_stated"
    PREFERENCE_CHANGE = "preference_change"
    DEVICE_CHANGE = "device_change"
    CONTRADICTION = "contradiction"
    CHANGE_OF_MIND = "change_of_mind"


class SimulatorClass(StrEnum):
    """Which simulator drives the synthetic user."""

    SCRIPTED = "scripted"
    USERLM = "UserLM"
    DITTO = "Ditto"
    OSIM = "OSim"


SCENARIO_USAGES = frozenset({"simulation_only", "eval_only"})
_REFERRING = frozenset(
    {EventKind.PREFERENCE_CHANGE, EventKind.CONTRADICTION, EventKind.CHANGE_OF_MIND}
)
_SCENARIO_KEYS = frozenset(
    {
        "id",
        "version",
        "title",
        "synthetic",
        "contains_user_data",
        "usage",
        "simulator_class",
        "languages",
        "duration_days",
        "persona",
        "event",
        "expectation",
    }
)
_EVENT_KEYS = frozenset({"id", "day", "kind", "device", "lang", "text", "refs"})
_EXPECTATION_KEYS = frozenset({"after", "holds"})


@dataclass(frozen=True, slots=True)
class Event:
    """One event on the scenario timeline."""

    id: str
    day: int
    kind: EventKind
    device: str
    lang: str
    text: str
    refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Expectation:
    """A statement that should hold for the agent after a given event."""

    after: str
    holds: str


@dataclass(frozen=True, slots=True)
class Scenario:
    """A validated synthetic life scenario."""

    id: str
    version: str
    title: str
    usage: str
    simulator_class: SimulatorClass
    languages: tuple[str, ...]
    duration_days: int
    persona: str
    events: tuple[Event, ...]
    expectations: tuple[Expectation, ...]


def _parse_event(table: dict[str, object], languages: tuple[str, ...], where: str) -> Event:
    check_keys(table, _EVENT_KEYS, where)
    event_id = req_match(req_str(table, "id", where), IDENTIFIER, "id", where)
    sub = f"{where} event '{event_id}'"
    kind = req_choice(
        req_str(table, "kind", sub), frozenset(k.value for k in EventKind), "kind", sub
    )
    refs_raw = table.get("refs", [])
    if not isinstance(refs_raw, list) or not all(isinstance(r, str) for r in refs_raw):
        msg = f"{sub}: field 'refs' must be a list of event ids"
        raise ScenarioError(msg)
    return Event(
        id=event_id,
        day=req_int(table, "day", sub),
        kind=EventKind(kind),
        device=req_str(table, "device", sub),
        lang=req_choice(req_str(table, "lang", sub), frozenset(languages), "lang", sub),
        text=req_str(table, "text", sub),
        refs=tuple(str(r) for r in refs_raw),
    )


def _check_timeline(events: tuple[Event, ...], duration_days: int, where: str) -> None:
    if not events:
        msg = f"{where}: a scenario needs at least one event"
        raise ScenarioError(msg)
    seen: set[str] = set()
    previous_day = 0
    device = events[0].device
    for event in events:
        sub = f"{where} event '{event.id}'"
        if event.id in seen:
            msg = f"{sub}: duplicate event id"
            raise ScenarioError(msg)
        if event.day < previous_day or event.day > duration_days:
            msg = f"{sub}: day {event.day} is out of order or beyond duration_days"
            raise ScenarioError(msg)
        missing = [r for r in event.refs if r not in seen]
        if missing:
            msg = f"{sub}: refs must point to earlier events ({', '.join(missing)})"
            raise ScenarioError(msg)
        if event.kind in _REFERRING and not event.refs:
            msg = f"{sub}: a {event.kind.value} event must reference an earlier event"
            raise ScenarioError(msg)
        if event.kind is EventKind.DEVICE_CHANGE:
            if event.device == device:
                msg = f"{sub}: device_change must switch to a different device"
                raise ScenarioError(msg)
        elif event.device != device:
            msg = f"{sub}: the device changes without a device_change event"
            raise ScenarioError(msg)
        device = event.device
        seen.add(event.id)
        previous_day = event.day


def parse_scenario(data: dict[str, object], where: str) -> Scenario:
    """Validate a parsed scenario document and return the typed scenario."""
    with as_error(ScenarioError):
        check_keys(data, _SCENARIO_KEYS, where)
        if not req_bool(data, "synthetic", where):
            msg = f"{where}: scenarios must be purely synthetic"
            raise ScenarioError(msg)
        if req_bool(data, "contains_user_data", where):
            msg = f"{where}: scenarios must not contain user data"
            raise ScenarioError(msg)
        languages = req_languages(data, "languages", where)
        duration_days = req_int(data, "duration_days", where)
        persona = req_table(data, "persona", where)
        check_keys(persona, frozenset({"summary"}), f"{where} [persona]")
        events = tuple(_parse_event(t, languages, where) for t in table_list(data, "event", where))
        _check_timeline(events, duration_days, where)
        event_ids = {e.id for e in events}
        expectations: list[Expectation] = []
        for table in table_list(data, "expectation", where):
            check_keys(table, _EXPECTATION_KEYS, f"{where} [[expectation]]")
            after = req_str(table, "after", where)
            if after not in event_ids:
                msg = f"{where}: expectation refers to unknown event '{after}'"
                raise ScenarioError(msg)
            expectations.append(Expectation(after, req_str(table, "holds", where)))
        simulator = req_choice(
            req_str(data, "simulator_class", where),
            frozenset(s.value for s in SimulatorClass),
            "simulator_class",
            where,
        )
        return Scenario(
            id=req_match(req_str(data, "id", where), IDENTIFIER, "id", where),
            version=req_match(req_str(data, "version", where), SEMVER, "version", where),
            title=req_str(data, "title", where),
            usage=req_choice(req_str(data, "usage", where), SCENARIO_USAGES, "usage", where),
            simulator_class=SimulatorClass(simulator),
            languages=languages,
            duration_days=duration_days,
            persona=req_str(persona, "summary", f"{where} [persona]"),
            events=events,
            expectations=tuple(expectations),
        )


def load_scenario(path: Path) -> Scenario:
    """Load and validate a scenario TOML file."""
    with as_error(ScenarioError):
        data = load_toml(path)
    return parse_scenario(data, str(path))
