"""TR+EN evaluation set definition, published-version immutability and F-21 run records.

A set is versioned and holds no user data; each section stays `not_built` until its manifested
datasets exist, and a run is refused while no section is built.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from one_ml._fields import (
    IDENTIFIER,
    SEMVER,
    SHA256_HEX,
    DocumentError,
    as_error,
    check_keys,
    load_toml,
    req_bool,
    req_choice,
    req_languages,
    req_match,
    req_str,
    req_str_list,
    table_list,
)

if TYPE_CHECKING:
    from pathlib import Path

REQUIRED_SECTIONS = (
    "general",
    "one_tasks",
    "behaviour",
    "language",
    "retrieval",
    "voice",
    "device_sustained_load",
    "cost",
)


class EvalSetError(DocumentError):
    """An evaluation set, its published registry or a run record is invalid."""


class SectionStatus(StrEnum):
    """Build state of an evaluation section."""

    NOT_BUILT = "not_built"
    BUILT = "built"


class Reproduction(StrEnum):
    """Whether a reported number has been independently reproduced."""

    PENDING = "reproduction_pending"
    REPRODUCED = "reproduced"


@dataclass(frozen=True, slots=True)
class Section:
    """One section of an evaluation set."""

    id: str
    title: str
    status: SectionStatus
    sources: tuple[str, ...]
    manifests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvalSet:
    """A validated evaluation set definition."""

    name: str
    version: str
    languages: tuple[str, ...]
    sections: tuple[Section, ...]

    @property
    def built_sections(self) -> tuple[Section, ...]:
        """Sections whose datasets are built."""
        return tuple(s for s in self.sections if s.status is SectionStatus.BUILT)


_SET_KEYS = frozenset({"name", "version", "languages", "contains_user_data", "section"})
_SECTION_KEYS = frozenset({"id", "title", "status", "sources", "manifests"})


def _parse_section(table: dict[str, object], where: str) -> Section:
    check_keys(table, _SECTION_KEYS, where)
    section_id = req_match(req_str(table, "id", where), IDENTIFIER, "id", where)
    sub = f"{where} section '{section_id}'"
    status = SectionStatus(
        req_choice(
            req_str(table, "status", sub),
            frozenset(s.value for s in SectionStatus),
            "status",
            sub,
        )
    )
    sources = req_str_list(table, "sources", sub) if "sources" in table else ()
    manifests = req_str_list(table, "manifests", sub) if "manifests" in table else ()
    if status is SectionStatus.BUILT and not manifests:
        msg = f"{sub}: a built section must list its dataset manifests"
        raise EvalSetError(msg)
    return Section(section_id, req_str(table, "title", sub), status, sources, manifests)


def load_eval_set(path: Path) -> EvalSet:
    """Load and validate an evaluation set definition."""
    where = str(path)
    with as_error(EvalSetError):
        data = load_toml(path)
        check_keys(data, _SET_KEYS, where)
        if req_bool(data, "contains_user_data", where):
            msg = f"{where}: an evaluation set must not contain user data"
            raise EvalSetError(msg)
        sections = tuple(_parse_section(t, where) for t in table_list(data, "section", where))
        ids = [s.id for s in sections]
        if tuple(sorted(ids)) != tuple(sorted(REQUIRED_SECTIONS)):
            msg = f"{where}: sections must be exactly {', '.join(REQUIRED_SECTIONS)}"
            raise EvalSetError(msg)
        return EvalSet(
            name=req_match(req_str(data, "name", where), IDENTIFIER, "name", where),
            version=req_match(req_str(data, "version", where), SEMVER, "version", where),
            languages=req_languages(data, "languages", where),
            sections=sections,
        )


def check_published(eval_set: EvalSet, set_path: Path, registry_path: Path) -> bool:
    """Fail if a published set version's file has changed; return whether it is published."""
    where = str(registry_path)
    with as_error(EvalSetError):
        data = load_toml(registry_path)
        check_keys(data, frozenset({"published"}), where)
        for entry in table_list(data, "published", where):
            check_keys(entry, frozenset({"name", "version", "sha256"}), where)
            if (req_str(entry, "name", where), req_str(entry, "version", where)) != (
                eval_set.name,
                eval_set.version,
            ):
                continue
            expected = req_match(req_str(entry, "sha256", where), SHA256_HEX, "sha256", where)
            actual = hashlib.sha256(set_path.read_bytes()).hexdigest()
            if actual != expected:
                msg = (
                    f"published set {eval_set.name}@{eval_set.version} has changed "
                    f"(published {expected}, now {actual}); bump the version instead"
                )
                raise EvalSetError(msg)
            return True
    return False


@dataclass(frozen=True, slots=True)
class Environment:
    """Environment in which a result was produced."""

    device: str
    os: str
    quantization: str
    context_length: int
    temperature: float
    sustained_load: bool


@dataclass(frozen=True, slots=True)
class JudgeCalibration:
    """Judge model and the calibration evidence behind judged scores."""

    judge_model: str
    calibration_set_version: str
    raw_output: str


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Everything needed to reproduce and audit one evaluation run."""

    set_name: str
    set_version: str
    eval_code_version: str
    model_version: str
    adapter_version: str | None
    dataset_versions: dict[str, str]
    run_command: str
    raw_output: str
    environment: Environment
    full_context_baseline: str
    judge: JudgeCalibration | None
    reproduction: Reproduction = field(default=Reproduction.PENDING)

    def __post_init__(self) -> None:
        """Validate the record."""
        required = {
            "set_name": self.set_name,
            "eval_code_version": self.eval_code_version,
            "model_version": self.model_version,
            "run_command": self.run_command,
            "raw_output": self.raw_output,
            "full_context_baseline": self.full_context_baseline,
            "device": self.environment.device,
            "os": self.environment.os,
            "quantization": self.environment.quantization,
        }
        for name, value in required.items():
            if not value.strip():
                msg = f"run record: '{name}' must not be empty"
                raise EvalSetError(msg)
        if SEMVER.fullmatch(self.set_version) is None:
            msg = f"run record: invalid set version '{self.set_version}'"
            raise EvalSetError(msg)
        if not self.dataset_versions:
            msg = "run record: 'dataset_versions' must name every dataset used"
            raise EvalSetError(msg)
        if self.environment.context_length <= 0 or self.environment.temperature < 0:
            msg = "run record: context length must be positive and temperature non-negative"
            raise EvalSetError(msg)

    def to_json(self) -> str:
        """Serialise the record as stable JSON."""
        return json.dumps(asdict(self), ensure_ascii=False, indent=2, sort_keys=True)
