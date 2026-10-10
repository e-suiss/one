"""Dataset manifests: schema, license gate, content hash verification and contamination check.

Every dataset that ml/ reads must be described by a manifest in `ml/datasets/manifests/`; the data
itself lives outside the repository and is rejected unless its sha256 matches the manifest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from one_ml._fields import (
    IDENTIFIER,
    SEMVER,
    SHA256_HEX,
    DocumentError,
    as_error,
    check_keys,
    load_toml,
    opt_str,
    req_choice,
    req_languages,
    req_match,
    req_str,
    req_table,
    table_list,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence


class ManifestError(DocumentError):
    """A manifest is invalid, fails the license gate, or does not match its data."""


class Usage(StrEnum):
    """What a dataset may be used for."""

    TRAIN = "train"
    EVAL_ONLY = "eval_only"
    SIMULATION_ONLY = "simulation_only"


class LicenseStatus(StrEnum):
    """License gate decision for a component."""

    ALLOWED = "allowed"
    FLAGGED = "flagged"
    EVAL_SIMULATION_ONLY = "eval_simulation_only"
    FORBIDDEN = "forbidden"
    UNVERIFIED = "unverified"


class ProductionMethod(StrEnum):
    """How a dataset was produced."""

    COLLECTED = "collected"
    CURATED = "curated"
    SYNTHETIC = "synthetic"


class PersonalDataScanResult(StrEnum):
    """Outcome of the personal-data scan accepted for a dataset."""

    NONE_FOUND = "none_found"
    REDACTED = "redacted"


@dataclass(frozen=True, slots=True)
class Production:
    """Production method; synthetic data names its generating model and prompt version."""

    method: ProductionMethod
    generator_model: str | None
    prompt_version: str | None


@dataclass(frozen=True, slots=True)
class PersonalDataScan:
    """Result of the personal-data scan and the tool that produced it."""

    result: PersonalDataScanResult
    tool: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """A validated dataset manifest."""

    name: str
    version: str
    source: str
    license: str
    file: PurePosixPath
    content_sha256: str
    languages: tuple[str, ...]
    usage: Usage
    production: Production
    personal_data_scan: PersonalDataScan


@dataclass(frozen=True, slots=True)
class LicenseEntry:
    """One component in the license gate."""

    name: str
    license: str
    status: LicenseStatus
    condition: str | None


@dataclass(frozen=True, slots=True)
class Dataset:
    """A dataset whose content matched its manifest, with the hashes of its samples."""

    manifest: Manifest
    path: Path
    sample_hashes: frozenset[str]


_MANIFEST_KEYS = frozenset(
    {
        "name",
        "version",
        "source",
        "license",
        "file",
        "content_sha256",
        "languages",
        "usage",
        "production",
        "personal_data_scan",
    }
)
_PRODUCTION_KEYS = frozenset({"method", "generator_model", "prompt_version"})
_SCAN_KEYS = frozenset({"result", "tool"})
_LICENSE_KEYS = frozenset({"name", "license", "status", "condition"})


def _enum_values(enum: type[StrEnum]) -> frozenset[str]:
    return frozenset(member.value for member in enum)


def _parse_file(raw: str, where: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or raw != str(path):
        msg = f"{where}: field 'file' must be a normalised relative path inside the data root"
        raise ManifestError(msg)
    return path


def _parse_production(data: Mapping[str, object], where: str) -> Production:
    table = req_table(data, "production", where)
    sub = f"{where} [production]"
    check_keys(table, _PRODUCTION_KEYS, sub)
    method = ProductionMethod(
        req_choice(req_str(table, "method", sub), _enum_values(ProductionMethod), "method", sub)
    )
    generator_model = opt_str(table, "generator_model", sub)
    prompt_version = opt_str(table, "prompt_version", sub)
    if method is ProductionMethod.SYNTHETIC:
        if generator_model is None or prompt_version is None:
            msg = f"{sub}: synthetic data requires 'generator_model' and 'prompt_version'"
            raise ManifestError(msg)
    elif generator_model is not None or prompt_version is not None:
        msg = f"{sub}: 'generator_model' and 'prompt_version' apply only to synthetic data"
        raise ManifestError(msg)
    return Production(method, generator_model, prompt_version)


def _parse_scan(data: Mapping[str, object], where: str) -> PersonalDataScan:
    table = req_table(data, "personal_data_scan", where)
    sub = f"{where} [personal_data_scan]"
    check_keys(table, _SCAN_KEYS, sub)
    result = req_choice(
        req_str(table, "result", sub), _enum_values(PersonalDataScanResult), "result", sub
    )
    return PersonalDataScan(PersonalDataScanResult(result), req_str(table, "tool", sub))


def parse_manifest(data: Mapping[str, object], where: str) -> Manifest:
    """Validate a parsed manifest document and return the typed manifest."""
    with as_error(ManifestError):
        check_keys(data, _MANIFEST_KEYS, where)
        usage = req_choice(req_str(data, "usage", where), _enum_values(Usage), "usage", where)
        return Manifest(
            name=req_match(req_str(data, "name", where), IDENTIFIER, "name", where),
            version=req_match(req_str(data, "version", where), SEMVER, "version", where),
            source=req_str(data, "source", where),
            license=req_str(data, "license", where),
            file=_parse_file(req_str(data, "file", where), where),
            content_sha256=req_match(
                req_str(data, "content_sha256", where), SHA256_HEX, "content_sha256", where
            ),
            languages=req_languages(data, "languages", where),
            usage=Usage(usage),
            production=_parse_production(data, where),
            personal_data_scan=_parse_scan(data, where),
        )


def load_manifest(path: Path) -> Manifest:
    """Load and validate a manifest TOML file."""
    with as_error(ManifestError):
        data = load_toml(path)
    return parse_manifest(data, str(path))


def load_licenses(path: Path) -> dict[str, LicenseEntry]:
    """Load the license gate, keyed by component name."""
    where = str(path)
    with as_error(ManifestError):
        data = load_toml(path)
        check_keys(data, frozenset({"component"}), where)
        entries: dict[str, LicenseEntry] = {}
        for table in table_list(data, "component", where):
            check_keys(table, _LICENSE_KEYS, where)
            name = req_str(table, "name", where)
            status = req_choice(
                req_str(table, "status", where), _enum_values(LicenseStatus), "status", where
            )
            if name in entries:
                msg = f"{where}: duplicate component '{name}'"
                raise ManifestError(msg)
            entries[name] = LicenseEntry(
                name=name,
                license=req_str(table, "license", where),
                status=LicenseStatus(status),
                condition=opt_str(table, "condition", where),
            )
    return entries


def _gate_component(
    name: str, role: str, usage: Usage, licenses: Mapping[str, LicenseEntry]
) -> LicenseEntry:
    entry = licenses.get(name)
    if entry is None:
        msg = f"license gate: {role} '{name}' has no entry in licenses.toml"
        raise ManifestError(msg)
    if entry.status in {LicenseStatus.FORBIDDEN, LicenseStatus.UNVERIFIED}:
        msg = f"license gate: {role} '{name}' is {entry.status.value} ({entry.license})"
        raise ManifestError(msg)
    if usage is Usage.TRAIN and entry.status is not LicenseStatus.ALLOWED:
        msg = f"license gate: {role} '{name}' is {entry.status.value} and cannot be used to train"
        raise ManifestError(msg)
    return entry


def check_license(manifest: Manifest, licenses: Mapping[str, LicenseEntry]) -> None:
    """Apply the license gate to a manifest's source and, for synthetic data, its generator."""
    entry = _gate_component(manifest.source, "source", manifest.usage, licenses)
    if manifest.license != entry.license:
        msg = (
            f"license gate: manifest '{manifest.name}' declares license '{manifest.license}' "
            f"but licenses.toml records '{entry.license}' for '{entry.name}'"
        )
        raise ManifestError(msg)
    generator = manifest.production.generator_model
    if generator is not None:
        _gate_component(generator, "generator model", manifest.usage, licenses)


def file_sha256(path: Path) -> str:
    """Return the hex sha256 of a file's bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sample_hashes(path: Path) -> frozenset[str]:
    """Return the sha256 of each JSONL sample in canonical JSON form."""
    hashes: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                sample = json.loads(line)
            except json.JSONDecodeError as exc:
                msg = f"{path}:{number}: invalid JSON sample: {exc.msg}"
                raise ManifestError(msg) from exc
            canonical = json.dumps(
                sample, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            hashes.add(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    return frozenset(hashes)


def open_dataset(
    manifest_path: Path, data_root: Path, licenses: Mapping[str, LicenseEntry]
) -> Dataset:
    """Validate a manifest, apply the license gate and verify its data file's sha256."""
    manifest = load_manifest(manifest_path)
    check_license(manifest, licenses)
    path = data_root.joinpath(*manifest.file.parts)
    if not path.is_file():
        msg = f"dataset '{manifest.name}': data file {path} not found"
        raise ManifestError(msg)
    actual = file_sha256(path)
    if actual != manifest.content_sha256:
        msg = (
            f"dataset '{manifest.name}': sha256 mismatch for {path} "
            f"(manifest {manifest.content_sha256}, file {actual})"
        )
        raise ManifestError(msg)
    return Dataset(manifest=manifest, path=path, sample_hashes=sample_hashes(path))


def resolve_input(
    data_path: Path, manifests_dir: Path, data_root: Path, licenses: Mapping[str, LicenseEntry]
) -> Dataset:
    """Open a data file only if exactly one manifest in `manifests_dir` describes it."""
    try:
        relative = PurePosixPath(data_path.resolve().relative_to(data_root.resolve()).as_posix())
    except ValueError as exc:
        msg = f"input {data_path} is outside the data root {data_root}"
        raise ManifestError(msg) from exc
    matches = [
        candidate
        for candidate in sorted(manifests_dir.glob("*.toml"))
        if load_manifest(candidate).file == relative
    ]
    if not matches:
        msg = f"input {data_path} has no manifest in {manifests_dir}"
        raise ManifestError(msg)
    if len(matches) > 1:
        msg = f"input {data_path} is described by more than one manifest"
        raise ManifestError(msg)
    return open_dataset(matches[0], data_root, licenses)


def check_contamination(train: Sequence[Dataset], evaluation: Iterable[Dataset]) -> None:
    """Fail if any evaluation sample also appears in a training dataset."""
    for dataset in train:
        if dataset.manifest.usage is not Usage.TRAIN:
            msg = f"dataset '{dataset.manifest.name}' is {dataset.manifest.usage.value}, not train"
            raise ManifestError(msg)
    train_hashes: frozenset[str] = frozenset().union(*(d.sample_hashes for d in train))
    for dataset in evaluation:
        if dataset.manifest.usage is Usage.TRAIN:
            msg = f"dataset '{dataset.manifest.name}' is a train dataset, not an evaluation one"
            raise ManifestError(msg)
        overlap = train_hashes & dataset.sample_hashes
        if overlap:
            msg = (
                f"contamination: {len(overlap)} sample(s) of '{dataset.manifest.name}' "
                "also appear in training data"
            )
            raise ManifestError(msg)
