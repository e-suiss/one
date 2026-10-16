from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from one_ml.manifest import (
    LicenseEntry,
    LicenseStatus,
    ManifestError,
    Usage,
    check_contamination,
    check_license,
    load_manifest,
    open_dataset,
    resolve_input,
    sample_hashes,
)

type Writer = Callable[[Path, Mapping[str, object]], Path]
type Doc = Callable[..., dict[str, object]]
type Factory = Callable[..., tuple[Path, Path]]

SAMPLES: list[dict[str, object]] = [
    {"prompt": "Yarın 10'da toplantı ayarla.", "lang": "tr"},
    {"prompt": "Remind me to call the studio.", "lang": "en"},
]


def test_t_33_valid_manifest_loads(tmp_path: Path, write_toml: Writer, manifest_data: Doc) -> None:
    manifest = load_manifest(write_toml(tmp_path / "m.toml", manifest_data()))
    assert manifest.usage is Usage.TRAIN
    assert manifest.languages == ("tr", "en")
    assert manifest.production.generator_model == "Qwen3.5"


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_t_33_manifest_missing_field_is_rejected(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, field: str
) -> None:
    path = write_toml(tmp_path / "m.toml", manifest_data(**{field: None}))
    with pytest.raises(ManifestError, match=field):
        load_manifest(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("usage", "training"),
        ("languages", ["tr", "de"]),
        ("languages", ["tr", "tr"]),
        ("content_sha256", "abc"),
        ("version", "1.0"),
        ("file", "../outside.jsonl"),
        ("file", "/abs/data.jsonl"),
        ("personal_data_scan", {"result": "found", "tool": "scan"}),
        ("production", {"method": "synthetic", "prompt_version": "p-1"}),
        ("production", {"method": "collected", "generator_model": "Qwen3.5"}),
        ("extra", "value"),
    ],
)
def test_t_33_invalid_manifest_is_rejected(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, field: str, value: object
) -> None:
    path = write_toml(tmp_path / "m.toml", manifest_data(**{field: value}))
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_t_33_matching_hash_opens_dataset(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    dataset = open_dataset(manifest_path, data_root, licenses)
    assert len(dataset.sample_hashes) == len(SAMPLES)


def test_t_33_manifest_hash_mismatch_is_rejected(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    data_file = data_root / "set-a" / "v0.1.0.jsonl"
    data_file.write_text(data_file.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="sha256 mismatch"):
        open_dataset(manifest_path, data_root, licenses)


def test_t_33_missing_data_file_is_rejected(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    (data_root / "set-a" / "v0.1.0.jsonl").unlink()
    with pytest.raises(ManifestError, match="not found"):
        open_dataset(manifest_path, data_root, licenses)


def test_t_33_input_with_manifest_is_resolved(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    data_file = data_root / "set-a" / "v0.1.0.jsonl"
    dataset = resolve_input(data_file, manifest_path.parent, data_root, licenses)
    assert dataset.manifest.name == "set-a"


def test_t_33_input_without_manifest_is_rejected(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    stray = data_root / "stray.jsonl"
    stray.write_text('{"x": 1}\n', encoding="utf-8")
    with pytest.raises(ManifestError, match="no manifest"):
        resolve_input(stray, manifest_path.parent, data_root, licenses)


def test_t_33_input_outside_data_root_is_rejected(
    tmp_path: Path, make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    manifest_path, data_root = make_dataset(SAMPLES)
    outside = tmp_path / "elsewhere.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="outside the data root"):
        resolve_input(outside, manifest_path.parent, data_root, licenses)


def test_t_33_sample_hash_ignores_key_order(tmp_path: Path) -> None:
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    first.write_text('{"a": 1, "b": "ç"}\n', encoding="utf-8")
    second.write_text('{"b":"ç","a":1}\n\n', encoding="utf-8")
    assert sample_hashes(first) == sample_hashes(second)


def test_t_33_invalid_sample_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="invalid JSON"):
        sample_hashes(path)


def test_t_33_contamination_overlap_is_rejected(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    train_m, root = make_dataset(SAMPLES, name="train-a")
    eval_m, _ = make_dataset([SAMPLES[1], {"prompt": "new"}], name="eval-a", usage="eval_only")
    train = open_dataset(train_m, root, licenses)
    evaluation = open_dataset(eval_m, root, licenses)
    with pytest.raises(ManifestError, match="contamination: 1 sample"):
        check_contamination([train], [evaluation])


def test_t_33_disjoint_train_and_eval_pass(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    train_m, root = make_dataset(SAMPLES, name="train-a")
    eval_m, _ = make_dataset([{"prompt": "new"}], name="eval-a", usage="eval_only")
    check_contamination(
        [open_dataset(train_m, root, licenses)], [open_dataset(eval_m, root, licenses)]
    )


def test_t_33_contamination_check_rejects_swapped_roles(
    make_dataset: Factory, licenses: dict[str, LicenseEntry]
) -> None:
    train_m, root = make_dataset(SAMPLES, name="train-a")
    eval_m, _ = make_dataset([{"prompt": "new"}], name="eval-a", usage="eval_only")
    train = open_dataset(train_m, root, licenses)
    evaluation = open_dataset(eval_m, root, licenses)
    with pytest.raises(ManifestError, match="not train"):
        check_contamination([evaluation], [])
    with pytest.raises(ManifestError, match="not an evaluation"):
        check_contamination([], [train])


def test_t_33_repository_manifests_are_valid(
    ml_root: Path, licenses: dict[str, LicenseEntry]
) -> None:
    for path in sorted((ml_root / "datasets" / "manifests").glob("*.toml")):
        check_license(load_manifest(path), licenses)


def test_mf_45_license_gate_matches_spec(licenses: dict[str, LicenseEntry]) -> None:
    expected = {
        "Qwen3.5": ("Apache-2.0", LicenseStatus.ALLOWED),
        "Gemma 4": ("Apache-2.0", LicenseStatus.ALLOWED),
        "e5-small": ("MIT", LicenseStatus.ALLOWED),
        "LaMP": ("CC-BY-NC-SA-4.0", LicenseStatus.FORBIDDEN),
        "OPPU": ("none", LicenseStatus.FORBIDDEN),
        "OSim": ("unverified", LicenseStatus.EVAL_SIMULATION_ONLY),
        "Ditto": ("unverified", LicenseStatus.EVAL_SIMULATION_ONLY),
        "UserLM": ("MIT", LicenseStatus.EVAL_SIMULATION_ONLY),
        "EmbeddingGemma 2": ("Apache-2.0", LicenseStatus.ALLOWED),
    }
    for name, (license_id, status) in expected.items():
        assert (licenses[name].license, licenses[name].status) == (license_id, status)
    assert licenses["Llama"].status is LicenseStatus.FLAGGED
    assert licenses["Llama"].condition == "user_count"


SIM_LICENSES = {"OSim": "unverified", "Ditto": "unverified", "UserLM": "MIT"}


def _gate(manifest_data: Doc, tmp_path: Path, write_toml: Writer, **fields: object) -> Path:
    return write_toml(tmp_path / "gate.toml", manifest_data(**fields))


@pytest.mark.parametrize("source", ["OSim", "Ditto", "UserLM"])
def test_mf_54_simulation_source_in_train_manifest_is_rejected(
    tmp_path: Path,
    write_toml: Writer,
    manifest_data: Doc,
    licenses: dict[str, LicenseEntry],
    source: str,
) -> None:
    path = _gate(manifest_data, tmp_path, write_toml, source=source, license=SIM_LICENSES[source])
    with pytest.raises(ManifestError, match="cannot be used to train"):
        check_license(load_manifest(path), licenses)


@pytest.mark.parametrize("usage", ["eval_only", "simulation_only"])
@pytest.mark.parametrize("source", ["OSim", "Ditto", "UserLM"])
def test_mf_54_simulation_source_is_allowed_outside_training(
    tmp_path: Path,
    write_toml: Writer,
    manifest_data: Doc,
    licenses: dict[str, LicenseEntry],
    source: str,
    usage: str,
) -> None:
    path = _gate(
        manifest_data,
        tmp_path,
        write_toml,
        source=source,
        license=SIM_LICENSES[source],
        usage=usage,
    )
    check_license(load_manifest(path), licenses)


@pytest.mark.parametrize("usage", ["train", "eval_only", "simulation_only"])
@pytest.mark.parametrize(
    ("source", "license_id"),
    [("LaMP", "CC-BY-NC-SA-4.0"), ("OPPU", "none")],
)
def test_mf_45_forbidden_or_unverified_source_is_rejected(
    tmp_path: Path,
    write_toml: Writer,
    manifest_data: Doc,
    licenses: dict[str, LicenseEntry],
    source: str,
    license_id: str,
    usage: str,
) -> None:
    path = _gate(
        manifest_data, tmp_path, write_toml, source=source, license=license_id, usage=usage
    )
    with pytest.raises(ManifestError, match=r"forbidden|unverified"):
        check_license(load_manifest(path), licenses)


@pytest.mark.parametrize("usage", ["train", "eval_only", "simulation_only"])
def test_mf_45_unverified_component_is_rejected_for_any_use(
    tmp_path: Path,
    write_toml: Writer,
    manifest_data: Doc,
    licenses: dict[str, LicenseEntry],
    usage: str,
) -> None:
    gate = {
        **licenses,
        "Pending": LicenseEntry(
            name="Pending", license="unverified", status=LicenseStatus.UNVERIFIED, condition=None
        ),
    }
    path = _gate(
        manifest_data, tmp_path, write_toml, source="Pending", license="unverified", usage=usage
    )
    with pytest.raises(ManifestError, match="unverified"):
        check_license(load_manifest(path), gate)


def test_mf_45_flagged_llama_cannot_train(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, licenses: dict[str, LicenseEntry]
) -> None:
    path = _gate(
        manifest_data, tmp_path, write_toml, source="Llama", license="Llama Community License"
    )
    with pytest.raises(ManifestError, match="flagged"):
        check_license(load_manifest(path), licenses)


def test_mf_45_unknown_source_is_rejected(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, licenses: dict[str, LicenseEntry]
) -> None:
    path = _gate(manifest_data, tmp_path, write_toml, source="Somewhere", license="MIT")
    with pytest.raises(ManifestError, match="no entry"):
        check_license(load_manifest(path), licenses)


def test_mf_45_declared_license_must_match_gate(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, licenses: dict[str, LicenseEntry]
) -> None:
    path = _gate(manifest_data, tmp_path, write_toml, license="MIT")
    with pytest.raises(ManifestError, match="declares license"):
        check_license(load_manifest(path), licenses)


@pytest.mark.parametrize("generator", ["UserLM", "LaMP", "OSim", "Unknown"])
def test_mf_45_synthetic_generator_is_gated_for_training(
    tmp_path: Path,
    write_toml: Writer,
    manifest_data: Doc,
    licenses: dict[str, LicenseEntry],
    generator: str,
) -> None:
    production = {"method": "synthetic", "generator_model": generator, "prompt_version": "p-1"}
    path = _gate(manifest_data, tmp_path, write_toml, production=production)
    with pytest.raises(ManifestError, match="generator model"):
        check_license(load_manifest(path), licenses)


def test_mf_45_allowed_synthetic_manifest_passes(
    tmp_path: Path, write_toml: Writer, manifest_data: Doc, licenses: dict[str, LicenseEntry]
) -> None:
    check_license(load_manifest(_gate(manifest_data, tmp_path, write_toml)), licenses)
