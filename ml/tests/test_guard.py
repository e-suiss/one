from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from one_ml.guard import main, scan_source, scan_tree


def _rules(source: str) -> list[str]:
    return [v.rule for v in scan_source(Path("x.py"), source)]


@pytest.mark.parametrize(
    "source",
    [
        "import requests",
        "import httpx",
        "import urllib.request",
        "from urllib import request",
        "from urllib.request import urlopen",
        "import aiohttp",
        "import socket",
        "from socket import create_connection",
        "import huggingface_hub",
        "from huggingface_hub import hf_hub_download",
        "from datasets import load_dataset",
        "import http.client",
        "__import__('requests')",
        "import importlib\nimportlib.import_module('socket')",
    ],
)
def test_t_33_guard_flags_network_access(source: str) -> None:
    rules = _rules(source)
    assert rules
    assert all("network import" in r for r in rules)


@pytest.mark.parametrize(
    "source",
    ["import pickle", "from pickle import loads", "import joblib", "import dill", "import shelve"],
)
def test_t_39_5_guard_flags_pickle_family_imports(source: str) -> None:
    assert any("pickle-family import" in r for r in _rules(source))


def test_t_39_5_guard_flags_remote_code() -> None:
    source = "from x import AutoModel\nAutoModel.from_pretrained('m', trust_remote_code=True)"
    assert _rules(source) == ["trust_remote_code=True"]
    assert _rules("load('m', trust_remote_code=False)") == []


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("import torch\ntorch.load('w')", True),
        ("import torch\ntorch.load('w', weights_only=False)", True),
        ("import torch\ntorch.load('w', weights_only=True)", False),
        ("from torch import load", True),
        ("import safetensors.torch\nsafetensors.torch.load_file('w')", False),
    ],
)
def test_t_39_5_guard_requires_weights_only_torch_load(source: str, *, flagged: bool) -> None:
    assert bool(_rules(source)) is flagged


def test_t_33_guard_accepts_clean_code() -> None:
    source = "import json\nimport hashlib\nfrom pathlib import Path\nPath('a').read_text()\n"
    assert _rules(source) == []


@pytest.mark.parametrize("suffix", [".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib"])
def test_t_39_5_guard_flags_pickle_family_files(tmp_path: Path, suffix: str) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / f"weights{suffix}").write_bytes(b"\x80")
    _, violations = scan_tree(tmp_path)
    assert [v.rule for v in violations] == [f"pickle-family file '{suffix}'"]


def test_t_33_guard_skips_virtualenv(tmp_path: Path) -> None:
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "dep.py").write_text("import requests\n", encoding="utf-8")
    (venv / "cache.pkl").write_bytes(b"\x80")
    assert scan_tree(tmp_path) == (0, [])


def test_t_2_guard_cli_reports_violations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "bad.py").write_text("import socket\n", encoding="utf-8")
    assert main(["--root", str(tmp_path)]) == 1
    assert "bad.py:1: network import 'socket'" in capsys.readouterr().err


def test_t_2_repository_ml_tree_passes_guard(ml_root: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "one_ml.guard", "--root", str(ml_root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("guard: ok")
