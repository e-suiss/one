# one-ml

ML, evaluation and simulation for One. Never imported by production; data lives outside the repo
and is read only through manifests in `datasets/manifests/` (license gate: `licenses.toml`).

```sh
uv sync --locked
uv run ruff format --check . && uv run ruff check .
uv run mypy
uv run pytest -q
uv run python -m one_ml.guard
uv run python -m one_ml.evals run --set evals/tr_en/set.toml --model ID --code-version V --out runs/ID.json
uv run pip-audit --skip-editable
```
