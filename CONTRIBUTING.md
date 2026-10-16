# Contributing to One

One is proprietary. Only Suiss team members contribute, and maintainers push signed commits directly to `main`. These rules are binding.

## First day

```sh
git clone git@github.com:e-suiss/one.git && cd one
git config core.hooksPath .githooks   # formatting and secret scan before each commit
just deps                             # PostgreSQL + pgvector, object store, monitoring
just test                             # the same tests CI runs on every push
just check                            # the same checks CI runs on every push
```

`just dev` starts the full environment with local Access, Relay and Work. It refuses to start while a sibling image in `deploy/compat.toml` is not published: there is no fallback mode and nothing is faked. The model server needs an NVIDIA GPU (`just dev-model` on a GPU host). Tool versions are pinned in `rust-toolchain.toml`, `.node-version`, `ml/.python-version`, `apps/apple/versions.toml` and `apps/android/versions.toml`.

There is no development mode: security and privacy checks are never disabled locally.

## Code rules (summary)

- Code, comments, commit messages and issues are in English.
- No explanatory comments. Allowed: `// SAFETY:` notes, doc comments (`///`, one `//!` paragraph per module), bare specification ID lines such as `// SEC-12`, `TODO(#123)`, shebangs and tool directives, and GitHub Actions version notes. The reason lives in the specification.
- Rust: `rustfmt`, workspace lints, warnings are errors; no panics on the request path; checked arithmetic; `unsafe` only in generated bindings.
- Components are split into `domain` / `ports` / `app` / `adapters`; time and randomness come only from the `Clock` and `Rng` ports.
- A record, its derived state and its outbox event commit in one transaction; external calls never run inside a transaction.
- Untrusted content never reaches the planner; every value carries its provenance label.
- User data is never logged; telemetry takes only opaque IDs, counts, durations and numbers from the closed field list.
- No physical deletes (`DELETE`/`TRUNCATE`); forgetting is crypto-shredding.
- Each JavaScript package is its own npm project; there is no JavaScript at the repository root.
- Tests run against real PostgreSQL, object storage, Access, Relay and Work; flaky tests are quarantined within 24 hours, never retried until green.
- A test that verifies a specification rule starts its name with the rule ID: `sec_12_planner_rejects_untrusted_value`, `test_t_33_…`, `t_29_…`.

## Specification

- When the specification is ambiguous, contradictory or silent, the code does not decide. Raise it as an open question; implement it after it has a decision ID.
- Canonical concept and relation code names come only from `conformance/catalog/glossary.toml`; no synonyms. A new concept is a concept candidate: the commit that adds it carries `Concept-Candidate:` with its decision ID.
- Vendor benchmark numbers are claims, not measurements. Numbers we publish come from our own evaluation sets with code, raw output, dataset version and run command.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/) with the crate or area as scope; signed; linear history; no force push.
- CI runs on every push. Do not push on top of a red `main`; fix or revert first.
- A commit that implements or changes a specification decision names the decision ID and carries the `decision` label on its issue.
- A commit that touches a security-sensitive path (see `.github/CODEOWNERS`) ends with:

  ```text
  Threat: what this could break or expose.
  Privacy: what personal data it touches, if any.

  Security-Sensitive: yes
  ```

  `cargo xtask commits BASE HEAD` checks this in CI.

## Review checklist

### Concept test

Every new concept, field or feature answers these in order:

1. Is it only a chat message, a screen or a notification? Then it is an interaction mode or a view, not a concept.
2. Does it have its own identity and do other records refer to it? Then it is a canonical concept candidate; otherwise a typed extension.
3. Is it owned by Access, Relay, Work or Pay? Then One keeps a reference, never a copy.
4. Is it an object of a protocol or framework? Then it is a projection, not canonical.
5. Can it be derived from another record? Then it is a view and is not stored as canonical.

A new canonical concept is marked as a concept candidate and is never added in code on its own.

### Change test

A change does not merge if it does any of the following:

1. Derives authority or instructions from observation, inference, memory, routines, trust or a "yes" in chat, or bypasses an Access denial.
2. Executes model output without a typed intent and an Access decision.
3. Gives untrusted content to the planner or drops a provenance label.
4. Moves more personal context than the task needs to the cloud, to Work or to another party.
5. Keeps task, memory or personality state as a single copy at a model provider or on one device.
6. Rewards or targets engagement measures such as opens, session time or daily use.
7. Learns its way around the user's mute, quiet hours or focus mode.
8. Produces personal data readable without the user's key, or silently weakens encryption.
9. Physically deletes data, or promises "deleted" for anything other than crypto-shredding.
10. Re-implements the work of Access, Relay, Work or Pay inside One.
11. Hides the agent, presents it as a human, or reaches sites without identifying itself.
12. Puts credentials, card data or cookies into model context.
13. Creates memory or model state the user cannot see, correct or make One forget.
14. Promises control the executor cannot actually provide ("stopped", "undone").
15. Presents an approval or setting a non-technical user cannot understand.
16. Ships a capability or behaviour that has not been measured.

## Security

See [SECURITY.md](SECURITY.md).
