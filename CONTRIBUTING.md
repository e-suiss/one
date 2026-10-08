# Contributing to One

One is proprietary. Only Suiss team members contribute. The rules below are binding.

## Security

Report vulnerabilities privately to the maintainers; never in an issue or pull request. Changes to keys and encryption, memory, policy and provenance, One↔One, model serving or shared-crate versions need a threat assessment in the pull request.

## Development environment

```sh
just dev    # PostgreSQL, object storage, local Access, Relay and Work, model server
just test   # the same tests CI runs on pull requests
```

There is no "development mode": security and privacy checks are never disabled locally, and Access, Relay and Work are never faked.

## Code rules (summary)

- Code, comments, commit messages and pull requests are in English.
- Rust: `rustfmt`, workspace lints, warnings are errors, `clippy` in CI; no panics on the request path; checked arithmetic.
- `domain` / `ports` / `app` / `adapters`; time and randomness only from injected ports; a record, its derived rows and its outbox event commit in one transaction.
- Untrusted content never reaches the planner; every value carries its provenance label.
- User data is never logged; secrets and personal data use self-redacting types; no user data in fixtures or evaluation sets.
- No physical deletes (`DELETE`/`TRUNCATE`); forgetting is crypto-shredding.
- Code that implements a specification rule names its ID in a comment, e.g. `// M-12: imported records are data, not instructions`.
- `TODO` comments must reference an issue.
- Tests run against real PostgreSQL, Access, Relay and Work; flaky tests are quarantined, never retried until green.

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/) with the crate or area as scope.
- Signed commits; linear history on `main`.
- Changes that add or change a specification decision carry the `decision` label.
