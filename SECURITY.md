# Security

One is proprietary and only Suiss team members work on it.

## Reporting a vulnerability

- **Team members:** report privately to the maintainers through the internal security channel. Never put a vulnerability in an issue, a commit message or a chat that is not the security channel.
- **Everyone else:** use the security contact Suiss publishes for its products. Reports are tracked in the internal vulnerability log.

Include what is affected, how to reproduce it and the impact you expect.

## Handling

- A leaked secret is revoked or rotated first, then removed from history; a private repository does not make a leaked secret safe.
- Fixes ship under their own heading in the changelog. When users need to do something, the product and the release notes say so in plain language.
- There is no public advisory process for this repository; the published security design describes what One guarantees.
