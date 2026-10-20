# Tenant Policy Engine

### A Hamed Minaei engineering project

![Verify](https://github.com/hamed665/tenant-policy-engine/actions/workflows/verify.yml/badge.svg)

A tenant-scoped authorization engine with resource ownership rules, immediate membership revocation and an atomic decision audit.

**Status:** tested reference implementation with a reproducible synthetic CLI demo.
**Project owner & maintainer:** [Hamed Minaei](https://github.com/hamed665)  
**Engineering focus:** Multi-tenant authorization  
**License:** MIT · Copyright © 2026 Hamed Minaei

## Features

- Server-owned tenant memberships and four explicit roles.
- Deny-by-default handling of unknown subjects, unknown actions and missing resources.
- Cross-tenant resource denial even when a subject owns both tenants.
- Classified resources require tenant-owner access; analyst edits require resource ownership.
- Atomic decision/audit transactions and tenant-filtered operator queries.

## Quick start

Python 3.11 or newer; only the standard library is used. No package install is required.

```bash
git clone https://github.com/hamed665/tenant-policy-engine.git
cd tenant-policy-engine
python demo.py
python -m unittest discover -s tests -v
```

The demo performs real computation against synthetic data. Its captured output is in
[docs/demo-output.json](docs/demo-output.json). It uses no customer records or production systems.

## Architecture

Administrative provisioning stores memberships and resources in SQLite. The application passes a subject from its verified identity layer, a selected tenant, an action and an optional resource ID. `decide` locks a transaction before reading current membership and resource policy, then writes both successful and denied decisions before returning. No membership cache is used, so the next decision sees committed revocation.

Core implementation: [policy.py](policy.py).
The core is separate from the demonstration runner and can be imported directly:

```python
from policy import PolicyEngine

engine = PolicyEngine(":memory:")
engine.provision_member("tenant-a", "verified-subject", "analyst")
engine.provision_resource("report-1", "tenant-a", "verified-subject")
decision = engine.decide(tenant="tenant-a", subject="verified-subject",
                         action="update", resource="report-1")
assert decision["allowed"]
engine.revoke("tenant-a", "verified-subject")
assert not engine.decide(tenant="tenant-a", subject="verified-subject",
                         action="read", resource="report-1")["allowed"]
engine.close()
```

## Installation and configuration

Construct `PolicyEngine(path)` with a database path or `:memory:` for isolated experiments. Provision memberships through a trusted administrative integration. Supported actions are read, create, update, delete and export; roles are owner, admin, analyst and viewer. There is no implicit role inheritance. `.env.example` documents a suggested database path for a future adapter; environment files are not loaded automatically.

An optional Dockerfile runs the same demo under a non-root UID:

```bash
docker build -t tenant-policy-engine .
docker run --rm --read-only --network none --tmpfs /tmp:rw,noexec,nosuid,size=32m tenant-policy-engine
```

The Docker definition is provided for reproducibility. Container execution is not claimed as verified unless recorded in VALIDATION.md.

## Testing

`python -m unittest discover -s tests -v` runs 13 behavioral tests.
GitHub Actions runs those tests and the demo on Python 3.11, 3.12 and 3.13.
Action dependencies are pinned to commit SHAs and the workflow token is read-only.
See [VALIDATION.md](VALIDATION.md) for local evidence and verification scope.

## Security

This library does not authenticate callers. Derive subject identity from verified sessions or tokens, never JSON request fields. Do not expose provisioning, revoke or audit directly to end users. Decision audit records contain identities/resource IDs and need restricted access and retention. Missing and foreign-tenant resources return the same reason. The database owner can alter audit history; this is not a tamper-proof log.

## Limitations

The decision transaction does not include your application business write. If authorization and mutation must be atomic, integrate both in one transaction or use database-native row policies. No HTTP server, SSO, invite flow, per-field policy, policy language, immutable audit storage or distributed consistency is provided. This is a reference authorization component, not a complete SaaS control plane.

## Maintainer

[Hamed Minaei](https://github.com/hamed665) owns and maintains this portfolio repository.
For implementation details, review the source, behavioral tests and merged pull requests.
See [AUTHORS.md](AUTHORS.md) for development attribution and [ENGINEERING.md](ENGINEERING.md)
for a concise technical walkthrough.

## Attribution and ownership

This repository is an original implementation created for Hamed Minaei's portfolio with
AI-assisted development and local verification. No upstream application's source code or
Git history was imported. Python's standard library supplies the underlying runtime,
SQLite bindings, cryptography primitives, JSON, dates and decimal arithmetic as used here.
The implementation, tests, synthetic fixtures and documentation are maintained in this repository.

License: [MIT](LICENSE). No third-party runtime packages are required.
