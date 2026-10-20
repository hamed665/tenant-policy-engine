# Engineering walkthrough

**Hamed Minaei · Multi-tenant authorization**

## Problem and implemented scope

Tenant-bound resource checks, role policies, classified data rules and auditable revocation.

## Demonstration evidence

The demonstration compares an allowed owner read against denied viewer deletion, cross-tenant lookup and revoked membership.

Run `python demo.py` and compare with `docs/demo-output.json`.
Run `python -m unittest discover -s tests -v` to inspect failure-path behavior.
The verification workflow runs those commands on Python 3.11, 3.12 and 3.13.

## Review guide

1. Read the core implementation and the Architecture section of README.
2. Inspect tests for both permitted behavior and failure/ambiguity cases.
3. Review PR #1 for the initial implementation and its verification results.
4. Read Security and Limitations before extending or integrating the component.

## Portfolio description

"Multi-tenant authorization: Tenant-bound resource checks, role policies, classified data rules and auditable revocation. Includes a reproducible synthetic demonstration,
behavioral tests and CI verification."

This describes the implemented component, not an operating production service.
Development assistance and ownership are recorded in AUTHORS.md.
