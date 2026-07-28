# Security policy

## Scope

This repository contains public architecture, policies, prompts and reference code for Hermes Software Factory. It must never contain credentials, production data, unredacted logs, private agent transcripts or runtime state.

## Reporting

Report a suspected vulnerability privately through GitHub's private vulnerability reporting feature when it is enabled. Do not open a public issue containing exploit details, tokens, keys, customer data or production endpoints.

## Mandatory handling

1. Revoke or rotate an exposed credential before any code change.
2. Preserve immutable evidence and affected commit/image digests.
3. Stop unsafe deployment paths and use rollback when integrity is uncertain.
4. Create an incident record and apply `policies/security-policy.yaml` and `prompts/roles/incident-recovery.md`.
5. Never weaken a gate or delete evidence to obtain PASS.

The implementation agent must configure an equivalent private reporting path during bootstrap.

## Dependency-audit privacy

Target runtime dependencies are matched with the root-owned OSV-Scanner binary
and a locally cached PyPI advisory archive. The controller invokes the scanner
with `--offline --no-resolve`; package names, versions, repository identifiers,
and file hashes are not sent to OSV, PyPI, or deps.dev during a gate.

The public PyPI advisory archive is refreshed independently by
`hermes-factory-osv-db.timer`. The updater receives no target path or dependency
inventory. A missing, untrusted, corrupt, or older-than-72-hours database makes
the mandatory dependency gate fail closed.
