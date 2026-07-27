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
