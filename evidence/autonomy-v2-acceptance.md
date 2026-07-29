# Hermes Autonomy v2 acceptance report

Date: 2026-07-29

Source requirements:

- package: `hermes_autonomy_fix_pack.zip`
- SHA-256: `43CB5DC4E5DE987A07D6E3725F1BE2E3B5F6BB0B3290B32920D62F1CF35359C3`
- target release: `2.1.7`

## Required acceptance matrix

| Test group | Required | Result | Evidence |
|---|---:|---|---|
| AUT-P0-001..020 | yes | PASS | `tests/test_autonomy_v2.py`; `.venv\Scripts\python.exe -m pytest -q --tb=short` |
| AUT-P0-021 new repository E2E | yes | PASS | `tests/test_autonomy_v2_e2e.py::test_AUT_P0_021_new_repository_full_e2e_without_owner` |
| AUT-P0-022 private repository repair/replan E2E | yes | PASS | `tests/test_autonomy_v2_e2e.py::test_AUT_P0_022_private_repository_repair_replan_full_e2e` |
| AUT-P1-001..010 | before production-ready | PASS | `tests/test_autonomy_v2_e2e.py`; durable state and restart assertions included |
| Cross-product conflict isolation | yes | PASS | AUT-P1-001 uses the same conflict key in two products while preserving same-product serialization |
| Persistent workspace claim isolation | yes | PASS | AUT-P1-001 proves one CLAIMED task per product while a second product continues concurrently |
| Concurrent migration startup | yes | PASS | AUT-P0-019 deterministically holds the writer lock while another process starts and proves post-lock version recheck |
| Semantic plan precommit validation | yes | PASS | Worker regression proves exact safe edge coordinates schedule bounded repair; identity regressions prove existing task keys and reused plan IDs with changed immutable digests are rejected before mutation |
| Outcome commit failure boundary | yes | PASS | Injected SQLite integrity error becomes a durable controller failure without process escape or partial successor ingestion |
| In-place retry routing exclusivity | yes | PASS | `test_AUT_P0_006_retryable_in_place_repair_is_not_double_routed` proves one causal path and failure resolution |
| Failure-route crash replay | yes | PASS | Deterministic task-contract and repair-brief IDs replay a crash between immutable artifact persistence and task insertion without evidence conflict or duplicate recovery work |
| Causal recovery closure | yes | PASS | A successful recovery atomically resolves its full parent failure chain, active hypotheses, and matching controller incidents; migration v6 reconciles historical accepted/superseded recovery chains |
| Executable-plan liveness | yes | PASS | Planning-only graphs are rejected, unresolved rows without runnable work are not liveness proof, and an exhausted graph creates a real Replanner task for revision N+1 |
| Incident result semantics | yes | PASS | Schema-valid `incident-result.status=recovered` is treated as terminal recovery success while `contained` remains non-terminal |
| Architecture anti-pattern assertions | yes | PASS | `tests/test_autonomy_v2_e2e.py::test_AUT_ARCH_001_canonical_v2_path_excludes_legacy_heuristics` |
| Legacy 2.0.19 migration | yes | PASS | deterministic fixture SHA-256 `B6E1FE06EBC4DA35376D0640249B13D1ED66D23353C3BAAC875A9518CBE88736`; AUT-P0-019 verifies URL-only repository binding in v4 and bounded workspace-collision recovery in v5 |
| Full existing suite | yes | PASS | 201 tests; `.venv\Scripts\python.exe -m pytest -q --tb=short` |
| Static lint | yes | PASS | `.venv\Scripts\python.exe -m ruff check factory scripts tests pilot` |
| Type checking | yes | PASS | 60 source files; `.venv\Scripts\python.exe -m mypy factory scripts pilot` |
| Schema/package validation | yes | PASS | `.venv\Scripts\python.exe scripts\validate_package.py` |
| Secret scan | yes | PASS | `.venv\Scripts\python.exe scripts\secret_scan.py` |
| Manifest/SBOM | yes | PASS | `scripts\build_manifest.py`; `scripts\verify_manifest.py`; `scripts\build_sbom.py --check` |

None of the required AUT-P0/P1 cases is skipped. The E2E cases exercise durable
SQLite state, process restart, repository adapters, repair/replan lineage,
completion evidence, and the absence of routine `OWNER_ACTION_REQUIRED`.

## Secret handling decision

Raw candidate secret values may be inspected only inside the protected adapter
boundary and are never written to prompts, task contracts, failure evidence,
logs, or model-visible diagnostics. Agents receive the exact safe detector
coordinates, detector class, reason code, and a redacted fingerprint. This is
enough to locate and rewrite the offending source while preventing a diagnostic
record from becoming a second secret exposure.

## Production verification

This checked-in report records the pre-release acceptance run. Deployment
evidence, production service health, migration status, controlled production
E2E, backup snapshot, and restore proof are recorded by the release workflow
against the immutable merged commit.
