# Hermes 2.4.13 error-free release process

Hermes 2.4.13 separates product autonomy from release authority. Stable A keeps
production authority, Candidate B runs with a separate user, state root,
database, runtime directory, and candidate-scoped credentials, and the
independent verifier has neither model nor production credentials.

The runtime is closed-world. `factory/transition_catalog.py` is the sole product
state/event registry and `factory/failure_catalog.py` is the sole failure
owner/action registry. Unknown coordinates fail closed as Controller quarantine.
Task capabilities are reconstructed only from the canonical stage profile and
an exact toolchain proof; parent/model capabilities and wildcard scopes are not
eligible inputs.

Every candidate release must pass, in order:

1. Q0 source integrity and reproducible artifact;
2. Q1 schemas, Ruff, mypy, and catalog totality;
3. Q2 bounded safety/liveness model;
4. Q3 property and mutation testing;
5. Q4 replay of every versioned historical incident fixture;
6. Q5 every-version migration/crash/restore matrix;
7. Q6 real isolated Controller/worker/Gateway/Hermes/SQLite/service adapters;
8. Q7 at least 72 actual hours of side-effect-free shadow differential replay;
9. Q8 exactly ten fresh-state, first-pass canary archetypes.

Q7 treats a known-state `product_transition` from a pre-catalog Stable release
that lacks its historical triggering `event` as an explicit
`LEGACY_OBSERVED` outcome. It is never executed by Candidate B. A non-empty
unknown event or an unknown state remains a Controller quarantine and an
unexplained divergence.

The immutable feed retains Stable A's export timestamp. The independent
verifier separately timestamps each replay when it appends the commit-scoped Q7
journal entry, so evidence from a prior release epoch cannot satisfy the 72-hour
observation gate.

Every verifier cycle also appends a separate commit-scoped heartbeat hash chain
bound to the current decision-journal head. Q7 rejects late startup, gaps over
five minutes, stale final heartbeats, downtime counted as soak, or a heartbeat
that does not bind the complete replay. The finalizer requires a fresh verifier
cycle before evaluating the gate, then quiesces the Q7 timers before recording
the immutable decision and starting clean canaries.

Any Controller defect starts a new release epoch. A corrected Controller cannot
continue an old clean canary. Promotion requires an Ed25519 manifest from the
independent verifier, an unchanged source commit and candidate digest, verified
backup/restore and rollback evidence, and the root-owned release helper. Stable
A remains the rollback target through heightened observation and LTS graduation.

The executable stage runner is `python -m scripts.release_qualify stage ...`.
The verifier signs with `python -m scripts.release_qualify verify`; a separate
root service installs the verified envelope. Candidate B cannot access either
the verifier state or `/usr/local/sbin/hermes-factory-release-submit`.
