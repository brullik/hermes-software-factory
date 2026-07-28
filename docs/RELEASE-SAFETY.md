# Release safety gates

Release operation results are checked after JSON Schema validation and before a
worker can advance the lifecycle. The worker requires an injected
`ReleaseExecutor` for every `release-operator` task; without one it blocks the
task before invoking the model.

- A staging result cannot claim a merge or production deployment.
- A production result must bind the merge SHA to the candidate SHA.
- Production requires a durable successful staging operation and promotes its
  exact immutable `sha256:` image digest.
- The checked GitHub adapter requires an open pull request, independent approval,
  clean merge state, and passing required checks before squash merge.

## Single-owner production mode

The owner has explicitly enabled `single_owner` mode for this installation. This
is a recorded governance choice, not a simulated independent review. When the
owner override is used, the adapter still requires an open PR, exact head SHA,
clean merge state, passing required checks, and a non-secret audit reason. It
then uses GitHub's explicit administrative merge path and records
`approval_mode=owner_override`; it never reports that an independent reviewer
approved the change. The default adapter remains independent-review-first unless
`single_owner_mode=True` and `owner_override=True` are both supplied.

The configured production target is the owner's current VPS (its address is
redacted from the public repository), with `/opt/hermes-factory` as the install root and the allowlisted
`scripts/deploy/promote-release.py` entrypoint. Secrets and credentials remain
outside the repository.

These are deterministic policy checks. A model-generated claim is not release
evidence by itself. The executor receives the model proposal and must return
the authoritative result after the GitHub/deployment side effects; only that
returned result is persisted and used to advance the pipeline.

The disaster-recovery command restores controller state, resumes a pending task
through a new lease, and verifies a restored pilot SQLite database. Offsite restic
configuration is still an owner-controlled external acceptance item.
