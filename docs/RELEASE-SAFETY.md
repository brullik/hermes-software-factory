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

These are deterministic policy checks. A model-generated claim is not release
evidence by itself. The executor receives the model proposal and must return
the authoritative result after the GitHub/deployment side effects; only that
returned result is persisted and used to advance the pipeline.

The disaster-recovery command restores controller state, resumes a pending task
through a new lease, and verifies a restored pilot SQLite database. Offsite restic
configuration is still an owner-controlled external acceptance item.
