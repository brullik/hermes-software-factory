# Release safety gates

Release operation results are checked after JSON Schema validation and before a
worker can advance the lifecycle. The worker requires an injected
`ReleaseExecutor` for every `release-operator` task; without one it blocks the
task before invoking the model.

- A staging result cannot claim a merge or production deployment.
- A production result must bind the merge SHA to the candidate SHA.
- Production requires a durable successful staging operation and promotes its
  exact immutable `sha256:` image digest.
- The checked GitHub adapter requires an open pull request, the configured
  approval mode, a clean merge state, and every explicitly configured required
  check before squash merge.

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
redacted from the public repository). Factory self-releases remain isolated at
`/opt/hermes-factory`; external product releases are isolated under
`/opt/hermes-factory-products/<product_id>`. Secrets and credentials remain
outside both release trees.

The worker now constructs a concrete `ConfiguredReleaseExecutor` at runtime.
For an external product it derives the repository from the leased workspace's
HTTPS GitHub `origin`, rejects a repository outside the configured owner,
excludes generated release evidence, and publishes source changes through a
controller-owned commit and pull request. Protected paths such as workflows,
secrets, and production configuration cannot cross this boundary. Staging is a
safe extraction of that commit's `git archive`, not a copy of mutable `.git`
metadata, generated artifacts, or Python bytecode caches. Before staging
promotion, the controller reruns
secret, SAST, offline dependency, and license gates against that exact candidate
SHA and stores one immutable assurance bundle.

Production reloads the durable staging record, verifies the same PR head and
digest, applies single-owner or independent governance, and promotes the merge
commit through the absolute root-owned `production_helper`. The helper receives
only the derived repository, trusted product id, immutable merge SHA, and
accepted staging digest; no shell string, health command, source path, or
install root crosses the privilege boundary. External source is never executed
as root: production health is an exact structural digest check, while
application tests and security assurance remain mandatory unprivileged gates.

These are deterministic policy checks. A model-generated claim is not release
evidence by itself. The executor receives the model proposal and must return
the authoritative result after the GitHub/deployment side effects; only that
returned result is persisted and used to advance the pipeline.

The disaster-recovery command restores controller state, resumes a pending task
through a new lease, and verifies a restored pilot SQLite database. Offsite restic
configuration is still an owner-controlled external acceptance item.
