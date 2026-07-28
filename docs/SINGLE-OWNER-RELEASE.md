# Single-owner release decision

Status: enabled by the owner for this installation.

The project operates as a single-owner system. The independent GitHub reviewer
requirement is intentionally waived; the system must not claim that an
independent review occurred. Release governance remains fail-closed for the
immutable candidate SHA, required checks, clean merge state, health checks,
rollback, and audit evidence.

The production target is the owner's VPS:

- host: `current-vps.example.invalid` (actual address is kept outside the public repository)
- install root: `/opt/hermes-factory`
- deployment entrypoint: `scripts/deploy/promote-release.py`
- mode: `current_vps`

An owner override requires an explicit non-secret reason and is represented as
`approval_mode=owner_override`. It is not an independent approval. Offsite
backup is connected to the owner's encrypted Backblaze B2 Restic repository,
with a separate workstation repository retained as a fallback.
