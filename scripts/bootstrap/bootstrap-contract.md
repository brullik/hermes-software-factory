# Bootstrap contract

Bootstrap implementation must be idempotent and split into:

1. read-only preflight;
2. backups of files that will change;
3. package install from official repositories;
4. service user/directories;
5. exact version pinning;
6. credentials via OWNER_ACTION;
7. smoke tests;
8. SSH hardening only after a second key-based session is proven;
9. rollback instructions.

The agent must not run a remote `curl | bash` installer without first downloading, hashing and inspecting the script or using an official package path. Hermes official installer may be used only after provenance and exact resulting version are recorded.
