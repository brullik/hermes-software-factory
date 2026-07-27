# Implementation ledger format

Реализатор ведёт `evidence/implementation-ledger.jsonl`. Каждая строка:

```json
{
  "timestamp": "ISO-8601 UTC",
  "phase": "compatibility|bootstrap|controller|profiles|github|pilot|acceptance",
  "action": "stable machine-readable code",
  "status": "started|passed|failed|rolled_back|blocked_external",
  "subject": "component or resource",
  "version_or_sha": "exact value",
  "evidence_ref": "path or URL",
  "policy_digest": "sha256",
  "notes": "compact redacted note"
}
```

Ledger не содержит secrets и не заменяет full logs. Он позволяет другому агенту продолжить после обрыва сессии.
