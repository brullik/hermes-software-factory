# Pilot backlog DAG

```text
PILOT-001 (contract/docs) -> PILOT-002 (runtime/API) -> PILOT-003 (container hardening)
PILOT-002 -> PILOT-004 (black-box smoke)
PILOT-003 -> PILOT-005 (staging deploy)
PILOT-004 + PILOT-005 -> PILOT-006 (rollback rehearsal)
```

All tasks are low risk and use separate conflict keys. No task authorizes credentials, public exposure, or production deployment.
