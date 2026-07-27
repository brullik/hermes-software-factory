# Матрица ролей и модельных уровней

## Правило

У каждой смысловой роли есть несколько capability levels. Это не означает, что все уровни вызываются всегда. Controller выбирает минимальный допустимый tier и повышает его только по evidence.

| Роль | D0/W0 | Luna | Terra | Sol |
|---|---|---|---|---|
| Product Director | defaults/risk hints | low-risk draft | normal validation | high-risk strategy |
| Product Analyst | extraction rules | standard stories | complex domain | arbitration |
| Solution Architect | templates/capacity | simple CRUD | normal architecture | high-risk/cross-system |
| Task Specifier | DAG templates | normal tasks | conflicts/high risk | редко |
| Builder | formatter/codemod | local change | cross-file/integration | exhausted/very complex |
| Test Engineer | runners/templates | unit/basic integration | e2e/contract/concurrency | high-risk strategy |
| Reviewer | gates | low-risk semantic | normal review | high-risk/false PASS |
| Security Reviewer | scanners | low-risk triage | auth/integration | high risk |
| Release Operator | adapters | notes | incident analysis | severe incident |
| Product Tester | e2e scripts | ordinary UX failure | systemic failure | high-risk arbitration |
| Incident Recovery | rehearsed rollback | - | normal RCA | severe/unknown integrity |
| Benchmark | metrics | summary | adjudication | expert route dispute |

## Attempt limits

- Luna: initial + one targeted repair.
- Terra: initial + one targeted repair.
- Sol: one expert/arbitration attempt.
- Third same-tier semantic attempt: only visual/flaky/nondeterministic class with new evidence.
- Transport retries: up to three, do not count as semantic attempts.

## Почему эта схема экономична

Большинство задач завершается детерминированно или на Luna. Terra получает не весь проект, а compact Context Pack и результаты конкретных gates. Sol вызывается редко и не тратит контекст на рутинные операции.
