# 8. Deployment, backup и эксплуатация

## 8.1. Artifact promotion

Один и тот же container image digest проходит:

`build -> scan -> staging -> acceptance -> production`

Production не пересобирает исходный код.

## 8.2. Staging

Обязателен для всех сервисов. Staging:

- отдельные credentials;
- синтетические данные;
- отдельная database/schema;
- HTTPS либо localhost tunnel;
- migrations rehearsal;
- smoke/e2e/DAST;
- backup and restore drill;
- rollback rehearsal.

## 8.3. Production

Низкий и средний риск:

- automatic deployment;
- pre-deploy backup;
- migration check;
- canary/health check;
- automatic rollback threshold;
- post-deploy smoke;
- Telegram notification.

Высокий риск:

- отдельный VPS;
- special deployment policy;
- stronger review;
- explicit Product Contract pre-authorization;
- no real-money or irreversible action until domain-specific safety profile exists.

## 8.4. Reverse proxy

Caddy или эквивалент:

- automatic HTTPS;
- strict host allowlist;
- security headers;
- rate limiting where applicable;
- access logs without secrets;
- admin endpoints inaccessible publicly.

## 8.5. Backup

- restic encrypted repository;
- PostgreSQL logical dump + consistency verification;
- config/state backup;
- daily incremental;
- retention baseline: 7 daily, 4 weekly, 6 monthly;
- offsite required for stateful production;
- quarterly restore drill;
- restore evidence stored without data contents.

## 8.6. Monitoring

Minimum:

- `/health/live`;
- `/health/ready`;
- container/process uptime;
- HTTP error rate and latency;
- queue depth;
- DB connectivity/pool;
- disk/RAM;
- backup freshness;
- certificate expiry;
- deployment version/digest;
- provider health/quota state.

## 8.7. Automatic rollback

Rollback triggers:

- readiness fails beyond grace period;
- critical smoke test fails;
- error rate threshold breached;
- migration post-check fails;
- security monitor detects critical event.

Rollback action is allowlisted and tested before production.

## 8.8. Observation window

14 days:

- frequent smoke tests after deploy;
- incident creation;
- automatic bug repair within policy;
- daily compact status;
- optional improvements only backlog;
- successful close requires no open critical/high defect.
