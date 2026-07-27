# План приёмки Hermes Software Factory

## 1. Правило

Приёмка выполняется на реальном VPS и GitHub. Mock-тесты необходимы, но недостаточны. Каждый сценарий создаёт machine-readable evidence, привязанную к versions, policy digest и subject SHA.

Статусы: `PASS`, `FAIL`, `BLOCKED_EXTERNAL`, `NOT_APPLICABLE_POLICY`. Для mandatory сценария `N/A` запрещён.

## 2. Package acceptance

- [ ] Все JSON/YAML/Markdown читаются.
- [ ] Все schemas Draft 2020-12 валидны.
- [ ] Нет TODO/TBD/placeholder/`change-me`.
- [ ] Нет секретов.
- [ ] Role prompts содержат вход, алгоритм, запреты, escalation, output.
- [ ] Policy references разрешаются.
- [ ] SHA256 manifest совпадает.

## 3. Host/bootstrap

- [ ] Ubuntu 24.04 обнаружена.
- [ ] Существующие сервисы инвентаризированы до изменений.
- [ ] Docker/Compose работают.
- [ ] Непривилегированный `hermesfactory` работает.
- [ ] Постоянные services не работают root.
- [ ] SSH password auth выключен.
- [ ] Root login выключен после подтверждения доступа.
- [ ] Firewall default deny.
- [ ] Admin interface слушает только localhost/VPN.
- [ ] Restart VPS не теряет controller state.
- [ ] Disk/RAM limits предотвращают исчерпание VPS.

## 4. Hermes compatibility

- [ ] Exact Hermes tag/commit/digest закреплён.
- [ ] Profile isolation проверена.
- [ ] Kanban/task state сохраняется после restart.
- [ ] Delegation depth равна 1.
- [ ] Не более двух children.
- [ ] Child не получает parent transcript.
- [ ] Telegram gateway allowlist работает.
- [ ] Provider health/discovery работает.
- [ ] Known incompatible release автоматически отклоняется smoke test.

## 5. Authentication and secrets

- [ ] Codex/ChatGPT subscription auth работает без API key billing.
- [ ] GitHub auth имеет достаточный, но минимальный scope.
- [ ] Telegram token отсутствует в Git/logs/prompts.
- [ ] Secret files имеют корректные owner/mode.
- [ ] `env`, logs и crash dump не раскрывают secret.
- [ ] Test secret leak блокируется pre-commit/CI.
- [ ] Rotation runbook проверен на test credential.

## 6. Intake/autonomy

- [ ] Одна фраза в Telegram создаёт product.
- [ ] Повтор сообщения не создаёт duplicate.
- [ ] Product Contract формируется без ответа владельца.
- [ ] Необязательный вопрос не блокирует.
- [ ] `/status`, `/pause`, `/resume`, `/cancel` работают.
- [ ] Владелец не получает просьбу выполнить Git/code operation.
- [ ] Истинный blocker создаёт ровно один schema-valid OWNER_ACTION.
- [ ] Независимые задачи продолжаются.

## 7. Model escalation

### 7.1. Success at Luna

- [ ] Простая задача проходит Luna и не вызывает Terra/Sol.

### 7.2. Luna repair

- [ ] Первая failure создаёт repair brief с новой evidence.
- [ ] Prompt digest отличается.
- [ ] Вторая успешная Luna attempt завершает задачу.

### 7.3. Luna -> Terra

- [ ] Две semantic failures повышают tier.
- [ ] Terra получает compact history/evidence, не полный transcript.

### 7.4. Terra -> Sol

- [ ] Две Terra failures вызывают Sol.
- [ ] После одной Sol failure pipeline останавливает task safely.

### 7.5. Transient

- [ ] 429/network вызывает retry/fallback, но не tier escalation.
- [ ] Quota exhaustion переводит в DELAYED_QUOTA.
- [ ] Возобновление автоматическое после health probe.
- [ ] Платный API не используется.

## 8. Workspace and scope

- [ ] Две независимые задачи работают в разных worktree.
- [ ] Запись вне allowed paths блокируется.
- [ ] Изменение policy из product task блокируется.
- [ ] Same-file concurrent tasks сериализуются.
- [ ] Container очищается после task.
- [ ] Model не имеет Docker socket/gateway secrets.

## 9. Quality/security gates

- [ ] format/lint/typecheck/unit.
- [ ] integration/contract/e2e when applicable.
- [ ] changed-lines coverage >=80%.
- [ ] critical scenarios 100%.
- [ ] secret scan.
- [ ] dependency scan.
- [ ] SAST.
- [ ] license check.
- [ ] container scan.
- [ ] SBOM.
- [ ] accessibility.
- [ ] DAST baseline.
- [ ] migration up/down.
- [ ] install smoke.
- [ ] test weakening detected.
- [ ] full logs external, compact logs in context.
- [ ] evidence tied to subject SHA.

## 10. Independent review

- [ ] Builder cannot approve own PR.
- [ ] Reviewer is read-only.
- [ ] False PASS fixture is detected.
- [ ] New commit invalidates approval.
- [ ] Unresolved blocking thread blocks merge.
- [ ] High-risk uses required tier.

## 11. GitHub

- [ ] Repository created with correct visibility.
- [ ] Sensitive marker forces private.
- [ ] main protected.
- [ ] direct/force push blocked.
- [ ] PR template/evidence.
- [ ] required checks.
- [ ] reviewed SHA equals merge SHA.
- [ ] squash merge automatic.
- [ ] public fork does not receive secrets/self-hosted runner.
- [ ] release tag/changelog generated.

## 12. Deployment

- [ ] Same image digest staging -> production.
- [ ] HTTPS works.
- [ ] staging isolated.
- [ ] pre-deploy backup.
- [ ] health/smoke.
- [ ] simulated failure triggers rollback.
- [ ] rollback returns previous digest.
- [ ] stateful production blocked without offsite backup.
- [ ] high-risk production blocked on current VPS.

## 13. Backup/disaster recovery

- [ ] restic encrypted.
- [ ] scheduled backup.
- [ ] repository check.
- [ ] restore controller state to clean location.
- [ ] restore pilot DB.
- [ ] restore result consistency verified.
- [ ] secrets not included in evidence.
- [ ] controller resumes pending task after restore.

## 14. Pilot end-to-end

- [ ] Existing safe repo selected by documented score or neutral pilot created.
- [ ] Product Contract.
- [ ] Architecture/ADR/threat model.
- [ ] Backlog DAG.
- [ ] At least three independent tasks.
- [ ] At least one Luna success.
- [ ] At least one forced Luna -> Terra fixture.
- [ ] PR/review/merge.
- [ ] staging deploy.
- [ ] Playwright black-box scenarios.
- [ ] production low-risk deploy.
- [ ] rollback drill.
- [ ] user/admin docs.
- [ ] observation evidence.
- [ ] final product usable from browser/Telegram.

## 15. Resource acceptance on current VPS

- [ ] One product, max two workers.
- [ ] Under concurrency RAM does not swap-thrash/OOM.
- [ ] Disk cleanup works.
- [ ] Queue backpressure works.
- [ ] Deploy serialization works.
- [ ] Metrics/alerts indicate capacity threshold before failure.

## 16. Final owner acceptance

Владельцу предоставляется только:

- Telegram demonstration;
- URLs продукта;
- short owner guide;
- backup/restore status;
- exact versions;
- final PASS summary;
- list of any external resources not yet connected.

Владелец не обязан читать source code или GitHub checks для принятия технической готовности.
