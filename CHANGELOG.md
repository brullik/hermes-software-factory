# Changelog

## 2.1.8 - 2026-07-29

- Recovery work is always anchored to the product's current active plan, even
  when the causal task created that plan from a superseded parent revision.
- A routed recovery task stranded on an inactive plan is deterministically
  superseded by a fresh immutable task contract on the active revision.
- Liveness now counts only work belonging to the active plan. A stale READY
  row can no longer conceal an exhausted graph or prevent automatic recovery.

## 2.1.7 - 2026-07-29

- Successful recovery now resolves the complete causal failure ancestry,
  associated hypotheses, and controller incidents atomically. Migration v6
  reconciles historical chains already proven obsolete by accepted or
  superseded recovery work.
- `incident-result.status=recovered` is recognized as a successful
  Incident Recovery outcome instead of being misrouted as another semantic
  failure.
- Liveness checks no longer treat failed rows or an incident record without an
  active recovery task as proof of progress. An exhausted non-terminal graph
  records the controller incident and creates a real Replanner task for plan
  revision N+1.
- Backlog plans containing only planning/recovery roles are rejected before
  ingestion; every accepted plan must contain non-planning execution work.

## 2.1.6 - 2026-07-29

- Reused `BacklogPlan.plan_id` values are now compared against the immutable
  candidate digest before any child task-contract artifact can be written.
  Digest conflicts become an exact bounded validator diagnostic instead of a
  late controller or artifact-conflict incident.
- Failure Router task contracts and repair briefs now use deterministic
  artifact identities. A restart after artifact persistence but before task
  insertion can replay the same route without changing immutable evidence or
  creating a competing recovery path.

## 2.1.5 - 2026-07-29

- A restarted worker now detects a valid immutable result left by an
  interrupted `started` attempt and replays that evidence into the atomic
  outcome transaction instead of invoking the provider again.
- Legacy planning attempts that persisted a completed provider result before
  semantic graph validation are safely revalidated after restart. Invalid
  plans receive the exact bounded repair path without overwriting the original
  attempt artifact or opening a false artifact-conflict incident.

## 2.1.4 - 2026-07-29

- Concurrent service startup now rechecks each migration after acquiring the
  SQLite writer lock, preventing a stale pre-lock snapshot from inserting the
  same migration version twice.
- BacklogPlan semantic identities and edge endpoints are validated before
  outcome commit. Safe diagnostics include the exact validator coordinate and
  schedule a bounded repair instead of crashing the worker process.
- Unexpected atomic outcome-commit failures are persisted as controller
  failures with redacted diagnostics and no partial plan mutation.

## 2.1.3 - 2026-07-29

- Task claiming is serialized per product because each product owns one persistent,
  exclusively leased repository workspace. Independent products still run concurrently,
  regardless of matching repository-relative conflict keys.
- Migration v5 resolves the exact historical workspace-lease controller failures and
  incidents, supersedes their redundant recovery descendants, and requeues one earliest
  causal task per affected product.

## 2.1.2 - 2026-07-29

- A retryable failure with an already scheduled bounded in-place `repair` or
  `transient_retry` is now owned by that single retry path. Failure Router waits
  for its outcome instead of creating a competing child task for the same
  failure; success resolves the open envelope, while exhausted retries return
  to normal causal routing.

## 2.1.1 - 2026-07-29

- Conflict keys теперь изолированы `product_id`: одинаковые относительные пути в разных repositories не блокируют независимые workers, при этом конфликт внутри одного продукта по-прежнему сериализуется.
- Migration v4 распознаёт только точный URL-only legacy GitHub intake и восстанавливает `existing_repository`, canonical URL, repository name и отдельную безопасную root goal; произвольный текст и canonical v2 intake не анализируются regex-эвристикой.

## 2.1.0 - 2026-07-29

- Добавлен durable Product Execution Graph: versioned plans, multi-node DAG, dependency frontier, lineage, capabilities, failures, hypotheses и completion evidence мигрируют из 2.0.x без потери строк; перед первой миграцией создаётся backup SQLite.
- `TaskOutcome` атомарно фиксирует task/attempt result, failure, hypothesis, repair/replan successors, edges, product projection и outbox. Все семь fault-injection points, restart и idempotent replay покрыты release-blocking тестами.
- Intake разделяет root goal и repository metadata. New-product bootstrap создаёт собственный private repository и нейтральный initial commit; private GitHub credential остаётся внутри protected adapter.
- `repair_required` создаёт причинно связанную repair child, `needs_replan` — настоящий planning-only Replanner и plan revision N+1. После трёх попыток одной гипотезы Director обязан изменить диагноз, а не повторить прежний fix.
- Context Pack v2 и Failure/Repair/Transport diagnostics сохраняют точные безопасные координаты, fingerprints и bounded traceback без raw secrets. Устранён false positive, при котором `task-...` ошибочно принимался за OpenAI-style `sk-...`.
- OWNER_ACTION разрешён только для явной allowlist внешних причин. Missing adapter/model route, schema/artifact/migration failure и неизвестный blocker маршрутизируются как controller incidents.
- Completion reducer требует PASS evidence для root goals, mandatory nodes, independent review, required checks, exact staging/production digest, rollback readiness и observation; notification идемпотентна.
- Добавлены AUT-P0-001..022, AUT-P1-001..010 и anti-pattern acceptance tests, включая два полных E2E без участия владельца.

## 2.0.20 - 2026-07-29

- Context Pack теперь передаёт санитизированное содержимое выбранных файлов, а не только их хэши; исходный digest, digest санитизированного содержимого и безопасные координаты редактирования сохраняются отдельно.
- Independent Reviewer получает exact subject-bound candidate inventory/diff, read-only workspace binding, полные upstream Task Contracts и controller gate records, включая mandatory flag, subject SHA, command/artifact digests, timestamps и exit code.
- Прямой security-review dependency result также остаётся в independent-review context; отсутствие controller-owned evidence больше не маскируется под недостаток кода продукта.

## 2.0.19 - 2026-07-29

- Стандартный Builder contract разрешает изменять `pyproject.toml`, потому что обязательные controller-owned `target-dependency-audit` и `target-license-check` используют его как Python dependency/license contract.
- Устранён доказанный scope contradiction: Director больше не выдаёт исправление «создать `pyproject.toml`» внутри задачи, которая одновременно запрещает изменять этот файл.
- Repository PM task остаётся приоритетным источником scope: его frozen `allowed_paths` и `forbidden_paths` полностью заменяют стандартный Builder scope, поэтому расширение не ослабляет PM acceptance.

## 2.0.18 - 2026-07-29

- Transient provider retry больше не заменяет исходный repair brief технической причиной `network_timeout` или `malformed_transport`: blocker IDs, required fixes, definition of done и безопасные evidence refs исходной гипотезы переносятся в новый brief без потерь.
- Транспортная ошибка записывается как дополнительная диагностическая заметка без ложного требования менять код; Builder продолжает ту же доказанную гипотезу и получает новый prompt digest для разрешённого повтора.
- Документация recovery приведена в соответствие с per-hypothesis policy: три repair-cycles одной подписи, затем отдельный ограниченный `DIAGNOSIS-REASSESSMENT`, без глобального лимита на число разных доказанных проблем продукта.

## 2.0.17 - 2026-07-29

- Одна problem hypothesis получает до трёх полноценных repair-cycles даже при model floor Sol; число считается по blocker signature, а не по всему продукту.
- После трёх повторов той же подписи Director один раз переводит работу в отдельную `DIAGNOSIS-REASSESSMENT` hypothesis: Builder обязан доказать, ошибочны ли постановка, scope, controller gate/environment или исходный диагноз, и не может просто повторить прежний fix.
- Reassessment также ограничен тремя циклами и идемпотентной подписью; после его исчерпания Hermes остаётся fail-closed и отправляет точную русскую причину вместо бесконечного цикла.

## 2.0.16 - 2026-07-29

- Director больше не ограничивает весь продукт тремя разными root-cause replans: каждая новая доказанная подпись проблемы получает собственный bounded repair budget.
- Идемпотентность остаётся fail-closed: одна и та же подпись гипотезы открывается не более одного раза, поэтому изменение не создаёт бесконечный повтор прежнего диагноза.
- Product Director явно обязан отличать число решённых проблем от бюджета попыток текущей проблемы; новый blocker не наследует исчерпанные попытки старых blockers.

## 2.0.15 - 2026-07-28

- Provider-output sanitizer сохраняет полный JSON-ответ, но детерминированно заменяет credential-like значения на `[REDACTED]` до schema validation и записи evidence; безопасный аудит содержит точный JSON-путь и идентификатор правила, но не значение.
- Legacy-задача с непрозрачным `secret_exposure` получает ровно один повтор уровня Sol под новым sanitizer-протоколом и продолжает конвейер без OWNER_ACTION.
- Повтор старой гипотезы больше не нужен для ложноположительного секрета в ответе агента: контроллер устраняет транспортную проблему сам, а Builder продолжает работать с полным санитизированным результатом.

## 2.0.14 - 2026-07-28

- Director определяет исчерпанный бюджет по максимальному cycle всей истории проекта, а не по номеру последней handoff-задачи; новый blocker Test Engineer больше не теряется после более позднего Builder cycle.
- `needs_replan` теперь разбирается в actionable repair brief наравне с `repair_required`: finding IDs и required fixes сохраняются без обобщения.
- Legacy-механизм расширения числового лимита не перехватывает проект, который уже достиг текущего глобального предела; в этом случае управление получает root-cause replan.

## 2.0.13 - 2026-07-28

- Reconciler может безопасно продолжить проект с более раннего результата Builder, если все обязательные controller-owned проверки прошли, а `needs_replan` вызван только конфликтом внутреннего детектора с точной областью `allowed_paths`.
- Поздний неудачный Builder-цикл сохраняется в истории, доказанный результат становится зависимостью Test Engineer, а повторное восстановление остаётся идемпотентным.
- Builder явно получает правило не изобретать корневой manifest, Makefile или отдельный canonical-command detector вне разрешённых путей; штатная task-local acceptance command и controller-owned gates являются источниками истины.
- После трёх неудачных циклов Director закрывает прежнюю гипотезу: новый подтверждённый blocker получает отдельный actionable brief и новый ограниченный бюджет, тогда как повтор той же гипотезы не открывается снова. Ограничение относится к подписи проблемы, а не к числу разных проблем продукта.

## 2.0.12 - 2026-07-28

- Идемпотентность pre-provider handoff recovery привязана к точному `terminal_detail`: одинаковая ошибка не повторяется, а новая migration-ошибка после обновления получает одну автоматическую попытку.
- Legacy recovery-события без `terminal_detail` остаются идемпотентными для исходного `accepted result missing`, но не блокируют исправленный `deferred evidence invalid` handoff.

## 2.0.11 - 2026-07-28

- Deferred Builder handoff принимает обе исторически корректные формы outer evidence (`repair_required` и `blocked_external`), но только при прежних controller/event/schema/local-PM ограничениях.
- Reconciler автоматически возвращает Test Engineer в очередь после legacy evidence mismatch, если provider ещё не вызывался.

## 2.0.10 - 2026-07-28

- Test Engineer принимает controller-validated Builder result, если Builder был завершён локально и отложил только downstream GitHub gate; immutable provider evidence при этом не переписывается.
- Если старый worker успел остановить такой handoff до provider-вызова, reconciler идемпотентно возвращает Test Engineer в очередь без повторного Builder-вызова и без OWNER_ACTION.
- Production bootstrap запускает постоянный `hermes-worker-2`; release promotion перезапускает его, когда unit установлен, поэтому два product-scoped workspace могут обрабатываться параллельно.

## 2.0.9 - 2026-07-28

- После исчерпания model tiers Builder запускает следующий bounded product repair cycle вместо повторного FAILED_SAFE-loop.
- Controller-owned gate traceback попадает в `relevant_log_fragment` и `required_fixes`, поэтому Builder видит точную ошибку, а не только gate ID.
- Recovery каждого исчерпанного Builder cycle идемпотентен; повторное расширение того же policy budget также не создаёт цикл событий.
- Два проекта могут быть активны одновременно при двух workers; их planning/workspace/assurance locks остаются строго product-scoped.

## 2.0.8 - 2026-07-28

- Builder downstream-gate recovery читает mandatory/optional статус из controller-owned quality-gate catalog.
- Optional lint baseline не останавливает восстановление, но любой mandatory или неизвестный failed gate остаётся fail-closed.

## 2.0.7 - 2026-07-28

- Builder repair task активируется только с actionable brief: blocker IDs, точные required fixes, allowed paths и проверяемый DoD обязательны.
- Findings из reviewer- и attempt-схем нормализуются без потери `id/code`, описания и требуемого исправления.
- Локально завершённый Builder больше не блокируется на GitHub `pm-acceptance`: этот gate выполняется позже для immutable candidate.
- Reconciler автоматически восстанавливает ранее ошибочно остановленный Builder и продолжает с Test Engineer без нового repair cycle.
- Product Director обязан трассировать цели к требованиям, acceptance и evidence; Product Tester не может принять продукт без PASS/evidence по каждой critical journey.

## 2.0.4 - 2026-07-28

- Failed mandatory gate IDs сохраняются в task detail, repair brief и русском exhaustion-уведомлении.
- Legacy attempt evidence автоматически восстанавливает точные gate IDs при reconciliation.

## 2.0.3 - 2026-07-28

- Worker продлевает durable task lease во время длительного model/release execution.
- Потеря lease обнаруживается до terminal write, поэтому другой worker не получает параллельного исполнителя той же задачи.

## 2.0.2 - 2026-07-28

- Repair task остаётся недоступной worker до атомарного прикрепления validated repair brief.
- Отсутствующая legacy-диагностика нормализуется в непустую внутреннюю причину вместо остановки reconciler.

## 2.0.1 - 2026-07-28

- Добавлен постоянный reconciler: у каждого активного продукта автоматически восстанавливается следующая исполнимая задача.
- Внутренние ошибки и провал `pm-acceptance` теперь создают ограниченный repair cycle с новым diagnostic brief и эскалацией Terra -> Sol.
- После неуспешного candidate check фабрика закрывает неготовый PR, очищает candidate branch и продолжает исправление от актуального `main`.
- Watchdog считает активный продукт без очереди инцидентом и восстанавливает конвейер без команды владельца.
- `OWNER_ACTION` оставлен только для подтверждённых внешних блокировок; исчерпание внутренних repair cycles сообщает точную причину по-русски.
- Уведомления reconciler и OWNER_ACTION доставляются через durable Telegram outbox с повторной отправкой.

## 2.0.0 - 2026-07-26

- Переведён прототип маршрутизации одной задачи в долговечную автономную фабрику ПО.
- Добавлен полный конвейер: идея, Product Contract, архитектура, backlog, разработка, независимая приёмка, релиз, развёртывание, наблюдение и улучшения.
- Добавлена многоуровневая модельная эскалация D0/W0 -> Luna -> Terra -> Sol.
- Добавлены профили ролей, строгие JSON-контракты, policies-as-code, quality/security gates, quota circuit breaker и OWNER_ACTION.
- Зафиксированы решения владельца от 26 июля 2026 года.
- Устранено противоречие public/private: public по умолчанию только для безопасных проектов; чувствительные проекты принудительно private.
