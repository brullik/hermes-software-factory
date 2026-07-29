# Changelog

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
