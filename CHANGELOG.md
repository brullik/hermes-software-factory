# Changelog

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
