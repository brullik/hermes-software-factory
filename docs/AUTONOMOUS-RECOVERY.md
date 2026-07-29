# Autonomous recovery v2

## Основной инвариант

Каждый активный, не приостановленный продукт обязан иметь bounded progress path в активной
ревизии Product Execution Graph. Наличие произвольной строки `PENDING` не является
доказательством прогресса. Reconciler проверяет READY frontier, dependency/capability blockers,
timers, leases, OPEN failures, controller incidents и completion conditions.

## Причинная маршрутизация

1. `FAILED_TRANSIENT` оставляет ту же task и hypothesis, записывает `available_at` и
   возобновляется после bounded backoff. Transient retry не расходует semantic budget.
   Пока bounded in-place `repair` или `transient_retry` находится в `WAITING_TIME`,
   `READY` или `CLAIMED`, Failure Router не создаёт конкурирующую child task для того же
   Failure Envelope. Успех закрывает failure как `RESOLVED`; исчерпание retry снова
   передаёт причину обычной causal routing.
2. Локальный implementation/test/review failure создаёт repair child того же plan node.
   Child наследует root goal, acceptance, exact allowed scope, `failure_id`, `hypothesis_id`,
   `parent_task_id` и `source_task_id`.
3. `needs_replan`, scope contradiction или невозможная architecture создают роль `replanner`
   с capability profile `planning_readonly`. Результат — полный `backlog-plan-v2` revision N+1
   с явными supersession edges; принятые незатронутые nodes переиспользуются по task identity
   и immutable result digest. Edge endpoints, task identities и глобальные idempotency keys
   проверяются до атомарного commit; ошибка получает точную безопасную JSON-координату и
   bounded repair, не завершая worker process.
4. Controller/schema/migration/artifact invariant failure создаёт controller incident. Модель
   продукта не должна гадать, как чинить контроллер.
5. Одна hypothesis имеет не более трёх semantic attempts. После исчерпания Director закрывает
   её как `EXHAUSTED` и создаёт новую diagnosis-reassessment hypothesis с другой signature
   или явным parent.

Outcome, attempt finalization, failure/hypothesis, successors, edges, frontier, product
projection и outbox фиксируются одной SQLite transaction через `commit_task_outcome`.
Идемпотентный replay возвращает существующий outcome; другой digest с тем же key блокируется.
Если сама граница commit неожиданно отклоняет prepared outcome, worker повторно фиксирует
только санитизированный controller failure без plan/successor side effects.

Все процессы применяют migrations под SQLite writer lock и перечитывают version/checksum
после его получения. Поэтому одновременный старт controller и двух workers не может дважды
записать одну migration version.

## Изоляция persistent workspace

Каждый продукт имеет один постоянный repository workspace с эксклюзивной lease. Поэтому
scheduler выдаёт не более одной `CLAIMED` task на продукт; следующая READY task этого же
продукта ожидает освобождения workspace. Задачи разных продуктов продолжают выполняться
параллельно, а одинаковые repository-relative `conflict_keys` между продуктами не конфликтуют.

## Безопасная диагностика

Failure Envelope хранит тип исключения, reason code, deterministic fingerprint, safe message,
expected/actual, failed gate IDs, bounded redacted traceback и stack fingerprint. Provider
Transport Diagnostic хранит только размер/digest raw ответа, санитизированные head/tail,
parser type и безопасные detector coordinates. Raw credential не записывается.

Полное значение потенциального секрета не передаётся агенту, потому что prompt, SQLite,
артефакты, logs и Telegram имеют более широкую поверхность доступа, чем protected adapter.
Для точного исправления достаточно detector ID, JSON path или line/column, failed gate,
expected/actual и bounded surrounding evidence после redaction.

## OWNER_ACTION boundary

`OWNER_ACTION` разрешён только для действующей allowlist: отсутствующий credential, OAuth
device flow, 2FA, CAPTCHA, создание внешнего account, покупка ресурса, DNS без доступа,
юридическое решение или неодобренное необратимое production-действие.

Missing adapter/model route, ошибка кода, теста, CI, Git, deployment script, schema, migration,
artifact conflict и неизвестное условие — внутренние incidents. Они не делегируются владельцу.
После появления разрешённого capability grant WAITING_EXTERNAL task автоматически возвращается
во frontier без нового intake.

## Completion

Продукт становится `COMPLETED` только через reducer, когда:

- все mandatory root goals имеют PASS evidence;
- все mandatory nodes активного plan ACCEPTED или корректно SUPERSEDED;
- нет OPEN/ROUTED failures и graph blockers;
- independent review и required checks прошли;
- staging и production ссылаются на один immutable digest;
- backup/rollback readiness и production transaction доказаны;
- observation task принята после заданного интервала.

Completion evidence immutable и notification создаётся логически один раз через outbox.

## Legacy compatibility

Revision-0 продукты 2.0.x мигрируют в system plan и обслуживаются явно названными
`legacy_v1` recovery API. Канонический v2 worker не вызывает role/title-derived successor,
`latest_task()` или старый `advance_after`.
