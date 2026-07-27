# 2. Жизненный цикл продукта

## 2.1. Основные состояния

```text
IDEA_RECEIVED
  -> CONTRACT_DRAFTED
  -> CONTRACT_VALIDATED
  -> RISK_CLASSIFIED
  -> ARCHITECTED
  -> BACKLOG_READY
  -> IMPLEMENTING
  -> INTEGRATING
  -> STAGING_DEPLOYED
  -> PRODUCT_ACCEPTANCE
  -> RELEASE_READY
  -> PRODUCTION_DEPLOYED
  -> OBSERVATION
  -> COMPLETED
```

Боковые состояния:

- `REPAIRING`
- `DELAYED_QUOTA`
- `BLOCKED_OWNER`
- `FAILED_SAFE`
- `ROLLING_BACK`
- `ROLLED_BACK`
- `CANCELLED`

## 2.2. Этап 0 - intake

Вход может состоять из одной фразы. Gateway:

1. проверяет allowlist Telegram user ID;
2. создаёт immutable `idea-intake.json`;
3. присваивает `product_id`, `correlation_id`, `idempotency_key`;
4. удаляет очевидные секреты из текста и сохраняет redaction event;
5. публикует задачу Product Director.

Повторное сообщение с тем же idempotency key не создаёт второй продукт.

## 2.3. Этап 1 - Product Contract

Product Director:

- формулирует проблему и ожидаемый результат;
- создаёт personas и пользовательские сценарии;
- фиксирует scope/out-of-scope;
- определяет критерии приёмки;
- перечисляет допущения;
- помечает решения как reversible/irreversible;
- определяет data classification и risk markers.

Уточняющий вопрос может быть отправлен как необязательное уведомление. Через заданный grace period Director продолжает с безопасным допущением. Только истинная внешняя блокировка создаёт `OWNER_ACTION`.

## 2.4. Этап 2 - риск и архитектура

Risk Engine сначала применяет deterministic rules. Затем архитектурная роль создаёт:

- component model;
- data flow;
- trust boundaries;
- API contracts;
- ADR;
- deployment topology;
- backup/restore и rollback plan;
- observability plan;
- test strategy;
- threat model для среднего/высокого риска.

## 2.5. Этап 3 - backlog

Task Specifier формирует DAG задач. Каждая задача должна:

- иметь один проверяемый результат;
- перечислять allowed paths;
- иметь preconditions;
- иметь deterministic acceptance commands;
- иметь risk tier и model floor;
- не требовать истории чата;
- иметь зависимости;
- иметь rollback/revert strategy;
- укладываться в один PR или явно быть epic.

## 2.6. Этап 4 - разработка

Для ready-задачи Controller:

1. создаёт branch и worktree;
2. собирает Context Pack;
3. запускает D0/W0 route;
4. при необходимости запускает модель начального tier;
5. применяет scope guard;
6. запускает gates;
7. при провале создаёт repair brief;
8. повторяет в пределах policy;
9. передаёт независимому Reviewer.

## 2.7. Этап 5 - интеграция и release

После accepted tasks:

- integration branch/PR создаётся из immutable commits;
- полный CI выполняется на GitHub-hosted runner;
- self-hosted runner допускается только для закрытых интеграций;
- release candidate фиксируется tag/digest;
- staging deploy использует тот же image digest, который пойдёт в production;
- Product Tester выполняет black-box scenarios;
- release manifest подписывает доказательства.

## 2.8. Этап 6 - production и наблюдение

- низкий/средний риск развёртывается автоматически;
- высокий риск выполняет специальную policy;
- health check failure инициирует автоматический rollback;
- observation window - 14 дней;
- дефекты автоматически превращаются в repair tasks;
- необязательные функции попадают в backlog;
- после успешного окна продукт переходит в `COMPLETED`.

## 2.9. Условия завершения

Текст «готово» от агента не завершает продукт. Нужны:

- schema-valid release manifest;
- все mandatory gates PASS;
- accepted independent review;
- staging black-box acceptance;
- production health evidence либо policy-approved staging-only outcome;
- restore/rollback evidence;
- документация;
- отсутствие open critical/high defects.
