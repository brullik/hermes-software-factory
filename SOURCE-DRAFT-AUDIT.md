# Аудит исходного драфта и карта миграции

Исходный архив содержал 23 файла, четыре роли (`director`, `dispatcher`, `worker`, `reviewer`), базовый router, quality gate и шесть unit-тестов. Все исходные тесты были полезны как MVP, но проверяли только отдельную техническую задачу.

## Сохранённые идеи

- детерминированная маршрутизация до вызова LLM;
- плоская делегация;
- самодостаточный task packet;
- независимый reviewer;
- schema validation;
- allowlist quality commands;
- ограниченные repair-циклы.

## Заменённые части

| Исходный элемент | Новая реализация |
|---|---|
| Один Director | Product Director + условные Analyst/Architect |
| Dispatcher | Durable Controller + Task Specifier |
| Один Worker | Role lane с Luna/Terra/Sol escalation |
| Один Reviewer | Deterministic gates + Independent/Security/Product review |
| JSON-файл состояния | Hermes Kanban + controller database/event ledger |
| Маршрутизация по ключевым словам | Risk/domain/capability classifier с schema contracts |
| `allowed_paths` только в промте | worktree + policy guard + diff scope enforcement |
| Набор команд quality gate | полный gate graph и signed evidence |
| Завершение после patch | release, deploy, product acceptance, observation, rollback |
| Ручные подтверждения для обычных действий | policy-based autonomy; OWNER_ACTION только для настоящей блокировки |

## Почему исходный пакет не используется напрямую

Он не описывал bootstrap VPS, GitHub lifecycle, secrets, quota exhaustion, provider fallback, migration/backup/rollback, staging/production, эксплуатационное тестирование, release evidence и безопасное восстановление после перезапуска. Эти пробелы закрыты версией 2.0.
