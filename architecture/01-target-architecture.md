# 1. Целевая архитектура

## 1.1. Архитектурная позиция

Система строится не как чат нескольких агентов, а как **event-driven software delivery pipeline**. Состояние и права принадлежат детерминированному Controller, а модели являются временными исполнителями строго ограниченных контрактов.

```text
Telegram / GitHub / CLI
          |
          v
+-------------------------+
| Intake Gateway          |  allowlist, idempotency, rate limit
+-------------------------+
          |
          v
+---------------------------------------------------+
| Durable Controller                                 |
| state machine | policy engine | quota ledger       |
| scheduler     | evidence store | GitHub/deploy API |
+---------------------------------------------------+
     |               |                 |
     v               v                 v
Product lane     Build lanes       Assurance lane
Luna/Terra/Sol   max 2 worktrees   gates/review/test
     \               |                 /
      \--------------+----------------/
                     |
                     v
              Release Operator
             staging -> production
                     |
                     v
          Product Tester + Observation
```

## 1.2. Разделение control plane и execution plane

### Control plane

Работает постоянно:

- Intake Gateway;
- Durable Controller;
- Hermes Kanban/database;
- policy engine;
- quota/provider health ledger;
- scheduler;
- audit/event store;
- Telegram status bot;
- systemd watchdog.

Control plane не пишет продуктовый код и не имеет production secrets в модельном контексте.

### Execution plane

Создаётся по задаче:

- отдельный Git worktree;
- изолированный контейнер;
- минимальный набор секретов;
- role profile;
- ограничение CPU/RAM/time;
- ephemeral workspace;
- evidence output.

После завершения задачи временные credential mounts и контейнер удаляются.

## 1.3. Почему роли не должны быть постоянно активными

Постоянный разговор ролей расходует квоты и создаёт противоречивое состояние. Поэтому:

- Controller запускает роль только при входном контракте;
- роль возвращает один schema-valid artifact;
- история не передаётся целиком;
- следующая роль получает только Context Pack;
- макро-состояние хранится вне модели;
- subagent delegation разрешена только для независимых leaf-задач.

## 1.4. Физические компоненты на первом VPS

```text
/opt/hermes-factory/             immutable application code
/var/lib/hermes-factory/         controller DB, Kanban, evidence metadata
/var/lib/hermes-factory/repos/   bare mirrors
/var/lib/hermes-factory/worktrees/
/var/log/hermes-factory/         redacted structured logs
/etc/hermes-factory/             root-owned configuration
/etc/hermes-factory/credentials.d/ 0600 credentials
/var/backups/hermes-factory/     encrypted restic cache
```

Systemd units:

- `hermes-factory-controller.service`
- `hermes-factory-gateway.service`
- `hermes-factory-worker@.service`
- `hermes-factory-scheduler.timer`
- `hermes-factory-backup.timer`
- `hermes-factory-maintenance.timer`

## 1.5. Надёжность

- каждое событие имеет idempotency key;
- переход состояния выполняется транзакционно;
- lease задачи имеет срок и heartbeat;
- после crash задача возвращается в очередь;
- side effects записываются в outbox до выполнения;
- Git SHA, image digest и evidence digest неизменяемы;
- повторный запуск не создаёт второй PR/deployment;
- Controller никогда не считает текст модели доказательством прохождения gate.
