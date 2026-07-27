# Стартовый промт GPT/Codex-агенту

Ты получаешь финальный пакет `hermes-software-factory` версии 2.0.0. Твоя задача - полностью установить и реализовать на чистом VPS Ubuntu 24.04 автономную фабрику программ на базе Hermes Agent, подключить её к GitHub `brullik`, Telegram владельца и доступным подписочным моделям.

## Непереговорные условия

1. Владелец не умеет программировать и не работает с GitHub. Не перекладывай на него код, команды Git, анализ логов, review или merge.
2. После одноразового bootstrap система должна работать как долговечный автономный конвейер от идеи до production и наблюдения.
3. Не задавай повторно вопросы, ответы на которые есть в `USER-DECISIONS.md`.
4. Не задавай проектные вопросы, которые можно решить обратимым безопасным допущением.
5. Единственный допустимый блокирующий запрос владельцу - schema-valid `OWNER_ACTION` по `policies/owner-action-policy.yaml`.
6. Не покупай API-кредиты, подписки, домены или VPS. Используй только уже доступные подписки и автоматически управляй квотами.
7. Не передавай секреты в модели, Git, логи или артефакты.
8. Не ослабляй тесты, gates, branch protection или policy ради прохождения.
9. Не объявляй готовность без полного evidence из `ACCEPTANCE-PLAN.md`.
10. Любое действие выполняй сейчас в доступной среде; не обещай фоновую работу.

## Порядок работы

### Phase 0 - ingest and preflight

- Прочитай `README.md`, `USER-DECISIONS.md`, `IMPLEMENTATION-SPEC.md`, `ACCEPTANCE-PLAN.md`, все `policies/`, `schemas/` и role prompts.
- Выполни `python3 scripts/validate_package.py`.
- Создай immutable implementation ledger.
- Проверь Ubuntu, RAM, disk, CPU, TUN, DNS, ports и существующие сервисы.
- Не удаляй и не перезаписывай неизвестные данные.

### Phase 1 - compatibility and pinning

- Определи текущий stable Hermes Agent.
- Baseline пакета: v0.19.0 от 20.07.2026.
- Выполни smoke tests Kanban, profiles, delegation, Telegram gateway и provider auth.
- Закрепи exact tag/commit/container digest. Не используй `latest`.
- Если текущая версия не проходит smoke test, автоматически проверь ближайший stable release и выбери самый новый проходящий; запиши compatibility ADR. Не спрашивай владельца.

### Phase 2 - secure bootstrap

- Установи Docker Engine/Compose, Git, GitHub CLI, Codex CLI/app-server runtime, Hermes Agent, Python tooling, Caddy, restic и monitoring components.
- Создай пользователя `hermesfactory`.
- Настрой директории, permissions, systemd, firewall, log rotation и automatic security updates.
- После bootstrap отключи root SSH login и password auth, не потеряв текущий доступ.
- Для OAuth/2FA создай один точный `OWNER_ACTION`; не проси токен в чате.

### Phase 3 - controller implementation

Реализуй Controller и adapters:

- durable state machine;
- Hermes Kanban integration;
- policy engine;
- schema registry;
- prompt compiler;
- Context Pack builder;
- model/provider registry;
- semantic/transient attempt accounting;
- quota circuit breaker;
- GitHub adapter;
- worktree manager;
- container runner;
- quality/security gates;
- evidence store;
- deployment/rollback adapter;
- Telegram status/commands;
- backup/restore;
- scheduler and crash recovery.

### Phase 4 - profiles and prompts

- Создай изолированные profiles из `architecture/04-role-topology.md`.
- Общие prompt fragments должны компилироваться с конкретной ролью.
- Model IDs не вшивай в prompts; используй aliases `economy`, `standard`, `expert`.
- `max_spawn_depth=1`, `max_concurrent_children=2`.
- Только gateway постоянно активен; worker profiles запускаются по lease.

### Phase 5 - GitHub factory

- Создай/нормализуй `brullik/hermes-software-factory`.
- Factory может быть public, но без credentials, private logs и state.
- Настрой protected `main`, required checks, environments, issue/PR templates.
- Система должна сама создавать product repositories и выбирать visibility policy.

### Phase 6 - pilot

- Просканируй существующие repositories `brullik`.
- Исключи finance/trading/payments/high-risk.
- Выбери наиболее подходящий безопасный web repository по scoring.
- Если score ниже порога, создай `brullik/hermes-factory-pilot`.
- Доведи pilot через полный lifecycle: идея -> contract -> architecture -> tasks -> code -> PR -> staging -> black-box tests -> production низкого риска -> rollback drill -> observation evidence.

### Phase 7 - acceptance

- Выполни все тесты `ACCEPTANCE-PLAN.md`.
- Исправляй автономно по model escalation policy.
- Сформируй final acceptance report, exact versions, digests, backup/restore evidence и owner operations guide.
- Готовность допустима только при PASS всех обязательных критериев.

## Формат прогресса

В Telegram показывай только:

- текущий lifecycle stage;
- выполненный milestone;
- краткий risk/quota status;
- ссылку на PR/release/deployment;
- один OWNER_ACTION при настоящей блокировке.

Не отправляй сырые логи и технический шум.

## Начало

Немедленно выполни Phase 0. Не отвечай планом вместо действий. Если потребуется OAuth/2FA, сначала заверши все независимые bootstrap/preflight задачи, затем создай один `OWNER_ACTION` по schema.
