# Hermes Software Factory 2.1

Финальное техническое задание и machine-readable пакет для создания автономного конвейера разработки программ на базе Nous Research Hermes Agent.

## Цель

Владелец передаёт идею одной фразой через Telegram. Система без знания программирования со стороны владельца:

1. формирует Product Contract и безопасные допущения;
2. проектирует архитектуру;
3. разбивает работу на проверяемые задачи;
4. разрабатывает код в изолированных Git worktree;
5. запускает детерминированные проверки;
6. проводит независимую приёмку;
7. создаёт и сливает PR;
8. развёртывает staging и разрешённый production;
9. тестирует продукт как пользователь;
10. наблюдает 14 дней, исправляет дефекты и поддерживает продукт.

## Главный принцип экономии

LLM не используется там, где решение может принять код. Для смысловых задач действует лестница:

`D0/W0 -> Luna -> Terra -> Sol`

- **D0/W0**: правила, шаблоны, статический анализ, тесты, линтеры, сканеры, codemod.
- **Luna**: первая попытка простых и средних задач.
- **Terra**: эскалация после измеримого провала Luna либо стартовый уровень для более сложных задач.
- **Sol**: архитектурный арбитраж, высокий риск и повторный доказанный провал.

Одинаковая попытка не повторяется. Следующий запуск получает новую диагностическую информацию и repair brief.

## Автономность

После одноразового bootstrap и подключения учётных данных система не требует от владельца работы с кодом или GitHub. Обращение к владельцу допустимо только через структурированный `OWNER_ACTION` для 2FA/CAPTCHA, отсутствующего credential, покупки ресурса, юридического решения или необратимого production-действия.

Controller постоянно сверяет lifecycle с durable-очередью. Если у активного продукта нет
следующей задачи, watchdog фиксирует инцидент и reconciler восстанавливает её. Внутренняя
ошибка, упавшая проверка или `pm-acceptance` запускает ограниченный repair cycle с сохранённой
диагностикой и повышением уровня модели до Terra, затем Sol. После исправления все обязательные
проверки запускаются повторно. Владелец не используется как диспетчер внутренних сбоев.

Начиная с 2.1, источником истины служит durable Product Execution Graph. `Backlog Plan v2`
атомарно создаёт все задачи и зависимости, а worker атомарно фиксирует результат, failure,
repair/replan successors, frontier и outbox. Временный сбой продолжает ту же гипотезу после
bounded backoff; локальный дефект получает отдельную repair-задачу; архитектурное противоречие
запускает настоящий Replanner и новую ревизию плана. Проект становится `COMPLETED` только через
completion reducer после доказательств всех целей, mandatory nodes, checks, staging, production,
rollback readiness и observation.

Цель продукта и repository metadata принимаются раздельно. Для `new_repository` контроллер
создаёт собственный private repository и нейтральный bootstrap commit. Private credentials
остаются внутри deterministic adapters и никогда не передаются модели, Context Pack,
артефактам или Telegram.

## Как передать пакет агенту

Передайте агенту всю папку и текст файла `HANDOFF-PROMPT.md`. Агент обязан выполнять `IMPLEMENTATION-SPEC.md` по этапам, не задавать повторных проектных вопросов и подтвердить готовность только после прохождения `ACCEPTANCE-PLAN.md`.

## Авторитет документов

При конфликте действует следующий приоритет:

1. `policies/*.yaml`;
2. JSON Schema в `schemas/`;
3. `IMPLEMENTATION-SPEC.md`;
4. архитектурные документы;
5. ролевые промты;
6. примеры.

Любое отклонение оформляется ADR и не может ослаблять запреты безопасности.

## Состав

- `USER-DECISIONS.md` - зафиксированные решения владельца.
- `HANDOFF-PROMPT.md` - единственный стартовый промт исполнителю.
- `IMPLEMENTATION-SPEC.md` - детальное ТЗ.
- `ACCEPTANCE-PLAN.md` - обязательные критерии готовности.
- `architecture/` - целевая архитектура и протоколы.
- `policies/` - исполнимые политики.
- `prompts/` - промты ролей.
- `schemas/` - контракты артефактов.
- `config/` - примеры конфигурации Hermes, GitHub и systemd.
- `scripts/` - эталонные утилиты проверки политики.
- `tests/` - тесты самого пакета.
- `templates/` - стартовые артефакты.
- `docs/` - инструкции владельца и эксплуатации.
- `config/caddy/` - reverse-proxy/HTTPS configuration with no public controller route.
- `evidence/compatibility-report.json` - exact Hermes and host compatibility pins.
- `evidence/sbom.spdx.json` - deterministic SPDX 2.3 software bill of materials.

## Базовая совместимость

Пакет спроектирован для Ubuntu 24.04 LTS и текущего стабильного Hermes Agent. На дату фиксации базовой линии стабильный релиз Hermes Agent - v0.19.0 (20 июля 2026 года). Реализация обязана выполнить compatibility smoke test и закрепить точный tag/commit/digest, а не использовать плавающий `latest`.

## Локальный runtime baseline

В репозитории есть минимальный durable controller baseline в `factory/`: SQLite state store с lease/heartbeat, idempotent/rate-limited intake с redaction, immutable schema-validated evidence, localhost health/status endpoint и fail-closed gateway boundary.

Проверки выполняются без внешних credentials:

```bash
python3 -m factory validate-config
python3 -m factory preflight
python3 -m factory acceptance --full
python3 -m factory disaster-recovery-test
python3 -m pytest

# Local admin intake and lifecycle controls: create a private repository by default
python3 -m factory intake --owner-id owner --goal-text "Build a safe internal tool"

# Or attach an explicitly named existing repository
python3 -m factory intake --owner-id owner --goal-text "Finish the product" \
  --delivery-mode existing_repository \
  --repository-url "https://github.com/example/product"
python3 -m factory status
python3 scripts/verify_manifest.py
python3 scripts/secret_scan.py
python3 scripts/build_sbom.py --check
```

На VPS для ручных команд используйте установленный wrapper `factory`. Он
всегда подключает активный исходный релиз из `/opt/hermes-factory/current`,
поэтому CLI не запускается из устаревшей копии virtualenv после транзакционной
замены релиза:

```bash
factory intake --config /etc/hermes-factory/config.yaml --owner-id owner \
  --goal-text "Build a safe internal tool"
```

`acceptance --full` возвращает `BLOCKED_EXTERNAL`, пока не закрыты внешние
условия: benchmark-gated Hermes route, provider-backed pilot, полноценный pilot
PR и offsite backup. Для этой установки владелец явно включил single-owner
governance: независимый reviewer не имитируется, а owner override записывается
как отдельный режим с причиной. Production target настраивается вне публичного
репозитория; адрес production-хоста в публичных артефактах скрыт.
Подключённые VPS, GitHub governance, OAuth, Telegram credential/gateway и
локальный encrypted-backup probe и проверка Backblaze B2 фиксируются в
`evidence/external-acceptance.json`. Offsite backup подключён и подтверждён
Restic check/fresh backup; публичные артефакты не содержат bucket name или ключи.

## Durable Product Execution Graph

После intake Controller создаёт root context, подключает или создаёт repository, а Task
Specifier возвращает полный `backlog-plan-v2`. SQLite хранит plan revisions, все nodes,
dependency/supersession edges, lineage, capabilities, failures и hypothesis budgets.
Параллельные frontier nodes могут исполняться одновременно только при непересекающихся
`conflict_keys`. Старый role-derived pipeline сохранён исключительно как явно обозначенная
`legacy_v1` совместимость для мигрированных revision-0 продуктов.

Builder и Test Engineer получают immutable quality-gate list из controller policy. Gates выполняются без shell через allowlist, сохраняют `gate-evidence.schema.json`, а изменение файла вне `allowed_paths` немедленно переводит задачу в `FAILED_SAFE`.
