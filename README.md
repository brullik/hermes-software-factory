# Hermes Software Factory 2.0

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

# Local admin intake and lifecycle controls
python3 -m factory intake --owner-id owner --idea "Build a safe internal tool"
python3 -m factory status
python3 scripts/verify_manifest.py
python3 scripts/secret_scan.py
python3 scripts/build_sbom.py --check
```

`acceptance --full` возвращает `BLOCKED_EXTERNAL`, пока не закрыты внешние
условия: независимое approval и squash-merge PR, benchmark-gated Hermes route
и provider-backed pilot, полноценный pilot PR/Telegram/rollback black-box, а
также offsite backup. Подключённые VPS, GitHub governance, OAuth, Telegram
credential/gateway и локальный encrypted-backup probe фиксируются в
`evidence/external-acceptance.json`. Это ожидаемый безопасный статус, а не
успешная production-приёмка.

## Durable role pipeline

После intake Controller создаёт schema-validated task contract с durable role metadata. Provider-backed worker выполняет роли последовательно: Product Director, Product Analyst, Solution Architect, Task Specifier, параллельные Builder/Test Engineer/Security Reviewer, Independent Reviewer, Staging Release, Product Tester и Production Release. Каждая следующая задача появляется только после принятого результата предыдущей, а SQLite lease проверяет зависимости и конфликтные worktree.

Builder и Test Engineer получают immutable quality-gate list из controller policy. Gates выполняются без shell через allowlist, сохраняют `gate-evidence.schema.json`, а изменение файла вне `allowed_paths` немедленно переводит задачу в `FAILED_SAFE`.
