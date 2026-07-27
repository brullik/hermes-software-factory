# Подписки, providers и квоты

## OpenAI/Codex

Codex поддерживает вход через ChatGPT subscription и отдельно через API key. Для этой фабрики используется ChatGPT-managed OAuth/device-code access. Платный API key fallback запрещён policy.

## Nous Portal

Используется только существующая подписка/доступ. Bootstrap выполняет OAuth и model discovery, затем регистрирует доступные модели в aliases.

## Kimi и DeepSeek

Наличие пользовательской подписки не считается доказательством программного доступа. Bootstrap обязан выполнить supported Hermes auth и live probe:

- если доступ работает в рамках текущей подписки/учётной записи, provider допускается;
- если требуется новый pay-as-you-go API balance, provider остаётся disabled;
- это не блокирует остальную систему.

## Model aliases

Role prompts используют:

- `economy`;
- `standard`;
- `expert`.

Фактические model IDs записываются в runtime registry и могут меняться только после benchmark и versioned policy PR.

## Quota behavior

Поскольку денежный API-бюджет не используется, Controller ведёт quota ledger. 429/rate limit не означает, что модель «не справилась». Задача checkpoint-ится, может перейти к другому provider того же tier или в `DELAYED_QUOTA`, а затем автоматически продолжиться.
