# Telegram protocol

## Security

- direct messages only;
- exact owner user ID allowlist;
- pairing/setup available only on localhost;
- message id used for idempotency;
- attachments are scanned and treated as untrusted;
- bot token never appears in status/error.

## Intake

Обычный текст без команды может трактоваться как `/idea`, если нет active clarification. Бот возвращает `product_id` и краткую сводку.

## Notifications

Отправляются только milestone events:

- Product Contract ready;
- architecture/backlog ready;
- PR/release/deployment;
- quota delay;
- rollback/incident;
- OWNER_ACTION;
- completed.

Repeated low-level failures группируются.

## Runtime implementation

`factory.gateway` uses Telegram long polling through an injectable HTTP client.
It accepts private messages only, checks the configured numeric allowlist before
parsing text, persists the last update offset under the state directory, and
uses `telegram-update:<update_id>` as the intake idempotency key. A transport
failure backs off without advancing the offset, so an unacknowledged update is
replayed safely. The bot token is read from systemd `LoadCredential` or the
root-owned credential directory and is never put in logs, prompts, or reply
text. Intake applies a durable per-owner/source rate limit; idempotent retries
are admitted without consuming another rate-limit slot. Caller-provided
idempotency values are stored only as SHA-256 digests, and attachment metadata
is validated before a product row is created.

The gateway is intentionally not enabled by bootstrap while the credential is
absent. After the owner completes the secure credential action, the service
can be enabled with `systemctl enable --now hermes-factory-gateway.service`.

## Owner control

`pause` прекращает запуск новых attempts, но не прерывает атомарный deploy/rollback.
`cancel` создаёт safe cancellation plan: закрывает tasks, удаляет ephemeral worktrees и сохраняет evidence.
`resume` запускает reconciliation перед продолжением.
