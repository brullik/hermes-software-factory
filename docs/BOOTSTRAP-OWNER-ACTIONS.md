# Одноразовые действия владельца при установке

Полная автономность начинается после подключения внешних аккаунтов. Эти действия невозможно безопасно выполнить от имени владельца.

## Возможные действия

1. Подтвердить Codex/ChatGPT OAuth device code.
2. Подтвердить Nous Portal OAuth.
3. Выполнить `gh auth login`/browser confirmation для основного GitHub аккаунта.
4. Создать Telegram bot через официальный интерфейс и безопасно поместить token на VPS, не отправляя его в чат.
5. Указать собственный Telegram user ID для allowlist.
6. При необходимости дать доступ к DNS.
7. Подключить offsite backup account перед первым stateful production.
8. При необходимости приобрести отдельный VPS/domain.

## Как система должна просить

- только одно действие в одном OWNER_ACTION;
- простая инструкция;
- без просьбы прислать секрет;
- автоматический probe после выполнения;
- independent work продолжается.

После подтверждения OAuth/2FA владелец не участвует в coding/GitHub/deploy lifecycle.

Для Telegram токен вводится только локально на VPS без аргументов shell и без
чата:

```bash
sudo /opt/hermes-factory/current/scripts/bootstrap/install-telegram-credential.sh
sudo /opt/hermes-factory/current/scripts/bootstrap/configure-telegram-owner.sh <numeric-user-id>
sudo systemctl enable --now hermes-factory-gateway.service
```

Команды выполняются после соответствующего OWNER_ACTION; сам токен не нужно
показывать или отправлять в Codex.
