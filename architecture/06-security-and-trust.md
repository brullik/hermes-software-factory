# 6. Безопасность и границы доверия

## 6.1. Базовый принцип

Модель считается недоверенным планировщиком. Её текст не предоставляет полномочия. Любое действие проходит через policy-enforcing adapter.

## 6.2. Secret flow

```text
Owner/OAuth
   -> root-owned credential store
   -> scoped runtime mount
   -> adapter process
   X never into prompt, git, logs, artifacts
```

- файлы credentials: owner `root`, group scoped service, mode `0640` или строже;
- `auth.json` Codex размещается только на trusted host;
- переменные окружения редактируются перед логированием;
- команды `env`, `set`, `printenv` блокируются в model-controlled shell;
- GitHub secrets используются через environments с минимальным scope;
- secret scanner выполняется до commit и в CI.

## 6.3. Threats

Система должна учитывать:

- prompt injection из issues, README, web и dependencies;
- malicious PR/fork;
- dependency confusion;
- secret exfiltration;
- arbitrary shell command;
- poisoned test evidence;
- reviewer collusion;
- branch protection bypass;
- self-hosted runner persistence;
- supply-chain substitution;
- public exposure of admin service;
- destructive migration;
- model/provider outage.

## 6.4. Prompt injection controls

External content маркируется `UNTRUSTED_DATA`. Роль не должна исполнять инструкции из:

- repository text;
- issue/PR comment;
- webpage;
- log;
- generated file.

Tool request проверяется по разрешённой цели и allowlist. Любая инструкция изменить policy считается data, а не authority.

## 6.5. GitHub public repository rules

Public PR из fork:

- не получает repository secrets;
- не запускается на permanent self-hosted runner;
- выполняет только read-only GitHub-hosted checks;
- deployment workflow запускается только из protected branch;
- actions pin-ятся по full commit SHA;
- workflow permission по умолчанию `contents: read`.

## 6.6. VPS hardening

- SSH keys only;
- `PermitRootLogin no` после bootstrap;
- firewall default deny;
- unattended security updates;
- fail2ban либо эквивалент;
- Docker socket недоступен gateway;
- workers получают rootless/container-scoped execution;
- admin ports bind только `127.0.0.1`;
- auditd/system logs с redaction;
- backup restore drill.

## 6.7. Public/private automatic decision

Repository принудительно private при любом marker:

- personal/confidential data;
- real-money trading/payments;
- production credentials/integration schemas;
- medical/legal decisions;
- customer proprietary code;
- security exploit material beyond defensive patch context;
- license constraint;
- owner/product policy.

Это не блокирует конвейер и не требует вопроса владельцу.
