# Техническое задание на реализацию Hermes Software Factory

Версия: 2.0.0
Целевая ОС: Ubuntu 24.04 LTS
Владелец GitHub: `brullik`
Control repository: `brullik/hermes-software-factory`

## 1. Назначение

Создать автономную систему ИИ-агентов, которая получает пользовательскую идею и без навыков программирования со стороны владельца производит безопасный, протестированный, документированный и развёрнутый программный продукт.

Система является конвейером с долговечным состоянием. Она не зависит от одной chat session, переживает рестарт VPS, лимиты провайдера, падение worker и незавершённый PR.

## 2. Обязательные внешние компоненты

Реализатор обязан проверить и установить совместимые версии:

- Ubuntu packages;
- Docker Engine + Compose plugin;
- Git;
- GitHub CLI;
- Codex CLI/app-server или поддержанный Hermes Codex provider;
- Hermes Agent;
- Python 3.12+ environment;
- Caddy;
- PostgreSQL для controller state при необходимости либо SQLite с доказанной single-node надёжностью;
- restic;
- security scanners;
- Playwright/browser runtime;
- observability stack, соразмерный VPS.

Versions закрепляются exact tag/digest в `evidence/compatibility-report.json`.

## 3. Нефункциональные требования

### 3.1. Автономность

- После credentials bootstrap владелец не выполняет Git/code/deploy operations.
- Необязательный вопрос не останавливает pipeline.
- OWNER_ACTION создаётся только по строгой policy.
- Независимые задачи продолжают выполняться при blocker.

### 3.2. Экономичность

- Детерминированная обработка до LLM.
- Минимальный Context Pack.
- Model tier escalation только по evidence.
- Нет identical retry.
- Максимум два параллельных workers.
- Нет платного API fallback.
- Состояние сохраняется при quota delay.

### 3.3. Безопасность

- Least privilege.
- Secret isolation.
- Public fork isolation.
- Protected branches.
- Immutable evidence.
- Staging before production.
- Backup/restore/rollback.
- Prompt injection defense.

### 3.4. Надёжность

- Idempotency для intake, PR, merge, release и deploy.
- Lease + heartbeat.
- Crash recovery.
- Circuit breakers.
- Reconciliation with GitHub and deployment state.
- Transactional outbox для side effects.

## 4. Модули Controller

Реализация может использовать Python/FastAPI или другой ADR-обоснованный stack, но должна иметь следующие интерфейсы.

### 4.1. Intake service

Входы:

- Telegram message;
- GitHub issue with trusted label;
- local admin CLI.

Выход: `idea-intake.schema.json`.

Функции:

- allowlist;
- rate limit;
- idempotency;
- secret redaction;
- correlation IDs;
- attachment metadata;
- status response.

### 4.2. Workflow engine

Функции:

- lifecycle state machine;
- task DAG;
- dependency resolution;
- priority;
- leases;
- retry/escalation;
- delay/resume;
- event log;
- reconciliation;
- cancellation;
- pause/resume.

Каждый transition должен иметь preconditions и postconditions.

### 4.3. Policy engine

- загружает versioned YAML;
- валидирует schema;
- вычисляет bundle digest;
- запрещает runtime override из project branch;
- возвращает allow/deny/requires-owner-action;
- пишет audit record;
- имеет unit/property tests.

### 4.4. Artifact/schema registry

- валидирует все role outputs;
- сохраняет immutable artifact;
- вычисляет digest;
- ведёт provenance links;
- отклоняет unknown schema version;
- поддерживает migration только отдельным version bump.

### 4.5. Prompt compiler

Вход:

- common system fragment;
- role prompt;
- policy summary;
- task/context pack;
- output schema.

Выход:

- deterministic prompt bundle;
- digest;
- token/size estimate;
- redaction report.

### 4.6. Context builder

- repository map by SHA;
- import/symbol references;
- relevant tests;
- applicable ADR;
- compact failing logs;
- file count/token budget;
- provenance;
- no secret content.

### 4.7. Model/provider registry

- aliases `economy`, `standard`, `expert`;
- live discovery;
- auth health;
- quota status;
- provider capability;
- benchmark eligibility;
- same-tier fallback;
- no paid API fallback;
- no model hardcoding in role prompts.

### 4.8. Attempt manager

Различает:

- semantic attempt;
- transient retry;
- repair attempt;
- tier escalation;
- provider fallback.

Хранит reason codes и запрещает identical prompt digest.

### 4.9. Workspace manager

- bare mirror/cache;
- branch/worktree;
- one task lease per worktree;
- path scope;
- container isolation;
- cleanup;
- disk quota;
- conflict prevention.

### 4.10. Tool/policy adapter

Model requests не исполняются напрямую. Adapter:

- нормализует command;
- проверяет allowlist;
- запрещает dangerous shell;
- устанавливает cwd/time/resource limits;
- маскирует secrets;
- сохраняет полный log вне context;
- возвращает compact structured result.

### 4.11. Quality gate engine

- строит gate DAG по project type;
- запускает commands;
- нормализует exit/result;
- связывает с subject SHA;
- сохраняет evidence;
- не позволяет task branch менять mandatory gate;
- сравнивает coverage;
- поддерживает N/A только с policy reason.

### 4.12. GitHub adapter

- repository create/configure;
- branch/worktree;
- issue/label/project;
- PR create/update;
- review thread retrieval;
- check status;
- ruleset verification;
- squash merge;
- release/tag;
- immutable SHA check.

### 4.13. Deployment adapter

- compose/image digest deploy;
- Caddy config;
- staging/production environments;
- pre/post checks;
- migration;
- backup;
- rollback;
- audit.

### 4.14. Telegram gateway

Команды владельца:

- `/idea <text>`;
- `/status`;
- `/projects`;
- `/pause <product>`;
- `/resume <product>`;
- `/cancel <product>`;
- `/owner_action`;
- `/help`.

Команды не принимают raw secrets. Sensitive credential flow использует локальный secure path/OAuth device flow.

### 4.15. Backup/restore

- restic;
- encrypted;
- offsite policy;
- pre-deploy snapshot;
- retention;
- check;
- restore drill;
- evidence.

### 4.16. Benchmark service

- закрытый task set;
- provider/model alias;
- pass/gate/repair/false-pass metrics;
- route recommendation;
- policy PR;
- no automatic unreviewed route mutation.

## 5. Profiles

Создать profiles из `config/hermes-profiles/`. Каждый profile:

- имеет role identity;
- имеет model alias;
- имеет минимальный toolset;
- имеет separate session/state;
- не содержит secret values;
- выдаёт только schema output;
- останавливается после artifact;
- не управляет lifecycle напрямую.

## 6. Model escalation

Точный алгоритм находится в `architecture/03-model-escalation.md` и `policies/model-routing-policy.yaml`.

Обязательные свойства:

- Luna получает реальную возможность выполнить задачу там, где risk floor позволяет.
- После первой неудачи Luna получает targeted repair.
- После второй semantic failure задача передаётся Terra.
- Terra имеет две evidence-informed attempts.
- Sol используется один раз как эксперт/арбитр.
- 429/network не повышают tier.
- Scope/policy violation может немедленно повысить tier и создать security finding.
- После Sol failure задача `FAILED_SAFE`; новый бесконечный цикл запрещён.

## 7. Product templates v1

Система обязана поддерживать:

- FastAPI + PostgreSQL;
- React/Next.js + TypeScript;
- Telegram bot;
- CLI;
- data automation;
- LLM application;
- Docker Compose;
- GitHub Actions;
- Caddy HTTPS;
- monitoring/health;
- backup/rollback.

Шаблон является стартом, а не жёстким ограничением. Architect может выбрать другое через ADR.

## 8. GitHub governance

- `main` protected;
- no direct/force push;
- least Actions permissions;
- SHA-pinned actions;
- required checks;
- fork isolation;
- immutable reviewed SHA;
- squash merge;
- generated PR evidence;
- public/private visibility enforcement.

## 9. Deployment governance

- staging mandatory;
- low/medium production automatic after gates;
- high-risk separate policy and VPS;
- same image digest promotion;
- health/rollback;
- offsite backup for stateful production;
- no public Hermes admin.

## 10. Pilot selection

Scoring existing repositories:

| Критерий | Баллы |
|---|---:|
| React/Next frontend | 2 |
| REST API | 2 |
| PostgreSQL | 2 |
| Telegram integration | 1 |
| Authentication | 1 |
| Tests | 2 |
| Docker | 1 |
| CI | 1 |
| Monitoring | 1 |
| Rollback/deployment | 1 |

Minimum score: 10.

Exclusions: Bybit/trading/finance/payments, secrets, customer confidential data, destructive production integration, active security exploit tooling.

Если нет кандидата, создать neutral pilot.

## 11. Installation workflow

### Stage A - read-only preflight

- inventory host;
- backup current config;
- ports/services/users/storage;
- network;
- compatibility;
- no destructive change.

### Stage B - bootstrap

- system packages;
- Docker;
- service user;
- directories;
- source checkout;
- pinned dependencies;
- firewall/system hardening;
- systemd.

### Stage C - credentials

- GitHub/Codex/Telegram/provider auth;
- one OWNER_ACTION at a time;
- secret store;
- no chat secret.

### Stage D - smoke

- Hermes CLI;
- provider model call;
- profile isolation;
- Kanban persistence;
- delegation depth;
- Telegram allowlist;
- GitHub read/write;
- worktree/container;
- crash/restart.

### Stage E - factory implementation

- modules, profiles, policies, gates, tests.

### Stage F - pilot and acceptance

- end-to-end.

## 12. Deliverables in repository

- source;
- lockfiles;
- migrations;
- systemd units;
- Docker/Compose;
- Caddy config;
- CI workflows;
- tests;
- threat model;
- SBOM;
- install script;
- operations/runbook;
- disaster recovery;
- owner guide;
- exact version/digests;
- acceptance report.

## 13. Prohibited shortcuts

- cron-only state machine without durable task state;
- relying on chat transcript as database;
- one super-agent with all credentials;
- reviewer equals builder;
- unbounded retries;
- silent paid API use;
- model-generated shell without adapter;
- `latest` container tags;
- public admin dashboard;
- test weakening;
- storing tokens in repository;
- production without restore/rollback evidence.

## 14. Completion declaration

Implementation is complete only when:

```text
python -m pytest
factory validate-config
factory preflight
factory acceptance --full
factory disaster-recovery-test
factory pilot-report
```

all mandatory operations return success and `evidence/final-acceptance.json` validates against its schema or an implementation-equivalent documented schema.
