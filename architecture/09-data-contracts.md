# 9. Контракты, provenance и evidence

## 9.1. Все переходы schema-first

Роль не передаёт свободный текст как основной результат. Она пишет JSON, проверяемый schema. Человеческая сводка является дополнительным полем.

## 9.2. Artifact envelope

Каждый artifact содержит:

- `schema_version`;
- `artifact_id`;
- `product_id`;
- `task_id` при наличии;
- `created_at`;
- `producer.role`;
- `producer.tier`;
- `subject_sha`;
- `policy_digest`;
- `inputs[]` с digests;
- содержательную payload;
- `assumptions`;
- `open_findings`.

## 9.3. Provenance

Controller вычисляет SHA-256 для:

- prompt bundle;
- policy bundle;
- task contract;
- repository commit;
- tool configuration;
- logs;
- evidence;
- output artifact.

Любое изменение invalidates downstream approval по dependency graph.

## 9.4. Evidence hierarchy

1. deterministic command result;
2. signed/attested CI result;
3. runtime telemetry;
4. independent model review;
5. Builder statement.

Низший уровень не может отменить более высокий.

## 9.5. Retention

- Git history and release manifests: бессрочно;
- audit/event metrics: 90 дней;
- full agent transcripts: 14 дней;
- compact attempt summaries: 90 дней;
- raw logs: по product policy, default 30 дней;
- backups: по retention policy;
- secrets: никогда в evidence.
