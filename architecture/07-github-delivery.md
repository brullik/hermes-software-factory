# 7. GitHub delivery protocol

## 7.1. Repository bootstrap

Controller создаёт или нормализует:

- `main`;
- CODEOWNERS для policy files;
- issue/PR templates;
- labels;
- branch protection/ruleset;
- required status checks;
- environments `staging` и `production`;
- Dependabot/Renovate policy;
- release workflow;
- security policy;
- generated evidence directory.

## 7.2. Branching

- task branch: `factory/<product-id>/<task-id>-<slug>`;
- repair branch остаётся той же, attempt записывается metadata;
- один worktree на branch;
- main никогда не редактируется напрямую;
- интеграция только через PR;
- merge method: squash;
- reviewed head SHA должен совпадать с merging head SHA.

## 7.3. Pull request contract

PR body содержит:

- Product/Task IDs;
- objective;
- changed scope;
- risk tier;
- acceptance mapping;
- test/gate summary;
- security impact;
- migration/rollback;
- artifact/evidence digest;
- known limitations;
- generated-by metadata.

## 7.4. Review threads

- unresolved actionable thread блокирует merge;
- агент не закрывает thread без кода/evidence;
- stylistic suggestion может быть marked non-blocking с обоснованием;
- изменения после review автоматически аннулируют старое approval;
- Reviewer повторно проверяет новый SHA.

## 7.5. CI evidence

Каждый gate публикует machine-readable result:

```json
{
  "gate_id": "unit-tests",
  "status": "PASS",
  "command_digest": "...",
  "subject_sha": "...",
  "started_at": "...",
  "finished_at": "...",
  "artifact_digest": "..."
}
```

Failed workflow не может быть переименован или скрыт ради PASS. Non-required exploratory jobs явно помечаются context-only.

## 7.6. Merge

Controller выполняет squash-merge только если:

- branch protection satisfied;
- head SHA unchanged;
- mandatory gate graph PASS;
- independent review accepted;
- scope guard PASS;
- no unresolved blocking threads;
- no secret finding;
- release/deployment policy allows.

После merge task closes автоматически.
