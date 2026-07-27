# 4. Роли, profiles и права

## 4.1. Логические роли

1. Product Director
2. Product Analyst
3. Solution Architect
4. Task Specifier
5. Builder
6. Test Engineer
7. Independent Reviewer
8. Security Reviewer
9. Release Operator
10. Product Tester
11. Incident Recovery
12. Benchmark Evaluator
13. OWNER_ACTION Writer
14. Quota & Policy Controller - code only

## 4.2. Физические Hermes profiles

Чтобы не держать десятки процессов, роли объединены в lanes:

| Profile lane | Роли | Постоянный |
|---|---|---|
| `gateway-luna` | intake summary, notification | да |
| `planning-luna` | analyst/specifier low tier | нет |
| `planning-terra` | director/architect standard | нет |
| `planning-sol` | high-risk/arbitration | нет |
| `builder-luna` | simple build/test | нет |
| `builder-terra` | standard build/test | нет |
| `builder-sol` | complex repair only | нет |
| `assurance-luna` | low-risk review/test | нет |
| `assurance-terra` | independent/security review | нет |
| `assurance-sol` | high-risk arbitration | нет |
| `release-luna` | summaries and routine docs | нет |
| `release-terra` | incident-aware release | нет |
| `recovery-terra` | diagnosis and rollback | нет |
| `recovery-sol` | severe incident | нет |

Controller запускает не более двух worker profiles одновременно.

## 4.3. Separation of duties

- Builder не может принять собственную работу.
- Reviewer не может изменять код в том же attempt; он возвращает findings.
- Release Operator не может отменить mandatory gate.
- Product Tester работает по deployed artifact, а не по объяснению Builder.
- Security Reviewer не получает production secret values.
- Sol не получает расширенные системные права только из-за способности модели.
- Policy Controller не использует LLM.

## 4.4. Минимальные toolsets

### Planning

Read-only repository, search, artifact write. Нет deploy, secrets и merge.

### Builder

Один worktree, container terminal, test commands. Нет merge, main push, production.

### Assurance

Read-only diff/source, isolated test container, scanner outputs. Нет записи в branch.

### Release

GitHub PR/release, registry digest, deployment adapter. Нет произвольного редактирования кода.

### Recovery

Read observability, execute allowlisted rollback/restart/restore drills. Destructive actions запрещены policy.

## 4.5. Делегация

Hermes `delegate_task` применяется только когда родитель может дать полностью самодостаточный leaf contract. Настройки:

- `max_spawn_depth: 1`;
- `max_concurrent_children: 2`;
- orchestrator children disabled;
- child не получает историю родителя;
- child не имеет глобальных credentials;
- результат только по JSON Schema.

Долгие этапы и зависимости реализуются Kanban/Controller, а не вложенным деревом subagents.
