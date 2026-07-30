# Changelog

## 2.2.24 - 2026-07-31

- Give tool-enabled coding agents a configurable 30-minute bounded execution
  window while retaining a separate 15-minute planning limit, so image builds
  and black-box Compose tests are not misclassified before they can finish.
- Validate both runtime limits fail-closed and cap coding execution at one hour,
  preserving bounded autonomous recovery even on a slow production VPS.
- Classify the subprocess boundary precisely as `agent_execution_timeout`
  without retaining provider output, while preserving same-tier transient retry
  accounting and the three-attempt diagnosis-change rule.

## 2.2.23 - 2026-07-31

- Route actionable semantic findings from read-only reviewers, and failed
  mandatory gates from any non-Builder lifecycle role, to a Director replan
  where a fresh Builder slice must resolve the exact safe coordinate instead of
  accepting a prose-only same-role replacement.
- Require fresh replan slices to name reviewer blocker IDs as well as mandatory
  gate IDs from the bounded causal chain, so actionable coordinates cannot be
  dropped between Director and Builder.
- Preserve controller-owned quality gate IDs on exact executable repairs so an
  accepted replacement must rerun the inherited deterministic checks.
- Reject legacy read-only reviewer repairs and malformed mandatory-gate repair
  contracts before provider execution, forcing a Director replan or exact gate
  inheritance instead of repeating an incapable role.

## 2.2.22 - 2026-07-30

- Bound dependency and typed-review evidence by aggregate Context Pack budgets
  while preserving every predecessor identity, artifact reference, mandatory gate
  result, and safe diagnostic coordinate.
- Fairly compact verbose plan and evidence strings without dropping structural
  entries, so repaired plans cannot grow provider prompts without bound.
- Preflight compiled prompts against a conservative controller ceiling and
  deterministically rebuild a smaller immutable Context Pack before provider
  transport when additional compaction is required.

## 2.2.21 - 2026-07-30

- Reject replan deltas that merely reuse accepted implementation nodes without
  scheduling a fresh or materially changed executable slice.
- Require fresh replan slices to name every failed mandatory quality gate found
  in the bounded causal FailureEnvelope chain.
- Bind the proposal to its controller-issued source failure so a model cannot
  substitute unrelated evidence or activate a plan that omits the proven blocker.
- Teach Replanner to carry each safe required-fix coordinate into the bounded
  scope and exact gate ID into fresh executable acceptance.

## 2.2.20 - 2026-07-30

- Prove a historical repair branch belongs to the superseded task through its
  bounded parent FailureEnvelope ancestry, not only the terminal failure row.
- Reconcile transient failures raised by a repair itself only when their same-product
  ancestry reaches the original task and every replacement identity still matches.
- Preserve fail-closed behavior for missing, cyclic, cross-product, overlong, or
  otherwise unproven failure ancestry.

## 2.2.19 - 2026-07-30

- Resolve every sibling FailureEnvelope for a superseded task when one repair
  replacement is accepted, and suppress redundant pending repair work atomically.
- Add migration 16 to reconcile only proven historical duplicate accepted repair
  branches while preserving immutable result evidence and recording an audit event.
- Keep genuinely ambiguous or identity-conflicting replacement branches fail-closed;
  no resolver chooses between unproven competing results.

## 2.2.18 - 2026-07-30

- Preserve the active Replanner source failure and its bounded causal ancestors,
  including already resolved parents that retain authoritative gate diagnostics.
- Mark each supplied chain seed and causal depth so the Replanner can distinguish
  the terminal symptom from the safe root-cause coordinates and required fixes.
- Keep unrelated resolved history out of the prompt while retaining other active
  failure chains within the existing bounded context budget.

## 2.2.17 - 2026-07-30

- Preserve controller-owned mandatory gate summaries, statuses, exit codes,
  and immutable evidence references in the causal FailureEnvelope.
- Give Replanner and Builder the exact safe remediation coordinate instead of
  reducing deterministic failures to gate IDs and forcing blind hypotheses.
- Redact any secret-like values from gate summaries while retaining detector
  and location coordinates that are sufficient for autonomous repair.

## 2.2.16 - 2026-07-30

- Replace unbounded release maintenance with durable deploy leases, bounded
  TTLs, heartbeat renewal, fencing IDs, and drain-aware automatic recovery.
- Reconcile the exact historical prompt-boundary hotfix hold at startup while
  leaving every unrelated legacy or manual hold fail-closed.
- Prevent expired task leases, late heartbeats, and stale operators from
  stranding or taking over maintenance across controller and worker processes.
- Close stale active hypotheses whose causal failures are already resolved and
  expose maintenance mode, expiry, and recovery counters to operators.

## 2.2.15 - 2026-07-30

- Carry compiled Hermes prompts through a bounded UTF-8 stdin channel instead
  of the `--oneshot` argv value, avoiding Linux's per-argument size ceiling
  and keeping product context out of process listings.
- Preserve the pinned Hermes one-shot startup, model, provider, toolset,
  ignore-rules, usage-accounting, cleanup, and exit semantics through a small
  fail-closed launcher.
- Validate the stdin byte bound, encoding, and empty-input contract before
  importing the provider runtime.

## 2.2.14 - 2026-07-30

- Separate the provider prompt-input budget from the output-capture budget so
  bounded 100,000-character Context Packs plus their contracts and schemas can
  reach Hermes without a false pre-execution failure.
- Classify an actual prompt-input overflow as a controller fault with safe size
  coordinates instead of retrying it as malformed provider transport.
- Re-raise every unrecognized worker `ValueError` into the controller incident
  path rather than discarding its diagnostic under `malformed_transport`.
- Keep local `audit_output` and `audit_tools` working directories outside
  provider workspaces so locked archives and audit-only data cannot affect or
  leak into product execution.

## 2.2.13 - 2026-07-30

- Give every replanner a planning-specific acceptance contract instead of
  inheriting an unprovable final product-review criterion.
- Require bounded replan deltas to carry failed acceptance and mandatory gate
  obligations into fresh executable evidence while preserving unaffected work.
- Clarify that a replanner completes on a valid PlanProposal handoff even though
  its future product gates have not run yet.

## 2.2.12 - 2026-07-30

- Route evidence-backed `contained`, `recovered`, and `failed_safe`
  controller-incident results directly to a Director replan instead of
  repeating an already-contained recovery hypothesis.
- Require revision N+1 to rerun or replace the affected product node with
  fresh product-semantic evidence; never use an `IncidentResult` as proof that
  a product test or review passed.
- Preserve accepted unaffected work and keep the controller containment
  handoff outside the product's semantic hypothesis budget.

## 2.2.11 - 2026-07-30

- Give controller incident-recovery tasks dedicated containment, evidence, and
  bounded-next-step acceptance instead of inheriting an unrelated failed
  product role's semantic criteria.
- Preserve those controller criteria through incident repair chains and accept
  an evidence-backed `contained` result as a fail-safe terminal recovery
  outcome without requiring a production mutation or invented product finding.

## 2.2.10 - 2026-07-30

- Resolve a durable dependency on a superseded failed task through its unique
  accepted repair chain, so downstream reviewers receive the replacement's
  immutable completed evidence instead of the failed attempt.
- Reject ambiguous, cross-product, role-changing, schema-changing, or
  root-context-changing forward repair lineages rather than guessing which
  replacement output to admit.

## 2.2.9 - 2026-07-30

- Resolve evidence for accepted reused tasks through their validated
  `supersedes_task_id` chain to the original immutable attempt, while keeping
  each reused task free of duplicate attempt rows.
- Reject cyclic, cross-product, identity-changing, result-reference-changing,
  or result-digest-changing reuse lineages before admitting dependency
  evidence to a downstream agent.

## 2.2.8 - 2026-07-30

- Carry accepted, unchanged implementation slices and architecture-review
  evidence across immutable replan revisions instead of rebuilding or losing
  their durable results.
- Reconstruct semantic dependencies from controller-owned plan edges, preserve
  accepted parent-lineage nodes in replanner Context Packs, and bind a fresh
  architecture review to an accepted architecture-package producer.
- Refuse result reuse when a replan changes any semantic node contract field,
  while keeping the provider PlanProposal digest bound to the original
  immutable proposal.

## 2.2.7 - 2026-07-30

- Supply replanners with the active implementation inventory, accepted
  unaffected result coordinates, unresolved FailureEnvelopes, hypothesis
  history, safe problem coordinates, and the current policy digest.
- Preserve schema-bounded PlanProposal `summary` text in failure diagnostics
  when planning output returns `failed_safe` without reviewer-style findings.

## 2.2.6 - 2026-07-30

- Preserve required toolchain capabilities across the causal task lineage when
  FailureRouter creates an exact-node repair, so repair Context Packs retain
  the controller-selected container runtime and scanner grants.

## 2.2.5 - 2026-07-30

- Preserve the systemd-provisioned `XDG_RUNTIME_DIR` across the sanitized
  worker-to-Hermes subprocess boundary so builder terminal sessions can use
  the same rootless container engine already proven by Controller preflight.
- Include trusted resolved capability scopes in each Context Pack and direct
  builders to use the controller-selected container runtime instead of
  guessing a Docker socket.

## 2.2.4 - 2026-07-30

- Reject PlanProposal scopes that contain product requirements instead of
  relative repository path globs, and make the path-glob contract explicit in
  the schema and planner prompts.
- Preserve sanitized violating path coordinates and required fixes in
  `scope_violation` FailureEnvelopes so repair and replan agents can act on the
  exact controller diagnostic.
- Store workspace lease authority beside the model-managed repository instead
  of inside it, so provider cleanup cannot delete the marker required for a
  safe release.

## 2.2.3 - 2026-07-30

- Prove repository configuration and pull-request merge capabilities from the
  authenticated repository permission and enabled merge methods even when a
  free GitHub repository does not expose ruleset or branch-protection reads.

## 2.2.2 - 2026-07-30

- Give the rootless service user exclusive ownership of the temporary Podman
  build context before the controller-owned container build probe.

## 2.2.1 - 2026-07-30

- Enter the trusted release root before rootless Podman probes so the service
  user never inherits an unreadable operator home as its working directory.

## 2.2.0 - 2026-07-30

- Compile model-proposed semantic implementation slices into a deterministic,
  controller-owned lifecycle with typed evidence dependencies and mandatory
  architecture, security, acceptance, production, and observation stages.
- Add fail-closed semantic plan validation, hypothesis-changing circuit
  breaking, toolchain preflight, maintenance mode, durable state audit, and
  idempotent digest-bound recovery planning and application.
- Reject release candidates whose source, wheel, SBOM, changelog, or release
  record version evidence disagrees.

## 2.1.26 - 2026-07-29

- Publish the controller-owned quality gate ID catalog to planning agents and
  reject unregistered gate IDs before a proposed DAG can mutate durable state.
- Route unknown gate IDs in older persisted plans as
  `invalid_quality_gate_contract` with exact safe coordinates instead of
  misclassifying the post-parse controller error as `malformed_transport`.

## 2.1.25 - 2026-07-29

- Normalize every routed v2 repair brief to a non-empty blocker coordinate,
  using the sanitized failure reason when no test or quality gate ID exists.
- Preserve concrete required fixes while preventing policy and controller
  failures from creating unusable recovery briefs with empty gate mappings.

## 2.1.24 - 2026-07-29

- Preserve stdout as the sole machine-readable provider result when the Hermes
  subprocess exits successfully.
- Keep tool and progress diagnostics written to stderr out of successful JSON
  contracts, while retaining both channels for fail-closed nonzero-exit
  classification.

## 2.1.23 - 2026-07-29

- Add explicit immutable identity invariants to Task Specifier and Replanner
  context: fresh plan and task IDs, unique 64-hex idempotency keys, and no
  reuse of identities present in supplied context or failure evidence.
- Require planning agents to keep every acceptance criterion unique and trace
  each mandatory goal only to acceptance IDs that exist in proposed nodes.

## 2.1.22 - 2026-07-29

- Give Task Specifier and Replanner the controller-owned executable identity
  catalog, including each canonical role, output schema, capability profile,
  and complete required-capability set.
- Reject unsupported roles and registered-but-noncanonical output schemas
  before a proposed BacklogPlan can mutate the durable execution graph.
- Normalize planning-role identities during semantic validation so underscore
  aliases cannot bypass the planning-only graph guard.

## 2.1.21 - 2026-07-29

- Include every safe local JSON Schema dependency referenced by an output
  contract in the compiled provider prompt.
- Give Task Specifier and Replanner the complete `task-contract-v2` field,
  status, and enum contract embedded by `backlog-plan-v2`, preventing agents
  from guessing required node metadata.
- Reject path-escaping, missing, non-schema, or symlinked local schema
  references fail-closed.

## 2.1.20 - 2026-07-29

- Bound causal `incident-recovery` chains to three failed recovery tasks.
- Route the third failed controller recovery to a Product Director/Replanner
  diagnosis reassessment with a fresh child hypothesis instead of recursively
  creating a fourth recovery task.
- Preserve successful early controller recovery and its zero product-semantic
  budget behavior, with regression coverage for both paths.

## 2.1.19 - 2026-07-29

- Changed durable task claiming to product-level least-recently-served rotation
  before task priority, preventing high-priority Replanner loops in two older
  products from starving a lower-priority ready task in an independent product.
- Preserved task priority and critical-path ordering inside each selected
  product and added a regression where an unclaimed product runs before a
  priority-1000 task from the product that just consumed the worker.

## 2.1.18 - 2026-07-29

- Preserve the final sanitized validator coordinate, structured required fixes,
  blocker IDs, and transport-diagnostic reference when the bounded model tiers
  are exhausted, so a newly planned recovery task never falls back to a generic
  `schema_validation` failure.
- Added terminal-path regression coverage proving the coordinate survives in
  attempt and failure evidence while a secret-like provider value is absent
  from prompts and every persisted JSON artifact.

## 2.1.17 - 2026-07-29

- Propagate sanitized validator coordinates from transport diagnostics into
  repair briefs, attempt evidence, and failure envelopes so the next agent
  receives a concrete field-level correction without raw provider output,
  prompts, or secret values.
- Restrict Telegram gateway outbox claims atomically to owner-notification
  events, preventing unrelated durable events from starving Russian progress
  and owner-action messages.
- Added regressions for output-schema and semantic-plan diagnostic continuity,
  structured failure evidence, and delivery past an older generic outbox event.

## 2.1.16 - 2026-07-29

- Product intake now persists every valid idempotent request in the durable
  queue instead of rejecting it when all execution slots are occupied.
- `max_active_products` now limits concurrently claimed product work at the
  scheduler boundary; queued products remain independently visible and start
  automatically when a slot becomes available.
- Added v1 and v2 regression coverage for admission beyond execution capacity
  and strict single-slot claim behavior.

## 2.1.15 - 2026-07-29

- Failure Router now resolves legacy task-contract references through the
  canonical evidence coordinate and, when no file survives, reconstructs a
  least-privilege recovery contract from durable task and active-plan
  metadata without weakening mandatory product completion evidence.
- Isolated per-product reconciliation faults into deduplicated internal
  incidents so one malformed historical product cannot stop Director progress
  for any other product; successful reconciliation resolves the incident.
- Added regression coverage for legacy contract lookup, safe reconstruction,
  sanitized diagnostics, and cross-product reconcile isolation.

## 2.1.14 - 2026-07-29

- Made the durable task lease authoritative for persistent workspace markers:
  workers now reclaim a marker only after SQLite proves its former task lease
  is no longer active, while a genuinely active lease remains fail-closed.
- Added migration v11 to collapse workspace-contention incident trees created
  after the original one-time recovery and resume their causal root tasks.
- Added regression coverage for active-marker protection, stale-marker
  recovery, durable lease expiry, and post-deployment collision-tree repair.

## 2.1.13 - 2026-07-29

- Split mandatory local recovery from best-effort offsite replication so a
  free-tier provider download cap cannot block controller, builder, staging,
  or the pre-migration rollback point.
- Added a fail-closed offsite retry timer that checks every two hours but
  skips provider calls for 26 hours after a successful offsite proof, allowing
  free-tier download counters to reset before the next refresh.
- Serialized local and offsite restic operations with a shared lock, moved the
  SQLite backup input to a stable path for correct retention grouping, and
  separated local and offsite sanitized proof files.

## 2.1.12 - 2026-07-29

- Added a durable capability reconciler that preflights newly created
  products, refreshes stale or blocked grants, resumes their task frontier
  without process restarts, persists sanitized probe results, and
  deduplicates owner notifications.
- Capability profiles are now controller-owned minimums. Plans and direct
  task creation fail closed before SQLite mutation when a role/stage
  downgrades its profile or omits a canonical capability.
- GitHub grants now use repository-scoped read-only permission probes for
  identity, credential type, repository permissions, rulesets, branch
  protection, merge policy, and OAuth/App permissions; authentication alone
  no longer proves write or merge access.
- Production capability probes now require fresh offsite-restic proof, the
  root-owned transactional deploy and rollback helpers, a non-interactive
  sudo boundary, and a healthy target.
- Added mandatory AUT-P0-023 through AUT-P0-027 service-level acceptance
  coverage, including post-start intake, credential appearance, fail-closed
  under-declaration, read-only GitHub credentials, and the complete private
  product runtime path.

## 2.1.11 - 2026-07-29

- Reclassifying a missing planned output schema now also resolves the matching
  stale controller incident, keeping liveness and operator diagnostics aligned
  with the active Replanner path.
- Migration v9 closes historical controller incidents left open after
  migration v8 converted their failures into autonomous plan repair.

## 2.1.10 - 2026-07-29

- Backlog plan precommit validation now rejects output schemas that are not
  bundled in the immutable release schema registry, preventing an accepted
  plan from creating unexecutable worker tasks.
- Failure Router recognizes an exact missing planned-output-schema controller
  diagnostic as a plan defect and sends it to Replanner instead of repeatedly
  creating Incident Recovery work.
- Migration v8 reopens historical missing-output-schema failures and
  supersedes their obsolete incident-recovery branches so affected products
  continue autonomously on a corrected plan revision.

## 2.1.9 - 2026-07-29

- Failure Router now creates recovery work only for unresolved causal leaves.
  Ancestor failures remain durable audit evidence but cannot create a second
  competing branch after a descendant failure is recorded.
- Migration v7 supersedes historical recovery tasks shadowed by an active
  descendant recovery task while preserving the full failure lineage for
  atomic closure after success.

## 2.1.8 - 2026-07-29

- Recovery work is always anchored to the product's current active plan, even
  when the causal task created that plan from a superseded parent revision.
- A routed recovery task stranded on an inactive plan is deterministically
  superseded by a fresh immutable task contract on the active revision.
- Liveness now counts only work belonging to the active plan. A stale READY
  row can no longer conceal an exhausted graph or prevent automatic recovery.

## 2.1.7 - 2026-07-29

- Successful recovery now resolves the complete causal failure ancestry,
  associated hypotheses, and controller incidents atomically. Migration v6
  reconciles historical chains already proven obsolete by accepted or
  superseded recovery work.
- `incident-result.status=recovered` is recognized as a successful
  Incident Recovery outcome instead of being misrouted as another semantic
  failure.
- Liveness checks no longer treat failed rows or an incident record without an
  active recovery task as proof of progress. An exhausted non-terminal graph
  records the controller incident and creates a real Replanner task for plan
  revision N+1.
- Backlog plans containing only planning/recovery roles are rejected before
  ingestion; every accepted plan must contain non-planning execution work.

## 2.1.6 - 2026-07-29

- Reused `BacklogPlan.plan_id` values are now compared against the immutable
  candidate digest before any child task-contract artifact can be written.
  Digest conflicts become an exact bounded validator diagnostic instead of a
  late controller or artifact-conflict incident.
- Failure Router task contracts and repair briefs now use deterministic
  artifact identities. A restart after artifact persistence but before task
  insertion can replay the same route without changing immutable evidence or
  creating a competing recovery path.

## 2.1.5 - 2026-07-29

- A restarted worker now detects a valid immutable result left by an
  interrupted `started` attempt and replays that evidence into the atomic
  outcome transaction instead of invoking the provider again.
- Legacy planning attempts that persisted a completed provider result before
  semantic graph validation are safely revalidated after restart. Invalid
  plans receive the exact bounded repair path without overwriting the original
  attempt artifact or opening a false artifact-conflict incident.

## 2.1.4 - 2026-07-29

- Concurrent service startup now rechecks each migration after acquiring the
  SQLite writer lock, preventing a stale pre-lock snapshot from inserting the
  same migration version twice.
- BacklogPlan semantic identities and edge endpoints are validated before
  outcome commit. Safe diagnostics include the exact validator coordinate and
  schedule a bounded repair instead of crashing the worker process.
- Unexpected atomic outcome-commit failures are persisted as controller
  failures with redacted diagnostics and no partial plan mutation.

## 2.1.3 - 2026-07-29

- Task claiming is serialized per product because each product owns one persistent,
  exclusively leased repository workspace. Independent products still run concurrently,
  regardless of matching repository-relative conflict keys.
- Migration v5 resolves the exact historical workspace-lease controller failures and
  incidents, supersedes their redundant recovery descendants, and requeues one earliest
  causal task per affected product.

## 2.1.2 - 2026-07-29

- A retryable failure with an already scheduled bounded in-place `repair` or
  `transient_retry` is now owned by that single retry path. Failure Router waits
  for its outcome instead of creating a competing child task for the same
  failure; success resolves the open envelope, while exhausted retries return
  to normal causal routing.

## 2.1.1 - 2026-07-29

- Conflict keys теперь изолированы `product_id`: одинаковые относительные пути в разных repositories не блокируют независимые workers, при этом конфликт внутри одного продукта по-прежнему сериализуется.
- Migration v4 распознаёт только точный URL-only legacy GitHub intake и восстанавливает `existing_repository`, canonical URL, repository name и отдельную безопасную root goal; произвольный текст и canonical v2 intake не анализируются regex-эвристикой.

## 2.1.0 - 2026-07-29

- Добавлен durable Product Execution Graph: versioned plans, multi-node DAG, dependency frontier, lineage, capabilities, failures, hypotheses и completion evidence мигрируют из 2.0.x без потери строк; перед первой миграцией создаётся backup SQLite.
- `TaskOutcome` атомарно фиксирует task/attempt result, failure, hypothesis, repair/replan successors, edges, product projection и outbox. Все семь fault-injection points, restart и idempotent replay покрыты release-blocking тестами.
- Intake разделяет root goal и repository metadata. New-product bootstrap создаёт собственный private repository и нейтральный initial commit; private GitHub credential остаётся внутри protected adapter.
- `repair_required` создаёт причинно связанную repair child, `needs_replan` — настоящий planning-only Replanner и plan revision N+1. После трёх попыток одной гипотезы Director обязан изменить диагноз, а не повторить прежний fix.
- Context Pack v2 и Failure/Repair/Transport diagnostics сохраняют точные безопасные координаты, fingerprints и bounded traceback без raw secrets. Устранён false positive, при котором `task-...` ошибочно принимался за OpenAI-style `sk-...`.
- OWNER_ACTION разрешён только для явной allowlist внешних причин. Missing adapter/model route, schema/artifact/migration failure и неизвестный blocker маршрутизируются как controller incidents.
- Completion reducer требует PASS evidence для root goals, mandatory nodes, independent review, required checks, exact staging/production digest, rollback readiness и observation; notification идемпотентна.
- Добавлены AUT-P0-001..022, AUT-P1-001..010 и anti-pattern acceptance tests, включая два полных E2E без участия владельца.

## 2.0.20 - 2026-07-29

- Context Pack теперь передаёт санитизированное содержимое выбранных файлов, а не только их хэши; исходный digest, digest санитизированного содержимого и безопасные координаты редактирования сохраняются отдельно.
- Independent Reviewer получает exact subject-bound candidate inventory/diff, read-only workspace binding, полные upstream Task Contracts и controller gate records, включая mandatory flag, subject SHA, command/artifact digests, timestamps и exit code.
- Прямой security-review dependency result также остаётся в independent-review context; отсутствие controller-owned evidence больше не маскируется под недостаток кода продукта.

## 2.0.19 - 2026-07-29

- Стандартный Builder contract разрешает изменять `pyproject.toml`, потому что обязательные controller-owned `target-dependency-audit` и `target-license-check` используют его как Python dependency/license contract.
- Устранён доказанный scope contradiction: Director больше не выдаёт исправление «создать `pyproject.toml`» внутри задачи, которая одновременно запрещает изменять этот файл.
- Repository PM task остаётся приоритетным источником scope: его frozen `allowed_paths` и `forbidden_paths` полностью заменяют стандартный Builder scope, поэтому расширение не ослабляет PM acceptance.

## 2.0.18 - 2026-07-29

- Transient provider retry больше не заменяет исходный repair brief технической причиной `network_timeout` или `malformed_transport`: blocker IDs, required fixes, definition of done и безопасные evidence refs исходной гипотезы переносятся в новый brief без потерь.
- Транспортная ошибка записывается как дополнительная диагностическая заметка без ложного требования менять код; Builder продолжает ту же доказанную гипотезу и получает новый prompt digest для разрешённого повтора.
- Документация recovery приведена в соответствие с per-hypothesis policy: три repair-cycles одной подписи, затем отдельный ограниченный `DIAGNOSIS-REASSESSMENT`, без глобального лимита на число разных доказанных проблем продукта.

## 2.0.17 - 2026-07-29

- Одна problem hypothesis получает до трёх полноценных repair-cycles даже при model floor Sol; число считается по blocker signature, а не по всему продукту.
- После трёх повторов той же подписи Director один раз переводит работу в отдельную `DIAGNOSIS-REASSESSMENT` hypothesis: Builder обязан доказать, ошибочны ли постановка, scope, controller gate/environment или исходный диагноз, и не может просто повторить прежний fix.
- Reassessment также ограничен тремя циклами и идемпотентной подписью; после его исчерпания Hermes остаётся fail-closed и отправляет точную русскую причину вместо бесконечного цикла.

## 2.0.16 - 2026-07-29

- Director больше не ограничивает весь продукт тремя разными root-cause replans: каждая новая доказанная подпись проблемы получает собственный bounded repair budget.
- Идемпотентность остаётся fail-closed: одна и та же подпись гипотезы открывается не более одного раза, поэтому изменение не создаёт бесконечный повтор прежнего диагноза.
- Product Director явно обязан отличать число решённых проблем от бюджета попыток текущей проблемы; новый blocker не наследует исчерпанные попытки старых blockers.

## 2.0.15 - 2026-07-28

- Provider-output sanitizer сохраняет полный JSON-ответ, но детерминированно заменяет credential-like значения на `[REDACTED]` до schema validation и записи evidence; безопасный аудит содержит точный JSON-путь и идентификатор правила, но не значение.
- Legacy-задача с непрозрачным `secret_exposure` получает ровно один повтор уровня Sol под новым sanitizer-протоколом и продолжает конвейер без OWNER_ACTION.
- Повтор старой гипотезы больше не нужен для ложноположительного секрета в ответе агента: контроллер устраняет транспортную проблему сам, а Builder продолжает работать с полным санитизированным результатом.

## 2.0.14 - 2026-07-28

- Director определяет исчерпанный бюджет по максимальному cycle всей истории проекта, а не по номеру последней handoff-задачи; новый blocker Test Engineer больше не теряется после более позднего Builder cycle.
- `needs_replan` теперь разбирается в actionable repair brief наравне с `repair_required`: finding IDs и required fixes сохраняются без обобщения.
- Legacy-механизм расширения числового лимита не перехватывает проект, который уже достиг текущего глобального предела; в этом случае управление получает root-cause replan.

## 2.0.13 - 2026-07-28

- Reconciler может безопасно продолжить проект с более раннего результата Builder, если все обязательные controller-owned проверки прошли, а `needs_replan` вызван только конфликтом внутреннего детектора с точной областью `allowed_paths`.
- Поздний неудачный Builder-цикл сохраняется в истории, доказанный результат становится зависимостью Test Engineer, а повторное восстановление остаётся идемпотентным.
- Builder явно получает правило не изобретать корневой manifest, Makefile или отдельный canonical-command detector вне разрешённых путей; штатная task-local acceptance command и controller-owned gates являются источниками истины.
- После трёх неудачных циклов Director закрывает прежнюю гипотезу: новый подтверждённый blocker получает отдельный actionable brief и новый ограниченный бюджет, тогда как повтор той же гипотезы не открывается снова. Ограничение относится к подписи проблемы, а не к числу разных проблем продукта.

## 2.0.12 - 2026-07-28

- Идемпотентность pre-provider handoff recovery привязана к точному `terminal_detail`: одинаковая ошибка не повторяется, а новая migration-ошибка после обновления получает одну автоматическую попытку.
- Legacy recovery-события без `terminal_detail` остаются идемпотентными для исходного `accepted result missing`, но не блокируют исправленный `deferred evidence invalid` handoff.

## 2.0.11 - 2026-07-28

- Deferred Builder handoff принимает обе исторически корректные формы outer evidence (`repair_required` и `blocked_external`), но только при прежних controller/event/schema/local-PM ограничениях.
- Reconciler автоматически возвращает Test Engineer в очередь после legacy evidence mismatch, если provider ещё не вызывался.

## 2.0.10 - 2026-07-28

- Test Engineer принимает controller-validated Builder result, если Builder был завершён локально и отложил только downstream GitHub gate; immutable provider evidence при этом не переписывается.
- Если старый worker успел остановить такой handoff до provider-вызова, reconciler идемпотентно возвращает Test Engineer в очередь без повторного Builder-вызова и без OWNER_ACTION.
- Production bootstrap запускает постоянный `hermes-worker-2`; release promotion перезапускает его, когда unit установлен, поэтому два product-scoped workspace могут обрабатываться параллельно.

## 2.0.9 - 2026-07-28

- После исчерпания model tiers Builder запускает следующий bounded product repair cycle вместо повторного FAILED_SAFE-loop.
- Controller-owned gate traceback попадает в `relevant_log_fragment` и `required_fixes`, поэтому Builder видит точную ошибку, а не только gate ID.
- Recovery каждого исчерпанного Builder cycle идемпотентен; повторное расширение того же policy budget также не создаёт цикл событий.
- Два проекта могут быть активны одновременно при двух workers; их planning/workspace/assurance locks остаются строго product-scoped.

## 2.0.8 - 2026-07-28

- Builder downstream-gate recovery читает mandatory/optional статус из controller-owned quality-gate catalog.
- Optional lint baseline не останавливает восстановление, но любой mandatory или неизвестный failed gate остаётся fail-closed.

## 2.0.7 - 2026-07-28

- Builder repair task активируется только с actionable brief: blocker IDs, точные required fixes, allowed paths и проверяемый DoD обязательны.
- Findings из reviewer- и attempt-схем нормализуются без потери `id/code`, описания и требуемого исправления.
- Локально завершённый Builder больше не блокируется на GitHub `pm-acceptance`: этот gate выполняется позже для immutable candidate.
- Reconciler автоматически восстанавливает ранее ошибочно остановленный Builder и продолжает с Test Engineer без нового repair cycle.
- Product Director обязан трассировать цели к требованиям, acceptance и evidence; Product Tester не может принять продукт без PASS/evidence по каждой critical journey.

## 2.0.4 - 2026-07-28

- Failed mandatory gate IDs сохраняются в task detail, repair brief и русском exhaustion-уведомлении.
- Legacy attempt evidence автоматически восстанавливает точные gate IDs при reconciliation.

## 2.0.3 - 2026-07-28

- Worker продлевает durable task lease во время длительного model/release execution.
- Потеря lease обнаруживается до terminal write, поэтому другой worker не получает параллельного исполнителя той же задачи.

## 2.0.2 - 2026-07-28

- Repair task остаётся недоступной worker до атомарного прикрепления validated repair brief.
- Отсутствующая legacy-диагностика нормализуется в непустую внутреннюю причину вместо остановки reconciler.

## 2.0.1 - 2026-07-28

- Добавлен постоянный reconciler: у каждого активного продукта автоматически восстанавливается следующая исполнимая задача.
- Внутренние ошибки и провал `pm-acceptance` теперь создают ограниченный repair cycle с новым diagnostic brief и эскалацией Terra -> Sol.
- После неуспешного candidate check фабрика закрывает неготовый PR, очищает candidate branch и продолжает исправление от актуального `main`.
- Watchdog считает активный продукт без очереди инцидентом и восстанавливает конвейер без команды владельца.
- `OWNER_ACTION` оставлен только для подтверждённых внешних блокировок; исчерпание внутренних repair cycles сообщает точную причину по-русски.
- Уведомления reconciler и OWNER_ACTION доставляются через durable Telegram outbox с повторной отправкой.

## 2.0.0 - 2026-07-26

- Переведён прототип маршрутизации одной задачи в долговечную автономную фабрику ПО.
- Добавлен полный конвейер: идея, Product Contract, архитектура, backlog, разработка, независимая приёмка, релиз, развёртывание, наблюдение и улучшения.
- Добавлена многоуровневая модельная эскалация D0/W0 -> Luna -> Terra -> Sol.
- Добавлены профили ролей, строгие JSON-контракты, policies-as-code, quality/security gates, quota circuit breaker и OWNER_ACTION.
- Зафиксированы решения владельца от 26 июля 2026 года.
- Устранено противоречие public/private: public по умолчанию только для безопасных проектов; чувствительные проекты принудительно private.
