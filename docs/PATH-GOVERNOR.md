# Path Governor 2.3

Path Governor is deterministic controller code and the sole owner of execution
trajectory. Product agents may produce implementation or review evidence, and
the optional Path Arbiter may return one read-only proposal, but neither may
write graph state, choose task identities, issue SQL, use credentials, or
perform GitHub actions.

## Durable identities

- A Semantic Node identifies an obligation independently of a task or plan
  revision.
- A Result Binding is the immutable O(1) pointer from a Semantic Node to the
  accepted source task, attempt, output artifact, schema, contract digest, and
  policy digest.
- A Plan Membership refers either to an existing binding or to one execution
  task. `supersedes_task_id` is retained only for audit history.
- A Candidate Snapshot freezes one repository commit and tree digest over one
  architecture binding and all accepted implementation bindings. Test,
  Security Review, and Release Readiness consume the snapshot instead of a
  growing list of Builder tasks.

## Legacy migration and exact cycle handling

`factory path-migrate --product-id PRODUCT --dry-run` examines a paused product
without committing. A literal repeated task ID is a cycle. Depth alone is not:
the compatibility reader supports 10,000 nodes, materialises direct bindings,
and is then bypassed by normal execution.

Apply only after a successful dry run:

```text
factory path-migrate --product-id PRODUCT
```

The apply operation uses one SQLite transaction. It preserves all task,
attempt, failure, hypothesis, incident, plan, and event history; freezes one
Candidate Snapshot; supersedes the invalid Test repair branch; and creates one
fresh Test task against that snapshot without incrementing the plan revision.
The product must remain `PAUSED` until post-migration invariants pass.

## Progress and loop exit

The stable root-problem signature excludes task IDs, hypothesis IDs, attempt
IDs, and diagnostic wording. Its budget permits one deterministic correction,
one optional Path Arbiter call, and two evidence-producing executions. A
decision is accepted only when the progress vector strictly improves or a new
immutable evidence digest is produced. Exhaustion terminates in `FAILED_SAFE`;
task count and plan revision are never considered progress.

## Production recovery sequence

1. Enter leased deploy maintenance and pause only the selected product.
2. Take and verify the encrypted pre-migration backup.
3. Run `path-migrate --dry-run` on an exact production database copy.
4. Validate binding count, literal cycle count, maximum legacy depth, Candidate
   Snapshot count, superseded Test IDs, fresh Test status, and unchanged active
   plan revision.
5. Deploy the exact merged 2.3.1 commit and wheel digest.
6. Run the same dry run against production, apply once, and audit again.
7. Resume only the selected product and observe it through `COMPLETED`.
8. Restore the trusted production observation policy, run final backup and
   restore drill, and retain the audit evidence.

Any mismatch rolls back the migration transaction and leaves the product
paused. Other products are never resumed by this procedure.
