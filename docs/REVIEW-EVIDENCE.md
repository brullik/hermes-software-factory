# Review evidence contract

Independent review is a controller-owned verification stage. A product Builder
must never be asked to repair evidence that the controller failed to place in
the review context.

For every independent review, Hermes binds the prompt to the exact workspace
snapshot through `subject_sha` and supplies:

- the complete sanitized contents of selected changed files, plus their
  original file digest and sanitized-content digest;
- a changed-file inventory and bounded diff, with read-only access to the exact
  subject-bound workspace when the bounded excerpt is insufficient;
- the full upstream Task Contracts and accepted outputs;
- complete controller gate records, including mandatory status, subject SHA,
  command digest, artifact digest, timestamps, exit code, summary, and evidence
  reference;
- the exact predecessor security-review result.

Potential secret values are removed before persistence or prompt compilation.
The Context Pack preserves only safe detector IDs and file/JSON coordinates, so
an agent can identify the affected location without receiving the value.

If any controller-owned review artifact is absent, the condition is an internal
factory evidence defect. It is not an external owner blocker and does not prove
that product code needs modification.
