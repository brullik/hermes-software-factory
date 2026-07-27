# Карта файлов исходного пакета

| Исходный файл | Новый источник истины |
|---|---|
| `00-questions.md` | `USER-DECISIONS.md`, `policies/` |
| `01-architecture.md` | `architecture/` |
| `02-orchestration-protocol.md` | `architecture/02-pipeline-lifecycle.md`, `03-model-escalation.md` |
| `03-hermes-config.example.yaml` | `config/hermes-profiles/`, `config/model-routing/` |
| `04-implementation-spec.md` | `IMPLEMENTATION-SPEC.md` |
| `05-acceptance-tests.md` | `ACCEPTANCE-PLAN.md` |
| `prompts/director.md` | `prompts/roles/product-director.md` |
| `prompts/dispatcher.md` | Controller + `task-specifier.md` |
| `prompts/worker.md` | `builder.md`, `test-engineer.md` |
| `prompts/reviewer.md` | `independent-reviewer.md`, `security-reviewer.md`, `product-tester.md` |
| `scripts/router.py` | `scripts/model_router.py`, policy engine |
| `scripts/quality_gate.py` | gate graph/controller implementation |
| `schemas/task-packet...` | versioned schemas in `schemas/` |

Исходные файлы не должны копироваться в production repository как альтернативная спецификация.
