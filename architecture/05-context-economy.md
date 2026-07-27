# 5. Context Pack и экономия квот

## 5.1. Запрещено передавать

- полную историю проекта;
- полный repository tree без необходимости;
- неизменённые длинные логи;
- все ADR;
- секреты;
- бинарные файлы;
- результаты gates, не относящиеся к задаче;
- повторяющиеся системные инструкции в user message.

## 5.2. Структура Context Pack

```yaml
contract_version: "1.0"
task:
  id: ...
  objective: ...
  acceptance: [...]
constraints:
  allowed_paths: [...]
  forbidden_actions: [...]
project:
  stack: [...]
  relevant_tree: [...]
artifacts:
  selected_files:
    - path: ...
      reason: ...
evidence:
  failing_gates: [...]
  compact_logs: [...]
decisions:
  applicable_adr: [...]
output:
  schema: attempt-result.schema.json
```

## 5.3. Сборка контекста

Context builder использует:

1. task dependencies;
2. changed symbols;
3. import graph;
4. exact search hits;
5. nearby tests;
6. relevant API/schema;
7. compact summaries с provenance.

Каждый включённый файл имеет причину. Если файл не влияет на objective, он не включается.

## 5.4. Ограничения

Пример baseline:

- Luna: до 12 релевантных файлов или 30k input tokens;
- Terra: до 30 файлов или 80k input tokens;
- Sol: до 60 файлов или 160k input tokens;
- logs: максимум 200 строк на gate, с first/last error и hash полного лога;
- tool output сначала сохраняется как artifact, затем в модель передаётся summary.

Фактические limits адаптируются к модели, но Controller не должен автоматически заполнять доступное окно.

## 5.5. Кэширование

- неизменяемый common prompt отделён от task data;
- system fragments версионируются digest;
- repository map кэшируется по commit SHA;
- test discovery кэшируется по dependency lock digest;
- повторная попытка получает delta, а не весь предыдущий transcript.

## 5.6. Метрики

Для каждого attempt записываются, если provider предоставляет данные:

- input/output/cache tokens;
- tool rounds;
- duration;
- provider/model alias;
- result/gates;
- repair count;
- quota errors;
- context bytes/files;
- accepted/rejected.

Оптимизация маршрута выполняется только на основе этих метрик и закрытого benchmark.
