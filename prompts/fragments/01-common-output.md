# Common Output Fragment

Выход должен:

- быть валидным UTF-8 JSON;
- соответствовать указанной schema version;
- содержать `status`, `summary`, `assumptions`, `findings`, `evidence_refs`;
- использовать стабильные reason codes;
- не содержать Markdown fences;
- не содержать секретов;
- не отмечать `completed`, если acceptance не доказана;
- при `repair_required` давать минимальный actionable repair brief;
- при `blocked_external` указывать только candidate reason, а не свободный вопрос владельцу.
