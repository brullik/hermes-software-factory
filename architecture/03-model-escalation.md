# 3. Многоуровневая эскалация моделей

## 3.1. Общая лестница

```text
D0/W0 -> Luna attempt 1 -> Luna repair attempt 2
      -> Terra attempt 1 -> Terra repair attempt 2
      -> Sol arbitration attempt 1
      -> FAILED_SAFE / OWNER_ACTION only when externally blocked
```

Третья semantic attempt на том же tier разрешена только для задач, классифицированных как flaky/visual/nondeterministic и только при наличии новой evidence. По умолчанию лимит - две.

## 3.2. Почему не повторять один ответ 2-3 раза

Повтор без новой информации расходует квоту и редко меняет результат. Каждая repair attempt обязана содержать:

- failing gate IDs;
- минимальный релевантный фрагмент лога;
- expected vs actual;
- changed files;
- запрещённые обходы;
- предыдущий attempt summary;
- точную definition of done.

## 3.3. Ошибки, которые не повышают tier

Следующие события вызывают transient retry или provider fallback того же tier:

- HTTP 429/quota window;
- network timeout;
- provider 5xx;
- malformed transport response;
- process crash до получения результата;
- временно недоступный tool.

Они не являются доказательством недостаточной способности модели.

## 3.4. Ошибки, которые повышают tier

- два schema-valid, но неуспешных semantic attempts;
- повторный провал одного и того же deterministic gate;
- scope violation;
- противоречие Product Contract;
- архитектурный конфликт, который нельзя решить локальным repair;
- Reviewer обнаружил ложный PASS;
- риск повысился после анализа;
- задача превышает capability threshold стартового tier.

## 3.5. Стартовый tier по ролям

| Роль | Низкий риск | Средний риск | Высокий риск |
|---|---|---|---|
| Product Director | Luna draft, Terra validate | Terra | Sol |
| Product Analyst | Luna | Terra | Terra -> Sol |
| Solution Architect | Luna для шаблонного CRUD | Terra | Sol |
| Task Specifier | D0 -> Luna | Luna -> Terra | Terra |
| Builder | W0 -> Luna | Luna/Terra по complexity score | Terra -> Sol |
| Test Engineer | D0 -> Luna | Luna -> Terra | Terra -> Sol |
| Independent Reviewer | gates -> Luna | Terra | Sol |
| Security Reviewer | scanners -> Luna triage | Terra | Sol |
| Release Operator | D0, Luna summary | D0 -> Terra on incident | Terra/Sol only incident |
| Product Tester | scripts -> Luna | Luna -> Terra | Terra -> Sol |
| Incident Recovery | D0 rollback -> Terra | Terra | Sol |

## 3.6. Complexity score

Controller вычисляет score без LLM:

- number of components;
- changed file estimate;
- cross-service/API contract changes;
- schema/data migration;
- concurrency;
- authentication/authorization;
- external integrations;
- security/risk markers;
- unfamiliar technology;
- failed attempt count.

Пример маршрутизации:

- `0-3`: Luna;
- `4-6`: Terra;
- `7+`: Sol или Terra с обязательным Sol review;
- любой high-risk marker задаёт минимальный floor из risk policy.

## 3.7. Provider aliases

Промты не содержат конкретных model IDs. Controller использует aliases:

- `economy` -> лучшая прошедшая benchmark Luna-class модель;
- `standard` -> Terra-class;
- `expert` -> Sol-class;
- `deterministic` -> без модели.

Фактическая mapping формируется после live discovery доступов ChatGPT/Codex, Nous Portal, Kimi и DeepSeek. Маршрут не имеет права автоматически переключаться на платный API.

## 3.8. Quota-aware fallback

При исчерпании подписочной квоты:

1. сохранить checkpoint;
2. попробовать другой уже одобренный provider того же tier;
3. уменьшить параллельность до одного worker;
4. отложить необязательные model reviews;
5. перевести задачу в `DELAYED_QUOTA`;
6. автоматически возобновить после provider health probe.

Mandatory deterministic/security gates не отключаются.
