# 10. Отказы и восстановление

## 10.1. Классы отказов

- `TRANSIENT_PROVIDER`
- `QUOTA_EXHAUSTED`
- `SEMANTIC_FAILURE`
- `POLICY_VIOLATION`
- `GATE_FAILURE`
- `INFRASTRUCTURE_FAILURE`
- `EXTERNAL_BLOCKER`
- `SECURITY_INCIDENT`
- `DEPLOYMENT_FAILURE`
- `DATA_INTEGRITY_RISK`

## 10.2. Circuit breakers

Provider breaker открывается после configurable последовательных transient failures. В открытом состоянии новые задачи этого provider не запускаются; health probe выполняется отдельно.

Task breaker останавливает бесконечный repair после исчерпания attempt policy.

Deployment breaker блокирует новые releases после failed rollback или неизвестного состояния production.

## 10.3. Crash recovery

При запуске Controller:

1. проверяет leases;
2. сопоставляет task state с GitHub/containers/deployments;
3. завершённые side effects принимает идемпотентно;
4. незавершённые безопасно повторяет;
5. неизвестный production state переводит в `FAILED_SAFE`;
6. независимые задачи продолжает.

## 10.4. OWNER_ACTION

Создаётся только когда система технически не может продолжить:

- OAuth device code/2FA/CAPTCHA;
- отсутствующий внешний credential;
- регистрация/покупка ресурса;
- DNS/account action вне имеющихся прав;
- юридическое решение;
- необратимое production action, не разрешённое policy.

OWNER_ACTION содержит ровно одно действие, безопасную инструкцию и machine-checkable unblock condition.

## 10.5. Запрещённые способы «восстановления»

- отключить тест;
- удалить failing assertion;
- пометить failure как optional;
- скрыть лог;
- force push;
- изменить policy внутри task branch;
- использовать другой SHA без повторного review;
- восстановить production из непроверенного backup.
