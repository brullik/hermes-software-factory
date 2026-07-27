# Пример эскалации

1. Builder Luna реализует endpoint.
2. `unit-tests` PASS, `contract-tests` FAIL из-за неверного error envelope.
3. Controller сохраняет полный log, передаёт Luna только failing assertion и API contract.
4. Luna repair снова FAIL по тому же criterion.
5. Controller повышает tier до Terra.
6. Terra получает task, diff, API contract, два compact attempt summaries и gate evidence.
7. Terra исправляет root cause; все gates PASS.
8. Independent Reviewer Terra принимает immutable SHA.
9. Sol не вызывается.

429 между шагами 3 и 4 не считается semantic failure и не повышает tier.
