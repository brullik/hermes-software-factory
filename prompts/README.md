# Сборка промтов

Runtime prompt строится в порядке:

1. `fragments/00-common-system.md`;
2. конкретный `roles/<role>.md`;
3. `fragments/01-common-output.md`;
4. compact policy summary;
5. Context Pack;
6. exact output schema reference.

Model/provider ID в prompt не включается. Prompt compiler сохраняет digest. Repair attempt добавляет только repair brief и delta evidence. Полный предыдущий transcript не добавляется.
