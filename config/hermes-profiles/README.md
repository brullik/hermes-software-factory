# Hermes profiles

Эти файлы описывают **логические profiles**. Bootstrap adapter обязан сверить актуальный синтаксис установленной версии Hermes (`hermes --help`, `hermes config`, official docs) и материализовать отдельный `$HERMES_HOME` для каждого profile.

Нельзя копировать secret values в YAML. Для каждого profile:

- отдельный home/state/session/log;
- общий read-only policy bundle;
- свой SOUL/role prompt;
- model alias разрешается Controller;
- рабочая директория выдаётся по task lease;
- gateway credentials доступны только gateway profile;
- release credentials доступны только release adapter, не planning/builder.

Hermes delegation baseline:

```yaml
delegation:
  max_spawn_depth: 1
  max_concurrent_children: 2
  orchestrator_enabled: false
```

Точный provider/model для delegation задаётся runtime adapter по выбранному tier.
