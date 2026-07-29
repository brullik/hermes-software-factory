# Autonomy v2 flow

```text
Idea Intake v2
  → repository bootstrap/private clone
  → Product Director + Architecture
  → Backlog Plan v2 (all nodes and edges)
  → READY frontier
  → atomic TaskOutcome
      ├─ transient → same task + WAITING_TIME
      ├─ localized failure → repair child
      ├─ architecture/scope failure → Replanner + revision N+1
      └─ accepted → downstream frontier
  → checks + staging + production + observation
  → completion reducer
```

Секреты доступны только deterministic adapters. Агент получает root goal, lineage,
capability contract, точные безопасные failure coordinates и bounded file excerpts.
