# Pilot architecture

The pilot is a single stateless HTTP process around a persistent SQLite file. The process exposes three read-only health/status endpoints and serves one static page. The only durable state is a startup event ledger used to prove restart persistence.

Deployment is localhost-only on the VPS (`127.0.0.1:8090`), behind no public admin surface. Docker provides a non-root runtime, read-only root filesystem, dropped capabilities, a PID limit, and a memory limit.
