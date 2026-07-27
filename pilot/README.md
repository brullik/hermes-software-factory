# Hermes Factory Pilot

Neutral, credential-free staging product for the factory acceptance flow. It is intentionally low-risk: a read-only status dashboard with a small persistent SQLite event store, no external integrations, no customer data, and no payment or financial behavior.

## Local run

```bash
python app.py
curl http://127.0.0.1:8080/health/live
```

## Container run

```bash
docker compose up --build -d
curl http://127.0.0.1:8090/health/ready
```

The host binding is localhost-only. The container is non-root, read-only, drops Linux capabilities, and has a 256 MiB memory limit.
