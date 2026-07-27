# Pilot runbook

1. Build and start with `docker compose up --build -d`.
2. Verify `/health/live`, `/health/ready`, and `/api/status` on `127.0.0.1:8090`.
3. Record the image ID and container health before promotion.
4. Roll back by stopping the current Compose project and starting the previous pinned image.
5. Do not add credentials or bind the pilot to a public interface.
