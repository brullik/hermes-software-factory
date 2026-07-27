# Monitoring baseline

The controller and neutral pilot expose Prometheus-compatible `/metrics`
endpoints. The endpoints are bound to localhost by the systemd/Compose
configuration; Caddy publishes only the product surface and never the
controller admin endpoint.

The minimum operator probes are:

- controller `/healthz`, `/readyz`, `/metrics`;
- pilot `/health/live`, `/health/ready`, `/metrics`;
- systemd service state and Docker health;
- restic timer freshness and repository check;
- disk/RAM capacity before starting another worker.

An external metrics collector can scrape the endpoints through a local/VPN
path after the owner explicitly configures that collector.
