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

## Local Kanban

The controller serves a read-only board at `http://127.0.0.1:8787/kanban`.
It refreshes every five seconds from `/api/kanban` and shows products, durable
tasks, leases, and blocked states without exposing ideas, owner identifiers,
provider output, or credentials. The controller refuses non-loopback binds, so
remote access should use an SSH local port forward instead of opening the
admin port publicly:

```bash
ssh -N -L 8788:127.0.0.1:8787 <vps-host>
```

Then open `http://127.0.0.1:8788/kanban` on the local computer. The local
factory may already use `8787`, so `8788` is the default remote-board port.

An external metrics collector can scrape the endpoints through a local/VPN
path after the owner explicitly configures that collector.

When a VPS host is not available, the owner can use the Telegram gateway's
read-only `/kanban` command for a compact text snapshot of the same projection.
