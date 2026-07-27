# Caddy deployment

The factory never exposes the controller admin port. Caddy publishes only the
pilot/product HTTP surface on `127.0.0.1:8090` and terminates HTTPS for the
host supplied by the owner.

Run `scripts/bootstrap/configure-caddy.sh <hostname> <tls-email>` on the VPS
only after DNS points at the VPS. The script writes the host and email to a
root-owned environment file, installs this Caddyfile, enables ports 80/443,
and starts the system Caddy service. No credentials are stored in this file.
