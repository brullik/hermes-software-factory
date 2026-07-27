# Pilot threat model

Assets are limited to a synthetic SQLite event count and health metadata. There are no credentials, personal data, customer data, payments, external API calls, or public bind addresses.

Controls: localhost-only host binding, non-root container user, read-only filesystem, dropped capabilities, no-new-privileges, bounded memory/PIDs, and explicit health checks.
