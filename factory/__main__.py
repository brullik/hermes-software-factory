"""Allow ``python -m factory`` to invoke the operator CLI."""

from .cli import main

raise SystemExit(main())
