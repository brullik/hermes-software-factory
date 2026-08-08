"""Build a bounded, sanitized support bundle from an explicit file allowlist."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

from .common import redact_text, sha256_file, sha256_text, stable_json, utc_now


class SupportBundleError(RuntimeError):
    """Support evidence cannot be exported without exposing or mutating state."""


def build_support_bundle(
    *,
    incident_id: str,
    source_files: tuple[Path, ...],
    allowed_roots: tuple[Path, ...],
    output_root: Path,
    metadata: dict[str, Any],
) -> tuple[Path, str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", incident_id):
        raise SupportBundleError("support incident id is invalid")
    output_root.mkdir(parents=True, exist_ok=True)
    existing = sorted(output_root.glob(f"support-{incident_id}-*.zip"))
    if existing:
        if len(existing) != 1:
            raise SupportBundleError("support incident has multiple immutable bundles")
        destination = existing[0]
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.stat().st_size > 25 * 1024 * 1024
        ):
            raise SupportBundleError("existing support bundle is unsafe")
        try:
            with zipfile.ZipFile(destination, "r") as archive:
                if archive.testzip() is not None or "manifest.json" not in archive.namelist():
                    raise SupportBundleError("existing support bundle is corrupt")
        except zipfile.BadZipFile as error:
            raise SupportBundleError("existing support bundle is corrupt") from error
        return destination, sha256_file(destination)

    metadata_json = stable_json(metadata)
    safe_metadata, metadata_redactions = redact_text(metadata_json)
    if metadata_redactions or safe_metadata != metadata_json:
        raise SupportBundleError("support metadata contains secret-like content")
    records: list[tuple[str, bytes]] = []
    names: set[str] = set()
    total = 0
    for source in source_files:
        path = source.resolve()
        if not any(
            path == root.resolve() or root.resolve() in path.parents for root in allowed_roots
        ):
            raise SupportBundleError("support source is outside allowlist")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 5 * 1024 * 1024:
            raise SupportBundleError("support source is unsafe")
        raw = path.read_text(encoding="utf-8", errors="replace")
        safe, _ = redact_text(raw)
        data = safe.encode("utf-8")
        if path.name in names:
            raise SupportBundleError("support source basenames collide")
        names.add(path.name)
        total += len(data)
        if total > 20 * 1024 * 1024:
            raise SupportBundleError("support bundle exceeds size limit")
        records.append((path.name, data))
    if not records:
        raise SupportBundleError("support bundle requires diagnostic evidence")
    manifest = {
        "schema_version": "1.0",
        "incident_id": incident_id,
        "created_at": utc_now(),
        "metadata": metadata,
        "files": [
            {"name": name, "digest": sha256_text(data.decode("utf-8")), "size": len(data)}
            for name, data in records
        ],
    }
    manifest_digest = sha256_text(stable_json(manifest))
    manifest["manifest_digest"] = manifest_digest
    destination = output_root / f"support-{incident_id}-{manifest_digest[:16]}.zip"
    try:
        # ZipFile's exclusive mode performs the O_EXCL create itself.  Making an
        # empty file read-only before ZipFile opens it breaks on Windows and
        # creates an unnecessary write-after-create race on Linux.
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            for name, data in records:
                archive.writestr(f"evidence/{name}", data)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    destination.chmod(0o440)
    return destination, sha256_file(destination)
