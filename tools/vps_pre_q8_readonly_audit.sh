#!/usr/bin/env bash
# Read-only source collection for the live Hermes PRE-Q8 plane.
# It never deletes state, stops services, edits SQLite, or prints credential values.
set -uo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
  printf 'Run as root: sudo bash %s\n' "$0" >&2
  exit 64
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROOT="/var/tmp/hermes-preq8-audit-${STAMP}"
ARCHIVE="${ROOT}.tar.gz"
mkdir -p "${ROOT}"/{identity,systemd,status,scenarios,journal,errors}
chmod 0700 "${ROOT}"

sanitize_stream() {
  python3 -c '
import re,sys
patterns = [
    (re.compile(r"(?i)\b(authorization|token|secret|password|passwd|api[_-]?key|cookie)(\s*[:=]\s*)(\S+)"), r"\1\2<REDACTED>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"), "<REDACTED_GITHUB_TOKEN>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "<REDACTED_API_KEY>"),
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b"), "<REDACTED_TELEGRAM_TOKEN>"),
    (re.compile(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@"), r"\1<REDACTED>@"),
]
for line in sys.stdin:
    for pattern,replacement in patterns:
        line = pattern.sub(replacement,line)
    sys.stdout.write(line)
'
}

capture() {
  local name="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    "$@"
  } >"${ROOT}/${name}.txt" 2>&1 || true
}

VPY="/opt/hermes-factory-verifier/venv/bin/python"
VROOT="/opt/hermes-factory-verifier/current"
CROOT="/opt/hermes-factory-candidate/current"
INDEX="/etc/hermes-factory/pre-q8/index.json"
CONTROL="/etc/hermes-factory/qualification-control.yaml"

capture identity/date date -u --iso-8601=seconds
capture identity/uname uname -a
capture identity/os-release cat /etc/os-release
capture identity/disk df -hT
capture identity/memory free -h
capture identity/current-links readlink -f /opt/hermes-factory-candidate/current /opt/hermes-factory-verifier/current
if [[ -d "${CROOT}/.git" ]]; then
  capture identity/candidate-git git -C "${CROOT}" rev-parse HEAD^{tree} HEAD
  capture identity/candidate-status git -C "${CROOT}" status --porcelain=v1 --untracked-files=all
fi
if [[ -d "${VROOT}/.git" ]]; then
  capture identity/verifier-git git -C "${VROOT}" rev-parse HEAD^{tree} HEAD
  capture identity/verifier-status git -C "${VROOT}" status --porcelain=v1 --untracked-files=all
fi

for path in "${INDEX}" "${CONTROL}" \
  /var/lib/hermes-factory-functional/q6-5/report-index.json; do
  if [[ -f "${path}" && ! -L "${path}" ]]; then
    safe_name="$(printf '%s' "${path}" | sed 's#[^A-Za-z0-9_.-]#_#g')"
    stat "${path}" >"${ROOT}/identity/${safe_name}.stat.txt" 2>&1 || true
    sha256sum "${path}" >"${ROOT}/identity/${safe_name}.sha256.txt" 2>&1 || true
  fi
done

if [[ -x "${VPY}" && -d "${VROOT}" ]]; then
  (
    cd "${VROOT}" || exit
    runuser -u hermesverifier -- "${VPY}" -m scripts.functional_qualification status
  ) 2>&1 | sanitize_stream >"${ROOT}/status/functional-status.json" || true
fi

capture systemd/aggregate-show systemctl show \
  hermes-factory-functional-qualification.service \
  hermes-factory-functional-qualification.timer \
  hermes-factory-pre-q8.service \
  -p Id -p LoadState -p ActiveState -p SubState -p Result \
  -p ExecMainCode -p ExecMainStatus -p NRestarts -p InvocationID \
  -p StateChangeTimestamp -p ActiveEnterTimestamp -p InactiveEnterTimestamp

capture systemd/jobs systemctl list-jobs --no-pager
capture systemd/failed systemctl --failed --no-pager
capture systemd/preq8-units systemctl list-units --all --no-pager --plain \
  'hermes-factory-pre-q8*' 'hermes-factory-golden*'

SCENARIO_ROWS="${ROOT}/status/scenario-index.tsv"
if [[ -f "${INDEX}" && -x "${VPY}" ]]; then
  "${VPY}" - "${INDEX}" >"${SCENARIO_ROWS}" <<'PY' 2>"${ROOT}/errors/index.txt" || true
import json,sys
from pathlib import Path
index = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in index.get("scenarios", []):
    print(
        str(item.get("scenario_id", "")),
        str(item.get("config_path", "")),
        str(item.get("database_path", "")),
        str(item.get("config_digest", "")),
        sep="\t",
    )
PY
fi

db_summary() {
  local snapshot="$1"
  python3 - "${snapshot}" <<'PY'
import json,sqlite3,sys
from pathlib import Path

path=Path(sys.argv[1])
out={"database":str(path),"exists":path.is_file()}
if not path.is_file():
    print(json.dumps(out,sort_keys=True))
    raise SystemExit(0)

connection=sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro",uri=True,timeout=20)
connection.row_factory=sqlite3.Row
try:
    connection.execute("PRAGMA query_only=ON")
    out["quick_check"]=str(connection.execute("PRAGMA quick_check").fetchone()[0])
    tables={str(row[0]) for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    out["tables"]=sorted(tables)
    def grouped(table,column):
        if table not in tables:
            return {}
        query=f'SELECT "{column}",COUNT(*) FROM "{table}" GROUP BY "{column}" ORDER BY "{column}"'
        return {str(row[0]):int(row[1]) for row in connection.execute(query)}
    out["product_statuses"]=grouped("products","status")
    out["task_statuses"]=grouped("tasks","status")
    out["failure_reason_codes"]=grouped("failures","reason_code")
    out["incident_statuses"]=grouped("controller_incidents","status")
    for table in (
        "completion_manifests","recovery_applications","side_effect_intents",
        "side_effect_receipts","path_decisions","attempts"
    ):
        if table in tables:
            out[f"{table}_count"]=int(
                connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            )
finally:
    connection.close()
print(json.dumps(out,sort_keys=True,indent=2))
PY
}

if [[ -s "${SCENARIO_ROWS}" ]]; then
  while IFS=$'\t' read -r scenario config database config_digest; do
    [[ "${scenario}" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || continue
    dest="${ROOT}/scenarios/${scenario}"
    mkdir -p "${dest}/db"
    {
      printf 'scenario_id=%s\nconfig_path=%s\ndatabase_path=%s\nconfig_digest=%s\n' \
        "${scenario}" "${config}" "${database}" "${config_digest}"
      [[ -f "${config}" ]] && stat "${config}" && sha256sum "${config}"
    } >"${dest}/identity.txt" 2>&1 || true

    for suffix in "" "-wal" "-shm"; do
      source_file="${database}${suffix}"
      if [[ -f "${source_file}" && ! -L "${source_file}" ]]; then
        cp --reflink=auto --preserve=mode,timestamps \
          "${source_file}" "${dest}/db/$(basename "${database}")${suffix}" \
          2>>"${ROOT}/errors/db-copy.txt" || true
      fi
    done
    snapshot="${dest}/db/$(basename "${database}")"
    db_summary "${snapshot}" >"${dest}/db-summary.json" 2>"${dest}/db-summary.err" || true

    for kind in controller worker scenario; do
      case "${kind}" in
        controller) unit="hermes-factory-pre-q8-controller@${scenario}.service" ;;
        worker) unit="hermes-factory-pre-q8-worker@${scenario}.service" ;;
        scenario) unit="hermes-factory-pre-q8@${scenario}.service" ;;
      esac
      systemctl show "${unit}" \
        -p Id -p LoadState -p ActiveState -p SubState -p Result \
        -p ExecMainCode -p ExecMainStatus -p NRestarts -p MainPID \
        -p InvocationID -p StateChangeTimestamp -p ActiveEnterTimestamp \
        -p InactiveEnterTimestamp >"${dest}/${kind}-unit.txt" 2>&1 || true
      journalctl -u "${unit}" -n 300 --no-pager -o short-iso-precise 2>&1 \
        | sanitize_stream >"${ROOT}/journal/${scenario}-${kind}.txt" || true
    done
  done <"${SCENARIO_ROWS}"
fi

find "${ROOT}" -type f -exec chmod 0600 {} +
{
  printf 'schema_version=1.0\n'
  printf 'created_at=%s\n' "${STAMP}"
  printf 'source_policy=read_only_no_state_deletion_no_sql_mutation\n'
  printf 'redaction=best_effort_allowlisted_operational_evidence\n'
} >"${ROOT}/AUDIT-METADATA.txt"
find "${ROOT}" -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum >"${ROOT}/MANIFEST.sha256"

tar -C "$(dirname "${ROOT}")" -czf "${ARCHIVE}" "$(basename "${ROOT}")"
chmod 0600 "${ARCHIVE}"
sha256sum "${ARCHIVE}" | tee "${ARCHIVE}.sha256"
printf 'AUDIT_ARCHIVE=%s\n' "${ARCHIVE}"
