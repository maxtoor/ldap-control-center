#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$ROOT_DIR/backups/update-$TIMESTAMP"
DO_BACKUP=1
DO_DRY_RUN=0

usage() {
  cat <<'EOF'
Uso:
  scripts/update_stack.sh [--skip-backup] [--dry-run]

Opzioni:
  --skip-backup   Non esegue backup LDAP prima dell'aggiornamento.
  --dry-run       Stampa i comandi senza eseguirli.
EOF
}

run() {
  if [[ "$DO_DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
    return 0
  fi
  echo "[run] $*"
  "$@"
}

run_redirect() {
  local output_file="$1"
  shift
  if [[ "$DO_DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $* > $output_file"
    return 0
  fi
  echo "[run] $* > $output_file"
  "$@" > "$output_file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-backup)
      DO_BACKUP=0
      shift
      ;;
    --dry-run)
      DO_DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Argomento non riconosciuto: $1" >&2
      usage
      exit 2
      ;;
  esac
done

echo "== LDAP Control Center: update stack =="
echo "Root: $ROOT_DIR"

if [[ "$DO_BACKUP" -eq 1 ]]; then
  echo "== Backup LDAP =="
  run mkdir -p "$BACKUP_DIR"
  run_redirect "$BACKUP_DIR/ldap-data.ldif" docker compose exec -T openldap sh -lc "slapcat -n 1"
  run_redirect "$BACKUP_DIR/ldap-config.ldif" docker compose exec -T openldap sh -lc "slapcat -n 0"
  echo "Backup completato in: $BACKUP_DIR"
else
  echo "== Backup LDAP saltato =="
fi

echo "== Pull immagini =="
run docker compose pull openldap phpldapadmin

echo "== Aggiornamento servizi uno per volta =="
run docker compose up -d --force-recreate openldap
run docker compose up -d --force-recreate phpldapadmin
run docker compose up -d --force-recreate app

echo "== Smoke test =="
run docker compose exec -T app python - <<'PY'
import urllib.request

checks = [
    "http://127.0.0.1:8000/login",
    "http://127.0.0.1:8000/password/forgot",
]
for url in checks:
    with urllib.request.urlopen(url, timeout=10) as resp:
        print(url, resp.status)
PY

echo "== Stato finale =="
run docker compose ps
echo "Update completato."
