#!/usr/bin/env bash
set -euo pipefail

latest="$(ls -1 artifacts/backups/*.sql 2>/dev/null | tail -n 1 || true)"
if [[ -z "${latest}" ]]; then
  echo "No backups found under artifacts/backups/. Run: make backup"
  exit 1
fi

echo "Restoring latest backup: ${latest}"
docker exec -i "$(docker compose ps -q postgres-primary)" psql -U app -d appdb -c "drop schema public cascade; create schema public;"
docker exec -i "$(docker compose ps -q postgres-primary)" psql -U app -d appdb < "${latest}"
echo "Restore complete."
