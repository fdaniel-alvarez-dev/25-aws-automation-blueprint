#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/backups
ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="artifacts/backups/appdb-${ts}.sql"

echo "Creating logical backup to ${out}..."
docker exec -i "$(docker compose ps -q postgres-primary)" pg_dump -U app -d appdb > "${out}"

echo "Backup created."
