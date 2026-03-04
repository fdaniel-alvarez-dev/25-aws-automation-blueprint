#!/usr/bin/env bash
set -euo pipefail

echo "Checking replication status on primary..."
docker exec -i "$(docker compose ps -q postgres-primary)" psql -U app -d appdb -c "select application_name, state, sync_state, write_lag, flush_lag, replay_lag from pg_stat_replication;"

echo
echo "Checking replica is in recovery mode..."
docker exec -i "$(docker compose ps -q postgres-replica)" psql -U app -d appdb -c "select pg_is_in_recovery();"
