#!/usr/bin/env bash
#
# Nightly Neo4j backup (Community edition) via `neo4j-admin database dump`.
#
# Community has no online backup, so we briefly STOP the `neo4j` database, dump it,
# then START it again — the DBMS itself stays up (only that one database blips).
# Dumps are timestamped and pruned after RETENTION_DAYS.
#
# Schedule via cron (host crontab), e.g. nightly at 02:30:
#   30 2 * * * /path/to/magi/scripts/neo4j_backup.sh >> /var/log/magi-backup.log 2>&1
#
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
SERVICE="${NEO4J_SERVICE:-neo4j}"
DATABASE="${NEO4J_DATABASE:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-changeme}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

cd "$(dirname "$0")/.."
mkdir -p "${BACKUP_DIR}"

stamp="$(date +%Y%m%d-%H%M%S)"
container_out="/tmp/magi-backup"

echo "[$(date -Is)] Starting Neo4j backup of '${DATABASE}'"

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }
cypher() { compose exec -T "${SERVICE}" cypher-shell -u neo4j -p "${NEO4J_PASSWORD}" "$1"; }

# Stop the database, dump it, restart it (guard restart with a trap).
cypher "STOP DATABASE ${DATABASE};"
trap 'cypher "START DATABASE '"${DATABASE}"';" || true' EXIT

compose exec -T "${SERVICE}" sh -c "mkdir -p ${container_out} && neo4j-admin database dump ${DATABASE} --to-path=${container_out} --overwrite-destination"

# Copy the dump out of the container to the host backup dir.
cid="$(compose ps -q "${SERVICE}")"
docker cp "${cid}:${container_out}/${DATABASE}.dump" "${BACKUP_DIR}/${DATABASE}-${stamp}.dump"

echo "[$(date -Is)] Backup written: ${BACKUP_DIR}/${DATABASE}-${stamp}.dump"

# Retention: delete dumps older than RETENTION_DAYS.
find "${BACKUP_DIR}" -name "${DATABASE}-*.dump" -type f -mtime "+${RETENTION_DAYS}" -print -delete

echo "[$(date -Is)] Backup complete"
