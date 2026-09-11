#!/usr/bin/env sh
set -eu

if [ "$#" -ne 2 ] || [ "$1" != "--confirm-replace-database" ]; then
    echo "Usage: $0 --confirm-replace-database BACKUP.dump" >&2
    echo "Warning: restoration replaces data in the Compose PostgreSQL database." >&2
    exit 2
fi

compose_env_file="${PHISHGUARD_COMPOSE_ENV_FILE:-.env.compose}"
backup_path="$2"

if [ ! -f "$compose_env_file" ]; then
    echo "Missing $compose_env_file. Copy .env.compose.example first." >&2
    exit 1
fi
if [ ! -s "$backup_path" ]; then
    echo "Backup file is missing or empty: $backup_path" >&2
    exit 1
fi

docker compose --env-file "$compose_env_file" stop web
docker compose --env-file "$compose_env_file" exec -T database \
    sh -c 'pg_restore --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --clean --if-exists --no-owner' \
    < "$backup_path"
docker compose --env-file "$compose_env_file" start web

echo "Database restored from: $backup_path"
