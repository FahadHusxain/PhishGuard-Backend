#!/usr/bin/env sh
set -eu

compose_env_file="${PHISHGUARD_COMPOSE_ENV_FILE:-.env.compose}"
backup_dir="${1:-backups}"

if [ ! -f "$compose_env_file" ]; then
    echo "Missing $compose_env_file. Copy .env.compose.example first." >&2
    exit 1
fi

mkdir -p "$backup_dir"
umask 077
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_path="$backup_dir/phishguard-$timestamp.dump"

docker compose --env-file "$compose_env_file" exec -T database \
    sh -c 'pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format=custom' \
    > "$backup_path"

if [ ! -s "$backup_path" ]; then
    echo "Backup failed or produced an empty file: $backup_path" >&2
    exit 1
fi

echo "Backup created: $backup_path"
