#!/bin/sh
# Exécuté par l'image postgres au premier démarrage (volume vide) uniquement.
set -eu

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD doit être défini}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v app_password="$APP_DB_PASSWORD" <<'SQL'
-- Rôle utilisé par l'API : lecture/écriture des données, aucun droit sur la structure.
CREATE ROLE auth_app LOGIN PASSWORD :'app_password';
SQL
