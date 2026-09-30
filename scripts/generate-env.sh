#!/bin/sh
# Crée .env à partir de .env.example avec des secrets aléatoires.
set -eu
cd "$(dirname "$0")/.."

if [ -e .env ] && [ "${1:-}" != "--force" ]; then
    echo ".env existe déjà (utiliser --force pour l'écraser)." >&2
    exit 1
fi

python3 - <<'PY'
import base64, os, re, secrets

values = {
    "SECRET_KEY": secrets.token_urlsafe(48),
    "TOTP_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),  # clé Fernet
    "POSTGRES_ADMIN_PASSWORD": secrets.token_hex(24),
    "APP_DB_PASSWORD": secrets.token_hex(24),
    "REDIS_PASSWORD": secrets.token_hex(24),
}

text = open(".env.example", encoding="utf-8").read()
for key, value in values.items():
    text = re.sub(rf"^{key}=.*$", f"{key}={value}", text, flags=re.M)
    text = text.replace(f"<{key}>", value)

fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(text)
PY

echo ".env créé (droits 600)."
