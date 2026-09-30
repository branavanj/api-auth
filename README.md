# Auth API

API d'authentification en FastAPI : mot de passe et double authentification obligatoire.

- **Second facteur par défaut** : un code à 6 chiffres envoyé par email.
- **Second facteur renforcé** : une app TOTP (Google Authenticator, 1Password, etc.) avec 10 codes de secours. Une fois le TOTP activé, le code par email n'est plus accepté.

## Démarrage

```bash
./scripts/generate-env.sh          # crée .env avec des secrets aléatoires
docker compose up -d               # Postgres + Redis + Mailpit
```

Ensuite, au choix :

```bash
# API en local, avec rechargement automatique du code
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload

# ou tout dans Docker
docker compose --profile api up --build
```

- API et documentation interactive : http://localhost:8000/docs
- État de santé : http://localhost:8000/health/ready
- Emails reçus en local (Mailpit) : http://localhost:8025

Les ports ne sont ouverts que sur `127.0.0.1`.

## Infrastructure

| Service | Image | Port local | Données |
|---|---|---|---|
| PostgreSQL | `postgres:17-alpine` | 5432 | volume `pgdata` |
| Redis | `redis:7-alpine` | 6379 | volume `redisdata` (AOF + snapshots) |
| Mailpit | `axllent/mailpit` | 1025 (SMTP), 8025 (web) | – |
| API | image construite depuis `Dockerfile` | 8000 | – |

### PostgreSQL

Le schéma est créé au **premier démarrage** (volume vide) par [`db/init/`](db/init/) :

- `01-roles.sh` crée le rôle `auth_app`, utilisé par l'API ;
- `02-schema.sql` crée le schéma `auth`, les tables, les contraintes, les index et les droits.

| Rôle | Droits |
|---|---|
| `auth_admin` | Propriétaire, pour l'administration et les migrations |
| `auth_app` | `SELECT/INSERT/UPDATE/DELETE` sur les tables uniquement, aucun `CREATE`/`DROP`/`ALTER` |

Tables du schéma `auth` :

- **`users`** : identifiants, `password_hash` (Argon2), `totp_secret` (chiffré), `token_version`, `created_at`/`updated_at` (mis à jour par un trigger).
  - Contraintes : username en minuscules et au bon format, email en minuscules, hash forcément Argon2, TOTP actif seulement avec un secret.
- **`backup_codes`** : `code_hash` (HMAC hexadécimal), `used_at`, suppression en cascade avec l'utilisateur, un code unique par utilisateur.
- **`schema_migrations`** : versions du schéma appliquées.

Les scripts d'init ne tournent qu'une fois. Pour repartir de zéro en local (⚠️ **cela efface les données**) :

```bash
docker compose down -v && docker compose up -d
```

Se connecter à la base :

```bash
docker compose exec postgres psql -U auth_admin -d auth -c '\dt auth.*'
```

### Redis

Redis est protégé par un mot de passe et conserve ses données sur disque. Si sa mémoire est pleine, il refuse les nouvelles écritures au lieu d'effacer des sessions ou des compteurs en silence (`noeviction`). `FLUSHALL`, `FLUSHDB` et `DEBUG` sont désactivées.

Toutes les clés expirent d'elles-mêmes. Aucun code ni token n'y est stocké en clair : les clés utilisent un HMAC du token.

| Clé | Type | Contenu | Durée de vie |
|---|---|---|---|
| `code:verify_email:<user_id>` | hash | HMAC du code, tentatives | 10 min |
| `mfa:<hmac(token)>` | hash | user_id, tentatives, HMAC du code email | 5 min |
| `refresh:<hmac(token)>` | string | `{uid, ver}` | 7 j |
| `refresh:used:<hmac(token)>` | string | user_id (détection de rejeu) | 7 j |
| `totp:used:<user_id>:<pas>` | string | anti-rejeu TOTP | 2 min |
| `rl:<route>:<ip ou user>` | string | compteur de rate limiting | fenêtre de la limite |

## Parcours

```
POST /auth/register          {username, email, password}   → code envoyé par email
POST /auth/verify-email      {email, code}
POST /auth/login             {username, password}          → {mfa_token, methods}
POST /auth/2fa/verify        {mfa_token, method, code}     → {access_token, refresh_token}
                             (+ "use_cookie": true → refresh token en cookie httpOnly, absent du JSON)
GET  /me                     Authorization: Bearer <access_token>
```

### Toutes les routes

| Route | Auth | Rôle |
|---|---|---|
| `POST /auth/register` | – | Crée le compte et envoie le code de vérification |
| `POST /auth/verify-email` | – | Valide l'adresse email |
| `POST /auth/verify-email/resend` | – | Renvoie le code (réponse identique que le compte existe ou non) |
| `POST /auth/login` | – | Étape 1 : vérifie le mot de passe et renvoie un `mfa_token` valable 5 min |
| `POST /auth/2fa/resend` | mfa_token | Renvoie le code de connexion par email |
| `POST /auth/2fa/verify` | mfa_token | Étape 2 : `email`, `totp` ou `backup_code` ; renvoie les tokens |
| `POST /auth/refresh` | refresh (corps ou cookie) | Rotation du refresh token, réponse sur le même canal |
| `POST /auth/logout` | refresh (corps ou cookie) | Révoque ce refresh token et efface le cookie |
| `POST /auth/logout-all` | bearer | Invalide toutes les sessions |
| `GET /me` | bearer | Profil |
| `POST /me/password` | bearer | Change le mot de passe et déconnecte partout |
| `POST /2fa/totp/setup` | bearer | Génère le secret et l'URI `otpauth://` (à afficher en QR code côté client) |
| `POST /2fa/totp/enable` | bearer | Active le TOTP avec un premier code et renvoie 10 codes de secours |
| `POST /2fa/totp/disable` | bearer | Demande le mot de passe et un code TOTP ou de secours |
| `POST /2fa/backup-codes/regenerate` | bearer | Remplace les codes de secours |

## Santé

| Route | Rôle | Codes |
|---|---|---|
| `GET /health/live` | Le processus répond (liveness) | 200 |
| `GET /health/ready` | Postgres et Redis joignables, avec latence (readiness) | 200 / 503 |

```json
{"status": "degraded", "checks": {"database": {"status": "up", "latency_ms": 0.7}, "redis": {"status": "down", "error": "ConnectionError"}}}
```

Le conteneur Docker utilise `/health/ready` comme `HEALTHCHECK`. Si Redis ou Postgres tombe pendant une requête, l'API répond `503` avec `Retry-After`, et non une erreur 500.

## Journalisation

Les logs sont écrits sur la sortie standard, une ligne JSON par événement, prêts pour Loki, ELK ou Datadog. Le niveau se règle avec `LOG_LEVEL`.

- **`access`** : une ligne par requête (méthode, chemin, statut, durée, IP).
- **`audit`** : événements de sécurité (`login.failed`, `login.succeeded`, `mfa.failed`, `mfa.locked`, `session.refresh_reuse_detected`, `user.password_changed`, `mfa.totp_enabled`, `rate_limit.exceeded`, etc.).
- **`app`** : démarrage, arrêt et erreurs, avec la trace complète.

Chaque requête porte un `request_id`, repris de l'en-tête `X-Request-ID` ou généré, puis renvoyé dans la réponse. Il se retrouve sur toutes les lignes de la requête. Les mots de passe, codes et tokens ne sont jamais journalisés, et un test le vérifie.

```json
{"ts": "2026-09-30T01:07:15.744Z", "level": "WARNING", "logger": "audit", "msg": "login.failed", "request_id": "demo-1", "event": "login.failed", "reason": "bad_password", "user_id": 3, "ip": "203.0.113.7"}
```

## Sécurité

| Sujet | Mesure |
|---|---|
| Mots de passe | Argon2id, 12 caractères minimum, re-hash automatique si les paramètres changent |
| Codes OTP | `secrets` (CSPRNG), stockés en HMAC-SHA256 avec une clé secrète, TTL, 5 tentatives maximum, usage unique atomique |
| TOTP | Secret chiffré en base (Fernet), tolérance de ±30 s, anti-rejeu (un code ne sert qu'une fois) |
| Codes de secours | 10 codes d'environ 49 bits, stockés en HMAC, usage unique |
| Sessions | Access JWT de 15 min + refresh opaque rotatif (7 j). Un refresh réutilisé révoque toutes les sessions |
| Révocation | `token_version` par utilisateur (changement de mot de passe, logout-all, vol détecté) |
| Énumération | Même réponse 401 pour un utilisateur inconnu ou un mauvais mot de passe, même temps de réponse, renvoi du code sans fuite |
| Force brute | Rate limiting Redis sur login, inscription, envoi de codes et gestion de la 2FA |
| Erreurs | Aucune exception interne renvoyée au client, échecs SMTP journalisés en tâche de fond |
| Clés | Clés JWT et HMAC dérivées de `SECRET_KEY` (séparation des usages) |

À faire avant la prod :
- pour faire évoluer le schéma, ajouter un outil de migration (Alembic, ou des fichiers SQL numérotés appliqués par `auth_admin` et suivis dans `auth.schema_migrations`) ;
- servir derrière HTTPS ;
- derrière un reverse proxy, définir `FORWARDED_ALLOW_IPS` avec son IP pour que le rate limiting voie la vraie IP client ;
- pour un client navigateur : `use_cookie: true` place le refresh token dans un cookie `httpOnly` (`COOKIE_SECURE`, `REFRESH_COOKIE_PATH` à adapter).

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

Les tests utilisent SQLite en mémoire, fakeredis et une fausse boîte mail : aucun service externe n'est nécessaire.
