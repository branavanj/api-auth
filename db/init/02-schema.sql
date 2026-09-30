-- Schéma de l'API d'authentification (version 1).
-- Exécuté au premier démarrage du conteneur postgres, en tant que POSTGRES_USER.

BEGIN;

CREATE SCHEMA auth;

-- Suivi des versions du schéma appliquées.
CREATE TABLE auth.schema_migrations (
    version     integer     PRIMARY KEY,
    description text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth.users (
    id             bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username       varchar(32)  NOT NULL,
    email          varchar(254) NOT NULL,
    password_hash  varchar(255) NOT NULL,
    email_verified boolean      NOT NULL DEFAULT false,
    -- Secret TOTP chiffré par l'application (Fernet), jamais en clair.
    totp_secret    varchar(255),
    totp_enabled   boolean      NOT NULL DEFAULT false,
    -- Incrémenté pour révoquer tous les tokens de l'utilisateur.
    token_version  integer      NOT NULL DEFAULT 0,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    updated_at     timestamptz  NOT NULL DEFAULT now(),

    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_email_key    UNIQUE (email),
    CONSTRAINT users_username_format  CHECK (username ~ '^[a-z0-9_.-]{3,32}$'),
    CONSTRAINT users_email_lowercase  CHECK (email = lower(email)),
    CONSTRAINT users_password_argon2  CHECK (password_hash LIKE '$argon2%'),
    CONSTRAINT users_totp_has_secret  CHECK (NOT totp_enabled OR totp_secret IS NOT NULL),
    CONSTRAINT users_token_version_ok CHECK (token_version >= 0)
);

CREATE TABLE auth.backup_codes (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint      NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    -- HMAC-SHA256 hexadécimal du code, jamais le code lui-même.
    code_hash  char(64)    NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT backup_codes_user_code_key UNIQUE (user_id, code_hash),
    CONSTRAINT backup_codes_hash_format   CHECK (code_hash ~ '^[0-9a-f]{64}$')
);

-- Compter / lister rapidement les codes encore valables d'un utilisateur.
CREATE INDEX backup_codes_unused_idx ON auth.backup_codes (user_id) WHERE used_at IS NULL;

-- updated_at maintenu par la base, quel que soit le client qui écrit.
CREATE FUNCTION auth.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION auth.touch_updated_at();

INSERT INTO auth.schema_migrations (version, description) VALUES (1, 'Schéma initial');

-- Droits : l'API ne peut que lire et écrire des lignes.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.users, auth.backup_codes TO auth_app;
GRANT SELECT ON auth.schema_migrations TO auth_app;
ALTER ROLE auth_app SET search_path = auth;

DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO auth_app', current_database());
END;
$$;

COMMIT;
