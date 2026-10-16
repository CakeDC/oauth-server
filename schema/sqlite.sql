CREATE TABLE IF NOT EXISTS oauth_clients (
    id CHAR(36) NOT NULL PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_id_hash CHAR(64) NOT NULL UNIQUE,
    type VARCHAR(20) NOT NULL,
    application_type VARCHAR(10) NOT NULL,
    name VARCHAR(255) NOT NULL,
    client_uri TEXT NULL,
    logo_uri TEXT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    scopes TEXT NULL,
    token_endpoint_auth_method VARCHAR(30) NOT NULL,
    secret_hash CHAR(64) NULL,
    allow_introspection BOOLEAN NOT NULL DEFAULT 0,
    metadata TEXT NULL,
    metadata_fetched_at DATETIME NULL,
    metadata_expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created DATETIME NOT NULL,
    modified DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id CHAR(36) NOT NULL PRIMARY KEY,
    code_hash CHAR(64) NOT NULL UNIQUE,
    oauth_client_id CHAR(36) NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    subject VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    resource TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    family_id CHAR(36) NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id CHAR(36) NOT NULL PRIMARY KEY,
    token_hash CHAR(64) NOT NULL UNIQUE,
    type VARCHAR(10) NOT NULL,
    family_id CHAR(36) NOT NULL,
    parent_id CHAR(36) NULL,
    oauth_client_id CHAR(36) NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    subject VARCHAR(255) NOT NULL,
    subject_type VARCHAR(10) NOT NULL,
    resource TEXT NOT NULL,
    scopes TEXT NOT NULL,
    name VARCHAR(255) NULL,
    expires_at DATETIME NULL,
    used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    last_used_at DATETIME NULL,
    created DATETIME NOT NULL,
    modified DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_tokens_family_id ON oauth_tokens (family_id);

CREATE INDEX IF NOT EXISTS oauth_tokens_subject ON oauth_tokens (subject, type);

CREATE INDEX IF NOT EXISTS oauth_tokens_oauth_client_id ON oauth_tokens (oauth_client_id);

CREATE TABLE IF NOT EXISTS oauth_consents (
    id CHAR(36) NOT NULL PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    oauth_client_id CHAR(36) NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    resource_hash CHAR(64) NOT NULL,
    scopes TEXT NOT NULL,
    created DATETIME NOT NULL,
    modified DATETIME NOT NULL,
    UNIQUE (subject, oauth_client_id, resource_hash)
);
