-- ConsentLedger: server-side token revocation for logout
-- Applied by Alembic revision 0003 (database/alembic/versions/0003_auth_tokens.py)
--
-- JWTs are stateless; to make logout effective before a token expires, the
-- token's id (jti) is recorded here and rejected by the API until it expires.

CREATE TABLE revoked_tokens (
    jti             UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > revoked_at - INTERVAL '1 day')
);

CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens (expires_at);

GRANT SELECT, INSERT, DELETE ON revoked_tokens TO consentledger_app;
