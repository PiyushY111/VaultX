-- WebAuthn (passkeys) as a phishing-resistant second factor for logging in.
--
-- Nothing here is secret: a credential's public key can only verify
-- signatures, and challenges are random values handed to the client. Like
-- TOTP, passkeys guard logging in to the server, not the vault's encryption.

CREATE TABLE webauthn_credentials (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- Chosen by the authenticator; at most 1023 bytes (WebAuthn §5.1.3).
  -- Unique across all users, so one authenticator credential can't be
  -- registered to two accounts.
  credential_id bytea       NOT NULL UNIQUE
                            CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
  -- COSE-encoded public key.
  public_key    bytea       NOT NULL CHECK (octet_length(public_key) BETWEEN 1 AND 2048),
  -- The authenticator's signature counter (32 bits). Many passkeys always
  -- report 0; when it's non-zero it must go up, or the passkey may be cloned.
  sign_counter  bigint      NOT NULL DEFAULT 0
                            CHECK (sign_counter BETWEEN 0 AND 4294967295),
  transports    text[]      NOT NULL DEFAULT '{}',
  name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);

CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);

-- Challenges for one registration, login or re-authentication: single-use
-- (deleted when used), short-lived, and bound to the user and the purpose,
-- so a challenge issued for one of them can't be spent on another.
CREATE TABLE webauthn_challenges (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  purpose    text        NOT NULL CHECK (purpose IN ('register', 'login', 'reauth')),
  challenge  bytea       NOT NULL UNIQUE CHECK (octet_length(challenge) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX webauthn_challenges_user_purpose_idx ON webauthn_challenges (user_id, purpose);
CREATE INDEX webauthn_challenges_expires_at_idx ON webauthn_challenges (expires_at);

-- "Require passkey": when set, TOTP codes no longer count as a second factor
-- (for logging in or re-authenticating), since they can be phished.
-- Recovery codes still work. The server only sets it while the account has
-- a passkey.
ALTER TABLE users ADD COLUMN webauthn_required boolean NOT NULL DEFAULT false;
