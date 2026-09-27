-- Initial schema. The server stores only what clients send it: ciphertext,
-- nonces, KDF salt/params, and a server-side hash of the client's auth hash.
-- It never holds a master password, master key, or vault key in plaintext.

CREATE TABLE users (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email               text        NOT NULL UNIQUE
                                  CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  kdf_salt            bytea       NOT NULL CHECK (octet_length(kdf_salt) = 16),
  kdf_params          jsonb       NOT NULL CHECK (jsonb_typeof(kdf_params) = 'object'),
  -- SHA-256 of the client-derived authHash, never the authHash itself: a
  -- database leak must not let an attacker log in by replaying it.
  auth_hash           bytea       NOT NULL CHECK (octet_length(auth_hash) = 32),
  -- 32-byte vault key + 16-byte Poly1305 tag.
  encrypted_vault_key bytea       NOT NULL CHECK (octet_length(encrypted_vault_key) = 48),
  vault_key_nonce     bytea       NOT NULL CHECK (octet_length(vault_key_nonce) = 24),
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vault_items (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- Ciphertext with the 16-byte Poly1305 tag appended.
  encrypted_data bytea       NOT NULL CHECK (octet_length(encrypted_data) >= 16),
  -- Random 24-byte XChaCha20 nonces never collide in practice, so a duplicate
  -- means a buggy client reused one; reject it.
  nonce          bytea       NOT NULL UNIQUE CHECK (octet_length(nonce) = 24),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vault_items_user_id_idx ON vault_items (user_id);

CREATE TABLE sessions (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  -- SHA-256 of the bearer token; the token itself is only ever held by the client.
  token_hash bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  expires_at timestamptz NOT NULL
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
