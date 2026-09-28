-- Vault manifest and two-factor login.

-- The vault manifest: the client's encrypted list of every item id and
-- revision (see packages/crypto/src/manifest.ts). The server can't read it;
-- it only enforces that each write moves it to the next version, in the same
-- transaction as the item change. Version 0 means the vault has none yet.
ALTER TABLE users
  ADD COLUMN manifest_version   integer NOT NULL DEFAULT 0 CHECK (manifest_version >= 0),
  ADD COLUMN encrypted_manifest bytea   CHECK (octet_length(encrypted_manifest) >= 16),
  ADD COLUMN manifest_nonce     bytea   CHECK (octet_length(manifest_nonce) = 24),
  ADD CONSTRAINT users_manifest_complete CHECK (
    (manifest_version = 0) = (encrypted_manifest IS NULL)
    AND (encrypted_manifest IS NULL) = (manifest_nonce IS NULL)
  );

-- TOTP (RFC 6238) second factor for logging in. The server has to hold the
-- secret to check codes; it protects server access (logging in and
-- downloading ciphertext), not the vault's encryption, which never depends
-- on it. The last accepted time step is kept so a code can't be used twice.
ALTER TABLE users
  ADD COLUMN totp_secret         bytea  CHECK (octet_length(totp_secret) = 20),
  ADD COLUMN totp_pending_secret bytea  CHECK (octet_length(totp_pending_secret) = 20),
  ADD COLUMN totp_last_step      bigint NOT NULL DEFAULT 0;

-- One-time recovery codes for when the authenticator is lost. Only SHA-256
-- hashes are stored; a used code is deleted.
CREATE TABLE totp_recovery_codes (
  user_id   uuid  NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  PRIMARY KEY (user_id, code_hash)
);
