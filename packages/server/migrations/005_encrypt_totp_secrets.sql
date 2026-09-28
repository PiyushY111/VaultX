-- Two-factor secrets encrypted at rest.
--
-- From here on, users.totp_secret and users.totp_pending_secret hold
-- AES-256-GCM ciphertexts (49 bytes: key id, nonce, ciphertext, tag; see
-- src/totp-secret-box.ts) under TOTP_ENCRYPTION_KEY, which lives in the
-- server's environment, not the database.
--
-- SQL can't do the encryption (the key isn't here), so this migration only
-- widens the constraints. The server encrypts any remaining 20-byte
-- plaintext secrets at startup, right after migrating and before it accepts
-- requests (prepareTotpSecrets in src/totp-reencrypt.ts), so the 20-byte
-- form is still allowed for rows written before this migration.
ALTER TABLE users
  DROP CONSTRAINT users_totp_secret_check,
  DROP CONSTRAINT users_totp_pending_secret_check,
  ADD CONSTRAINT users_totp_secret_check
    CHECK (octet_length(totp_secret) IN (20, 49)),
  ADD CONSTRAINT users_totp_pending_secret_check
    CHECK (octet_length(totp_pending_secret) IN (20, 49));
