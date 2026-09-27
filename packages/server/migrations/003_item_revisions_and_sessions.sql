-- Item revisions (rollback protection) and session management.

-- Clients now bind each item's ciphertext to its id and a revision counter
-- (both are in the AEAD associated data), and the server only accepts the
-- next revision. Rows written before this migration become revision 0,
-- which clients decrypt with the old, unbound format and re-save as 1.
ALTER TABLE vault_items
  ADD COLUMN revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE vault_items ALTER COLUMN revision DROP DEFAULT;

-- Enough to list a user's sessions and let them revoke one they don't
-- recognize. The user agent is stored as sent (truncated), like any web
-- server's access log would; nothing here is secret.
ALTER TABLE sessions
  ADD COLUMN created_at   timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN last_used_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN client       text        CHECK (client IN ('web', 'extension')),
  ADD COLUMN user_agent   text        CHECK (length(user_agent) <= 256);
