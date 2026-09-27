-- Per-account throttling of failed logins (see src/login-throttle.ts).
--
-- Keyed by the normalized email as submitted, whether or not an account
-- exists, so throttle responses can't be used to discover registered emails.
-- Rows are short-lived: they're removed on a successful login or once their
-- window has passed.

CREATE TABLE login_failures (
  email             text        PRIMARY KEY,
  -- Attempts in the current window that have not (yet) succeeded.
  failure_count     integer     NOT NULL CHECK (failure_count > 0),
  window_started_at timestamptz NOT NULL
);

CREATE INDEX login_failures_window_started_at_idx ON login_failures (window_started_at);
