/**
 * The web vault's Content Security Policy, delivered as a <meta> tag in
 * production builds (the dev server needs inline scripts for hot reloading).
 *
 * - 'wasm-unsafe-eval' lets libsodium compile its WebAssembly; nothing else
 *   may be evaluated.
 * - connect-src allows Have I Been Pwned's range API, for the opt-in breach
 *   check (5-character hash prefixes only).
 * - require-trusted-types-for 'script' turns off every string-to-code DOM
 *   sink (innerHTML, script.src, new Worker(string), …) unless the value
 *   comes from a Trusted Types policy; `trusted-types` allows exactly one
 *   policy, which only ever returns the KDF worker's own URL (see
 *   src/vault/kdf.ts). Browsers without Trusted Types ignore both.
 *
 * A <meta> CSP can't carry frame-ancestors, report-uri or sandbox; set those
 * as HTTP headers on the reverse proxy (see packages/web/README.md).
 */
export const TRUSTED_TYPES_POLICY = 'vaultx-kdf-worker';

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "connect-src 'self' https://api.pwnedpasswords.com",
  "img-src 'self' data:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "require-trusted-types-for 'script'",
  `trusted-types ${TRUSTED_TYPES_POLICY}`,
].join('; ');
