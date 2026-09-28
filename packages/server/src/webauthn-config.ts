import { isIP } from 'node:net';

/**
 * Where passkeys are valid. WebAuthn binds every credential to the RP ID (a
 * domain) and every signature to the page origin that asked for it, so these
 * decide which sites can register and use passkeys for this server.
 */
export interface WebAuthnConfig {
  /** WEBAUTHN_RP_ID: the domain passkeys are scoped to, e.g. `vault.example.com`. */
  rpId: string;
  /** WEBAUTHN_RP_NAME: shown by the browser and authenticator. */
  rpName: string;
  /** WEBAUTHN_ORIGINS: exact origins of the web vault, e.g. `https://vault.example.com`. */
  origins: string[];
}

const DEFAULT_RP_NAME = 'VaultX';
const MAX_RP_NAME_LENGTH = 64;
const HOSTNAME_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

const isLocalhost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname.endsWith('.localhost');

function parseRpId(raw: string | undefined): string {
  const name = 'WEBAUTHN_RP_ID';
  const rpId = raw?.trim() ?? '';
  if (!rpId) {
    throw new Error(
      `${name} is not set. Set it to the domain the web vault is served from, e.g. vault.example.com (see .env.example).`,
    );
  }
  // WebAuthn only accepts a bare domain: no scheme, port, path or IP address.
  if (
    rpId !== rpId.toLowerCase() ||
    rpId.length > 253 ||
    isIP(rpId) !== 0 ||
    !rpId.split('.').every((label) => HOSTNAME_LABEL.test(label))
  ) {
    throw new Error(
      `${name} must be a lowercase domain name with no scheme, port or path (got "${rpId}").`,
    );
  }
  return rpId;
}

function parseOrigins(raw: string | undefined, rpId: string): string[] {
  const name = 'WEBAUTHN_ORIGINS';
  const entries = (raw ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (entries.length === 0) {
    throw new Error(
      `${name} is not set. Set it to the web vault's origin, e.g. https://vault.example.com.`,
    );
  }
  for (const entry of entries) {
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new Error(`${name} entry "${entry}" is not a URL.`);
    }
    if (url.origin !== entry) {
      throw new Error(
        `${name} entry "${entry}" must be an origin only (scheme, host, optional port), with no path or trailing slash.`,
      );
    }
    // Plain HTTP only for local development: browsers treat localhost as a
    // secure context, and nothing else.
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost(url.hostname))) {
      throw new Error(
        `${name} entry "${entry}" must use https (http is allowed for localhost only).`,
      );
    }
    if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`)) {
      throw new Error(
        `${name} entry "${entry}" is not on WEBAUTHN_RP_ID "${rpId}" or one of its subdomains, so browsers would refuse it.`,
      );
    }
  }
  return [...new Set(entries)];
}

function parseRpName(raw: string | undefined): string {
  const rpName = raw?.trim() || DEFAULT_RP_NAME;
  if (rpName.length > MAX_RP_NAME_LENGTH || /\p{Cc}/u.test(rpName)) {
    throw new Error(
      `WEBAUTHN_RP_NAME must be at most ${MAX_RP_NAME_LENGTH} characters, with no control characters.`,
    );
  }
  return rpName;
}

/** Reads and checks the WebAuthn settings; throws with a clear message if they're unusable. */
export function parseWebAuthnConfig(env: NodeJS.ProcessEnv): WebAuthnConfig {
  const rpId = parseRpId(env.WEBAUTHN_RP_ID);
  return {
    rpId,
    rpName: parseRpName(env.WEBAUTHN_RP_NAME),
    origins: parseOrigins(env.WEBAUTHN_ORIGINS, rpId),
  };
}
