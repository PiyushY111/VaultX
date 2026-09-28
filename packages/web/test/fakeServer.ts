import { createHash } from 'node:crypto';
import { vi } from 'vitest';

/**
 * In-memory stand-in for packages/server that records every request the app
 * makes, so tests can assert on exactly what crosses the network. It enforces
 * the same item-revision and session rules as the real server.
 */
export interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

interface StoredManifest {
  version: number;
  encrypted_data: string;
  nonce: string;
}

interface StoredUser {
  email: string;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyNonce: string;
  kdfSalt: string;
  kdfParams: unknown;
  manifest: StoredManifest | null;
  totpEnabled: boolean;
  recoveryCodes: string[];
  passkeys: StoredPasskey[];
  passkeyRequired: boolean;
}

export interface StoredPasskey {
  id: string;
  /** The credential id the fake authenticator returns (see fakePasskeyResponse). */
  credentialId: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

/**
 * What the fake WebAuthn browser API returns: the credential id, and the
 * server's challenge echoed back in clientDataJSON, as a real browser does.
 * The fake server checks the challenge was one it issued and hasn't been used.
 */
export function fakePasskeyResponse(credentialId: string, challenge: string) {
  const clientDataJSON = btoa(JSON.stringify({ challenge }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return {
    id: credentialId,
    rawId: credentialId,
    type: 'public-key' as const,
    clientExtensionResults: {},
    response: { clientDataJSON, authenticatorData: 'AA', signature: 'AA' },
  };
}

const challengeOf = (response: { response?: { clientDataJSON?: string } }): string | null => {
  try {
    const text = atob(response.response!.clientDataJSON!.replace(/-/g, '+').replace(/_/g, '/'));
    return (JSON.parse(text) as { challenge?: string }).challenge ?? null;
  } catch {
    return null;
  }
};

/** The fake's authenticator: this code is always valid when two-factor is on. */
export const FAKE_TOTP_CODE = '123456';
export const FAKE_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

export interface StoredItem {
  id: string;
  owner: string;
  revision: number;
  encrypted_data: string;
  nonce: string;
  created_at: string;
  updated_at: string;
}

interface StoredSession {
  id: string;
  owner: string;
  client: string | null;
  created_at: string;
}

export interface FakeServer {
  requests: RecordedRequest[];
  users: Map<string, StoredUser>;
  items: Map<string, StoredItem>;
  /** Keyed by bearer token. */
  sessions: Map<string, StoredSession>;
  expireAllSessions(): void;
  restore(): void;
  /** Passwords the fake Have I Been Pwned reports as breached, with their counts. */
  breached: Map<string, number>;
}

export function installFakeServer(): FakeServer {
  const requests: RecordedRequest[] = [];
  const users = new Map<string, StoredUser>();
  const items: FakeServer['items'] = new Map();
  const sessions: FakeServer['sessions'] = new Map();
  const breached: FakeServer['breached'] = new Map();
  let nextId = 1;
  /** Open passkey challenges: challenge → the user and purpose it was issued for. */
  const challenges = new Map<string, { email: string; purpose: 'login' | 'reauth' | 'register' }>();
  const issueChallenge = (email: string, purpose: 'login' | 'reauth' | 'register') => {
    const challenge = `challenge-${nextId++}`;
    challenges.set(challenge, { email, purpose });
    return challenge;
  };
  const requestOptions = (user: StoredUser, purpose: 'login' | 'reauth') => ({
    rpId: 'localhost',
    challenge: issueChallenge(user.email, purpose),
    allowCredentials: user.passkeys.map((p) => ({ id: p.credentialId, type: 'public-key' })),
    userVerification: 'required',
    timeout: 120_000,
  });
  const methodsOf = (user: StoredUser) => [
    ...(user.passkeys.length ? ['webauthn'] : []),
    ...(user.totpEnabled && !user.passkeyRequired ? ['totp'] : []),
    'recovery_code',
  ];
  const secondFactorDetails = (user: StoredUser, purpose: 'login' | 'reauth') => ({
    totp_required: true,
    second_factor_methods: methodsOf(user),
    ...(user.passkeys.length && { webauthn_options: requestOptions(user, purpose) }),
  });
  /** Checks and uses up a second factor the way the real server does; null if accepted. */
  const factorError = (
    user: StoredUser,
    factor: {
      webauthn?: { id: string; response?: { clientDataJSON?: string } };
      totp_code?: string;
      recovery_code?: string;
    },
    purpose: 'login' | 'reauth',
  ): string | null => {
    if (factor.webauthn) {
      const passkey = user.passkeys.find((p) => p.credentialId === factor.webauthn!.id);
      const challenge = challengeOf(factor.webauthn);
      const issued = challenge ? challenges.get(challenge) : undefined;
      if (challenge) challenges.delete(challenge);
      if (!passkey || issued?.email !== user.email || issued.purpose !== purpose) {
        return 'That passkey wasn’t accepted. Try again.';
      }
      passkey.last_used_at = new Date().toISOString();
      return null;
    }
    if (factor.totp_code) {
      if (user.passkeyRequired) return 'This account requires a passkey.';
      return user.totpEnabled && factor.totp_code === FAKE_TOTP_CODE
        ? null
        : 'That two-factor code is incorrect or was already used.';
    }
    const index = user.recoveryCodes.indexOf(factor.recovery_code ?? '');
    if (index === -1) return 'That two-factor code is incorrect or was already used.';
    user.recoveryCodes.splice(index, 1);
    return null;
  };
  const hasSecondFactor = (user: StoredUser) => user.totpEnabled || user.passkeys.length > 0;

  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const noContent = () => new Response(null, { status: 204 });
  const publicItem = (item: StoredItem) => {
    const { owner, ...rest } = item;
    void owner;
    return rest;
  };
  const unauthorized = () =>
    json(401, { statusCode: 401, error: 'Unauthorized', message: 'Unauthorized' });

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    const headers = Object.fromEntries(
      Object.entries((init.headers ?? {}) as Record<string, string>),
    );
    const bodyText = typeof init.body === 'string' ? init.body : '';
    requests.push({ method, url, headers, body: bodyText });

    // Have I Been Pwned's range API: every known hash suffix for a 5-character prefix.
    if (url.startsWith('https://api.pwnedpasswords.com/range/')) {
      const prefix = url.slice(-5).toUpperCase();
      const lines = [...breached]
        .map(
          ([password, count]) =>
            [createHash('sha1').update(password).digest('hex').toUpperCase(), count] as const,
        )
        .filter(([hash]) => hash.startsWith(prefix))
        .map(([hash, count]) => `${hash.slice(5)}:${count}`);
      // Padding entries, as the real service adds with Add-Padding.
      lines.push('0000000000000000000000000000000000A:0');
      return new Response(lines.join('\r\n'), { status: 200 });
    }
    const body = bodyText ? JSON.parse(bodyText) : {};
    const path = url.replace(/^\/api/, '');

    const token = (headers.authorization ?? '').replace(/^Bearer /, '');
    const owner = sessions.get(token)?.owner;
    const now = new Date().toISOString();

    if (method === 'POST' && path === '/signup') {
      if (users.has(body.email))
        return json(409, { message: 'An account with this email already exists' });
      users.set(body.email, {
        email: body.email,
        authHash: body.auth_hash,
        encryptedVaultKey: body.encrypted_vault_key,
        vaultKeyNonce: body.vault_key_nonce,
        kdfSalt: body.kdf_salt,
        kdfParams: body.kdf_params,
        manifest: null,
        totpEnabled: false,
        recoveryCodes: [],
        passkeys: [],
        passkeyRequired: false,
      });
      return json(201, { id: body.email });
    }
    if (method === 'POST' && path === '/prelogin') {
      const user = users.get(body.email);
      return json(200, {
        kdf_salt: user?.kdfSalt ?? 'AAAAAAAAAAAAAAAAAAAAAA==',
        kdf_params: user?.kdfParams ?? { memoryCost: 65536, iterations: 3, parallelism: 1 },
      });
    }
    if (method === 'POST' && path === '/login') {
      const user = users.get(body.email);
      if (!user || user.authHash !== body.auth_hash) {
        return json(401, { message: 'Invalid email or auth hash' });
      }
      if (hasSecondFactor(user)) {
        if (!body.webauthn && !body.totp_code && !body.recovery_code) {
          return json(401, {
            message: 'Enter the 6-digit code.',
            ...secondFactorDetails(user, 'login'),
          });
        }
        const error = factorError(user, body, 'login');
        if (error) {
          return json(401, {
            message: error,
            ...secondFactorDetails(user, 'login'),
            attempts_remaining: 4,
          });
        }
      }
      const newToken = `token-${nextId++}`;
      sessions.set(newToken, {
        id: crypto.randomUUID(),
        owner: user.email,
        client: body.client ?? null,
        created_at: now,
      });
      return json(200, {
        token: newToken,
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      });
    }
    if (!owner) return unauthorized();
    const user = users.get(owner)!;
    const reauthFails = (needsFactor: boolean) => {
      if (body.current_auth_hash !== user.authHash) {
        return json(403, { message: 'Current master password is incorrect.' });
      }
      if (needsFactor && hasSecondFactor(user)) {
        const error = factorError(user, body, 'reauth');
        if (error) return json(403, { message: error, ...secondFactorDetails(user, 'reauth') });
      }
      return null;
    };
    /** Applies the write's manifest if it's the next version, like the real server. */
    const manifestConflict = (manifest: StoredManifest | undefined) => {
      const current = user.manifest?.version ?? 0;
      if (!manifest || manifest.version !== current + 1) {
        return json(409, {
          message: 'Your vault was changed elsewhere.',
          manifest_version: current,
        });
      }
      return null;
    };
    const newCodes = () =>
      Array.from({ length: 10 }, (_, i) => `CODE${i}-${Math.random().toString(36).slice(2, 7)}`);

    if (method === 'GET' && path === '/account') {
      return json(200, {
        email: user.email,
        created_at: now,
        totp_enabled: user.totpEnabled,
        recovery_codes_remaining: user.recoveryCodes.length,
        passkeys: user.passkeys.length,
        passkey_required: user.passkeyRequired,
      });
    }
    if (method === 'POST' && path === '/account/passkeys/register/options') {
      const failed = reauthFails(true);
      if (failed) return failed;
      return json(200, {
        options: {
          rp: { id: 'localhost', name: 'VaultX' },
          user: { id: 'dXNlcg', name: user.email, displayName: '' },
          challenge: issueChallenge(user.email, 'register'),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          excludeCredentials: user.passkeys.map((p) => ({
            id: p.credentialId,
            type: 'public-key',
          })),
          authenticatorSelection: { userVerification: 'required' },
        },
      });
    }
    if (method === 'POST' && path === '/account/passkeys') {
      const challenge = challengeOf(body.response);
      const issued = challenge ? challenges.get(challenge) : undefined;
      if (challenge) challenges.delete(challenge);
      if (issued?.email !== user.email || issued.purpose !== 'register') {
        return json(400, { message: 'That passkey couldn’t be verified.' });
      }
      const first = !hasSecondFactor(user);
      const passkey: StoredPasskey = {
        id: crypto.randomUUID(),
        credentialId: body.response.id,
        name: body.name.trim(),
        created_at: now,
        last_used_at: null,
      };
      user.passkeys.push(passkey);
      if (first) user.recoveryCodes = newCodes();
      const { credentialId, ...info } = passkey;
      void credentialId;
      return json(201, {
        passkey: { ...info, transports: ['internal'] },
        ...(first && { recovery_codes: user.recoveryCodes }),
      });
    }
    if (method === 'GET' && path === '/account/passkeys') {
      return json(200, {
        passkeys: user.passkeys.map(({ credentialId, ...info }) => {
          void credentialId;
          return { ...info, transports: ['internal'] };
        }),
      });
    }
    const passkeyPath = /^\/account\/passkeys\/([0-9a-f-]{36})$/.exec(path);
    if (method === 'PATCH' && passkeyPath) {
      const passkey = user.passkeys.find((p) => p.id === passkeyPath[1]);
      if (!passkey) return json(404, { message: 'Passkey not found' });
      passkey.name = body.name.trim();
      return json(200, { passkey });
    }
    if (method === 'DELETE' && passkeyPath) {
      const passkey = user.passkeys.find((p) => p.id === passkeyPath[1]);
      if (!passkey) return json(404, { message: 'Passkey not found' });
      if (user.passkeyRequired && user.passkeys.length === 1) {
        return json(409, { message: 'Turn off “Require passkey” first.' });
      }
      const failed = reauthFails(true);
      if (failed) return failed;
      user.passkeys = user.passkeys.filter((p) => p !== passkey);
      if (!hasSecondFactor(user)) user.recoveryCodes = [];
      return noContent();
    }
    if (method === 'POST' && path === '/account/passkeys/reauth-options') {
      if (!user.passkeys.length) return json(409, { message: 'This account has no passkeys.' });
      return json(200, { options: requestOptions(user, 'reauth') });
    }
    if (method === 'PUT' && path === '/account/passkeys/required') {
      if (body.required && !user.passkeys.length) {
        return json(409, { message: 'Add a passkey first.' });
      }
      const failed = reauthFails(true);
      if (failed) return failed;
      user.passkeyRequired = body.required;
      return noContent();
    }
    if (method === 'POST' && path === '/account/totp/setup') {
      if (user.totpEnabled)
        return json(409, { message: 'Two-factor authentication is already on.' });
      return json(200, {
        secret: FAKE_TOTP_SECRET,
        otpauth_uri: `otpauth://totp/VaultX:${encodeURIComponent(user.email)}?secret=${FAKE_TOTP_SECRET}&issuer=VaultX`,
      });
    }
    if (method === 'POST' && path === '/account/totp/enable') {
      // The new code proves the new app; an account with passkeys needs one of those too.
      const failed = reauthFails(false);
      if (failed) return failed;
      if (user.passkeys.length) {
        const { webauthn, recovery_code } = body;
        const error = factorError(user, { webauthn, recovery_code }, 'reauth');
        if (error) return json(403, { message: error, ...secondFactorDetails(user, 'reauth') });
      }
      if (body.totp_code !== FAKE_TOTP_CODE)
        return json(403, { message: 'That code doesn’t match.' });
      user.totpEnabled = true;
      user.recoveryCodes = newCodes();
      return json(200, { recovery_codes: user.recoveryCodes });
    }
    if (method === 'POST' && path === '/account/totp/disable') {
      const failed = reauthFails(true);
      if (failed) return failed;
      user.totpEnabled = false;
      if (!user.passkeys.length) user.recoveryCodes = [];
      return noContent();
    }
    if (method === 'POST' && path === '/account/totp/recovery-codes') {
      const failed = reauthFails(true);
      if (failed) return failed;
      user.recoveryCodes = newCodes();
      return json(200, { recovery_codes: user.recoveryCodes });
    }
    if (method === 'DELETE' && path === '/account') {
      const failed = reauthFails(true);
      if (failed) return failed;
      users.delete(owner);
      for (const [id, item] of items) if (item.owner === owner) items.delete(id);
      for (const [t, s] of sessions) if (s.owner === owner) sessions.delete(t);
      return noContent();
    }
    if (method === 'PUT' && path === '/vault-manifest') {
      const conflict = manifestConflict(body);
      if (conflict) return conflict;
      user.manifest = body;
      return noContent();
    }

    if (method === 'POST' && path === '/logout') {
      sessions.delete(token);
      return noContent();
    }
    if (method === 'GET' && path === '/sessions') {
      const mine = [...sessions.entries()]
        .filter(([, s]) => s.owner === owner)
        .map(([t, s]) => ({
          id: s.id,
          client: s.client,
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/130.0 Safari/537.36',
          created_at: s.created_at,
          last_used_at: now,
          expires_at: now,
          current: t === token,
        }));
      return json(200, { sessions: mine });
    }
    if (method === 'DELETE' && path === '/sessions') {
      for (const [t, s] of sessions) if (s.owner === owner) sessions.delete(t);
      return noContent();
    }
    const sessionMatch = /^\/sessions\/(.+)$/.exec(path);
    if (method === 'DELETE' && sessionMatch) {
      const entry = [...sessions].find(([, s]) => s.id === sessionMatch[1] && s.owner === owner);
      if (!entry) return json(404, { message: 'Not found' });
      sessions.delete(entry[0]);
      return noContent();
    }
    if (method === 'POST' && path === '/account/password') {
      if (body.current_auth_hash !== user.authHash) {
        return json(403, { message: 'Current master password is incorrect.' });
      }
      const sent = body.items as StoredItem[];
      const mine = [...items.values()].filter((item) => item.owner === owner);
      const complete =
        sent.length === mine.length &&
        mine.every((item) =>
          sent.some((next) => next.id === item.id && next.revision === item.revision + 1),
        );
      if (!complete) return json(409, { message: 'Your vault changed while it was re-encrypted' });
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
      user.manifest = body.manifest;
      for (const next of sent) {
        Object.assign(items.get(next.id)!, {
          revision: next.revision,
          encrypted_data: next.encrypted_data,
          nonce: next.nonce,
          updated_at: now,
        });
      }
      Object.assign(user, {
        authHash: body.auth_hash,
        kdfSalt: body.kdf_salt,
        kdfParams: body.kdf_params,
        encryptedVaultKey: body.encrypted_vault_key,
        vaultKeyNonce: body.vault_key_nonce,
      });
      for (const [t, s] of sessions) if (s.owner === owner && t !== token) sessions.delete(t);
      return json(200, { items: sent.map((next) => publicItem(items.get(next.id)!)) });
    }

    if (method === 'GET' && path === '/vault-key') {
      return json(200, {
        encrypted_vault_key: user.encryptedVaultKey,
        vault_key_nonce: user.vaultKeyNonce,
        kdf_salt: user.kdfSalt,
        kdf_params: user.kdfParams,
      });
    }
    if (method === 'GET' && path === '/vault-items') {
      const mine = [...items.values()].filter((item) => item.owner === owner).map(publicItem);
      return json(200, { items: mine, manifest: user.manifest });
    }
    if (method === 'POST' && path === '/vault-items/batch') {
      if (body.items.length > 500 || body.items.some((i: StoredItem) => items.has(i.id)))
        return json(409, { message: 'Conflict' });
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
      user.manifest = body.manifest;
      const created = (body.items as StoredItem[]).map((fields) => {
        const item = { ...fields, owner, created_at: now, updated_at: now };
        items.set(item.id, item);
        return publicItem(item);
      });
      return json(201, { items: created });
    }
    if (method === 'POST' && path === '/vault-items') {
      if (body.revision !== 1 || items.has(body.id)) return json(409, { message: 'Conflict' });
      const { manifest, ...fields } = body;
      const conflict = manifestConflict(manifest);
      if (conflict) return conflict;
      user.manifest = manifest;
      const item = { ...fields, owner, created_at: now, updated_at: now };
      items.set(item.id, item);
      return json(201, publicItem(item));
    }
    const match = /^\/vault-items\/(.+)$/.exec(path);
    const existing = match ? items.get(decodeURIComponent(match[1]!)) : undefined;
    if (!existing || existing.owner !== owner) return json(404, { message: 'Not found' });
    if (method === 'PUT') {
      if (body.revision !== existing.revision + 1) {
        return json(409, {
          message: 'This item was changed elsewhere since it was loaded.',
          current_revision: existing.revision,
        });
      }
      const { manifest, ...fields } = body;
      const conflict = manifestConflict(manifest);
      if (conflict) return conflict;
      user.manifest = manifest;
      Object.assign(existing, fields, { updated_at: now });
      return json(200, publicItem(existing));
    }
    if (method === 'DELETE') {
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
      user.manifest = body.manifest;
      items.delete(existing.id);
      return noContent();
    }
    return json(404, { message: 'Not found' });
  });

  vi.stubGlobal('fetch', fetchMock);
  return {
    requests,
    users,
    items,
    sessions,
    breached,
    expireAllSessions: () => sessions.clear(),
    restore: () => vi.unstubAllGlobals(),
  };
}
