import { randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type pg from 'pg';
import type { WebAuthnConfig } from './webauthn-config.js';

/**
 * Passkeys (WebAuthn) as a second factor. The server keeps only public keys
 * and random challenges; nothing here can decrypt anything.
 *
 * Every ceremony uses a server-generated challenge stored in
 * `webauthn_challenges`, bound to one user and one purpose. A challenge is
 * deleted as it's checked (`DELETE … RETURNING`), so each works once, even
 * under concurrent requests, and it expires after CHALLENGE_TTL_SECONDS.
 */

export type ChallengePurpose = 'register' | 'login' | 'reauth';

export const CHALLENGE_TTL_SECONDS = 120;
const CHALLENGE_BYTES = 32;
/** Outstanding challenges kept per user and purpose; older ones are dropped. */
const MAX_OPEN_CHALLENGES = 5;
export const MAX_PASSKEYS_PER_USER = 10;

const TRANSPORTS: readonly AuthenticatorTransport[] = ['ble', 'hybrid', 'internal', 'nfc', 'usb'];

const toBase64Url = (bytes: Buffer): string => bytes.toString('base64url');
const BASE64URL = /^[A-Za-z0-9_-]*$/;

function fromBase64Url(value: string): Buffer | null {
  return BASE64URL.test(value) ? Buffer.from(value, 'base64url') : null;
}

type Db = pg.Pool | pg.PoolClient;

/** Stores a fresh challenge for `purpose` and returns it. */
async function issueChallenge(db: Db, userId: string, purpose: ChallengePurpose): Promise<Buffer> {
  const challenge = randomBytes(CHALLENGE_BYTES);
  // Housekeeping: expired challenges anywhere, and all but the newest few of
  // this user's for this purpose (so repeated requests can't pile them up).
  await db.query('DELETE FROM webauthn_challenges WHERE expires_at <= now()');
  await db.query(
    `DELETE FROM webauthn_challenges WHERE id IN (
       SELECT id FROM webauthn_challenges WHERE user_id = $1 AND purpose = $2
       ORDER BY created_at DESC OFFSET $3)`,
    [userId, purpose, MAX_OPEN_CHALLENGES - 1],
  );
  await db.query(
    `INSERT INTO webauthn_challenges (user_id, purpose, challenge, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
    [userId, purpose, challenge, CHALLENGE_TTL_SECONDS],
  );
  return challenge;
}

/**
 * Uses up a challenge: true only if it was issued to this user, for this
 * purpose, hasn't expired, and hasn't been used. Deleting it is what makes
 * it single-use.
 */
async function consumeChallenge(
  db: Db,
  userId: string,
  purpose: ChallengePurpose,
  challenge: string,
): Promise<boolean> {
  const bytes = fromBase64Url(challenge);
  if (!bytes || bytes.length !== CHALLENGE_BYTES) return false;
  const { rowCount } = await db.query(
    `DELETE FROM webauthn_challenges
     WHERE user_id = $1 AND purpose = $2 AND challenge = $3 AND expires_at > now()`,
    [userId, purpose, bytes],
  );
  return rowCount === 1;
}

interface CredentialRow {
  id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_counter: string;
  transports: string[];
}

const knownTransports = (transports: readonly string[] | undefined) =>
  (transports ?? []).filter((t): t is AuthenticatorTransport =>
    TRANSPORTS.includes(t as AuthenticatorTransport),
  );

async function userCredentials(db: Db, userId: string): Promise<CredentialRow[]> {
  const { rows } = await db.query<CredentialRow>(
    `SELECT id, credential_id, public_key, sign_counter, transports
     FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`,
    [userId],
  );
  return rows;
}

/** Options for navigator.credentials.get(), limited to this user's passkeys. */
export async function authenticationOptions(
  db: Db,
  config: WebAuthnConfig,
  userId: string,
  purpose: 'login' | 'reauth',
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const credentials = await userCredentials(db, userId);
  const challenge = await issueChallenge(db, userId, purpose);
  return generateAuthenticationOptions({
    rpID: config.rpId,
    challenge: new Uint8Array(challenge),
    timeout: CHALLENGE_TTL_SECONDS * 1000,
    // A PIN or biometric, not just a touch: the passkey is the second factor
    // on its own terms, not a presence check.
    userVerification: 'required',
    allowCredentials: credentials.map((row) => ({
      id: toBase64Url(row.credential_id),
      transports: knownTransports(row.transports),
    })),
  });
}

/** Options for navigator.credentials.create(). */
export async function registrationOptions(
  db: Db,
  config: WebAuthnConfig,
  user: { id: string; email: string },
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const existing = await userCredentials(db, user.id);
  const challenge = await issueChallenge(db, user.id, 'register');
  return generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpId,
    userName: user.email,
    // The account id, as the WebAuthn user handle: stable and not secret.
    userID: new Uint8Array(Buffer.from(user.id.replace(/-/g, ''), 'hex')),
    challenge: new Uint8Array(challenge),
    timeout: CHALLENGE_TTL_SECONDS * 1000,
    attestationType: 'none',
    excludeCredentials: existing.map((row) => ({
      id: toBase64Url(row.credential_id),
      transports: knownTransports(row.transports),
    })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
}

export interface VerifiedRegistration {
  credentialId: Buffer;
  publicKey: Buffer;
  counter: number;
  transports: AuthenticatorTransport[];
}

/**
 * Checks a new passkey's attestation: the challenge (issued to this user for
 * registration), origin, RP ID and user verification. Returns null if any of
 * them fail. Attestation statements aren't checked (`attestation: 'none'`):
 * any authenticator the user chooses is accepted.
 */
export async function verifyRegistration(
  db: Db,
  config: WebAuthnConfig,
  userId: string,
  response: RegistrationResponseJSON,
): Promise<VerifiedRegistration | null> {
  try {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge: (challenge) => consumeChallenge(db, userId, 'register', challenge),
      expectedOrigin: config.origins,
      expectedRPID: config.rpId,
      requireUserVerification: true,
    });
    if (!result.verified || !result.registrationInfo) return null;
    const { credential } = result.registrationInfo;
    return {
      credentialId: Buffer.from(credential.id, 'base64url'),
      publicKey: Buffer.from(credential.publicKey),
      counter: credential.counter,
      transports: knownTransports(credential.transports ?? response.response.transports),
    };
  } catch {
    // Malformed or failing responses: the library throws for both.
    return null;
  }
}

export type AssertionResult = 'ok' | 'invalid' | 'counter_regression';

/**
 * Checks a passkey assertion from `userId` for `purpose`. The credential must
 * belong to this user; the challenge must be this user's, for this purpose,
 * unexpired and unused; origin, RP ID and user verification must match; and
 * a non-zero signature counter must go up (a counter that doesn't suggests a
 * cloned authenticator, and the assertion is refused).
 */
export async function verifyAssertion(
  db: Db,
  config: WebAuthnConfig,
  userId: string,
  purpose: 'login' | 'reauth',
  response: AuthenticationResponseJSON,
): Promise<AssertionResult> {
  const credentialId = fromBase64Url(response.rawId);
  if (!credentialId || response.id !== response.rawId) return 'invalid';
  // Looked up by owner too, so another account's passkey never verifies here.
  const { rows } = await db.query<CredentialRow>(
    `SELECT id, credential_id, public_key, sign_counter, transports
     FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2`,
    [userId, credentialId],
  );
  const row = rows[0];
  if (!row) return 'invalid';
  const storedCounter = Number(row.sign_counter);

  let newCounter: number;
  try {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: (challenge) => consumeChallenge(db, userId, purpose, challenge),
      expectedOrigin: config.origins,
      expectedRPID: config.rpId,
      credential: {
        id: toBase64Url(row.credential_id),
        publicKey: new Uint8Array(row.public_key),
        counter: storedCounter,
        transports: knownTransports(row.transports),
      },
      requireUserVerification: true,
    });
    if (!result.verified || !result.authenticationInfo.userVerified) return 'invalid';
    newCounter = result.authenticationInfo.newCounter;
  } catch (error) {
    return /counter/i.test((error as Error).message) ? 'counter_regression' : 'invalid';
  }

  // Conditional, so two requests racing with the same counter can't both
  // pass (the challenge already stops exact replays).
  const { rowCount } = await db.query(
    `UPDATE webauthn_credentials SET sign_counter = $2, last_used_at = now()
     WHERE id = $1 AND (sign_counter < $2 OR (sign_counter = 0 AND $2 = 0))`,
    [row.id, newCounter],
  );
  return rowCount === 1 ? 'ok' : 'counter_regression';
}
