import {
  DEFAULT_KDF_PARAMS,
  DecryptionError,
  decryptVaultKey,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
  nextManifest,
  type VaultManifest,
} from '@password-manager/crypto';
import {
  ApiError,
  api,
  describeLoginFailure,
  needsSecondFactor,
  secondFactorChallenge,
  type SecondFactorChallenge,
  type ItemResponse,
  type SecondFactor,
} from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import { encryptNextRevision, toVaultItem, type VaultItem } from './items';
import { derivePasswordKeys, type PasswordKeys } from './kdf';
import { CLIENT_NAME, encryptManifestPayload } from './sync';

/**
 * An unlocked vault. Held in memory only — never written to localStorage,
 * sessionStorage, IndexedDB or cookies — and wiped by {@link lockSession}.
 */
export interface VaultSession {
  email: string;
  /** Bearer token for the API. Grants access to ciphertext only. */
  token: string;
  /** Decrypts and encrypts items. Never leaves this process. */
  vaultKey: Uint8Array;
}

export const MIN_MASTER_PASSWORD_LENGTH = 12;

/** Overwrites key material in place. JS can't guarantee no copies exist, but this removes the ones we hold. */
export function wipe(...buffers: Uint8Array[]): void {
  for (const buffer of buffers) buffer.fill(0);
}

/**
 * Wipes the vault key and drops the token. The server session is ended too
 * (best effort): unlocking logs in again anyway, so it would only linger.
 */
export function lockSession(session: VaultSession): void {
  const { token } = session;
  wipe(session.vaultKey);
  session.token = '';
  if (token) api.logout(token).catch(() => {});
}

export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

/**
 * Registers a new account. Only the email, KDF salt/params, authHash, and the
 * wrapped vault key are sent; the password and every derived key stay here.
 */
export async function signUp(emailInput: string, password: string): Promise<VaultSession> {
  const email = normalizeEmail(emailInput);
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new Error(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`);
  }
  const salt = await generateSalt();
  const kdfParams = { ...DEFAULT_KDF_PARAMS };
  const { stretchedMasterKey, authHash } = await derivePasswordKeys(password, salt, kdfParams);
  const vaultKey = await generateVaultKey();
  try {
    const wrapped = await encryptVaultKey(vaultKey, stretchedMasterKey);
    await api.signup({
      email,
      auth_hash: toBase64(authHash),
      encrypted_vault_key: toBase64(wrapped.ciphertext),
      vault_key_nonce: toBase64(wrapped.nonce),
      kdf_salt: toBase64(salt),
      kdf_params: kdfParams,
    });
    // We already hold the vault key, so log in with the same authHash rather
    // than running Argon2id a second time.
    const { token } = await api.login(email, toBase64(authHash));
    // This client just created the (empty) vault, so it can write the first
    // manifest without asking anyone to trust anything. If that fails, the
    // next load finds no manifest and asks the user to confirm the (empty)
    // vault as the baseline instead, so nothing is lost by carrying on.
    try {
      await api.putManifest(
        token,
        await encryptManifestPayload(nextManifest(null, {}, CLIENT_NAME), vaultKey),
      );
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
    }
    return { email, token, vaultKey };
  } catch (error) {
    wipe(vaultKey);
    throw error;
  } finally {
    wipe(stretchedMasterKey, authHash);
  }
}

/**
 * Thrown by {@link logIn} when the password is right but the account has
 * two-factor login on. It holds the keys derived from the password, so the
 * second factor can be sent without running Argon2id again; call `complete`
 * with it, or `cancel` to wipe them. They're wiped after five minutes anyway.
 */
export class SecondFactorRequiredError extends Error {
  private keys: PasswordKeys | null;
  private readonly timer: ReturnType<typeof setTimeout>;

  constructor(
    private readonly email: string,
    keys: PasswordKeys,
    message: string,
    /** Which factors the server accepts, and the current passkey challenge. */
    public challenge: SecondFactorChallenge,
  ) {
    super(message);
    this.name = 'SecondFactorRequiredError';
    this.keys = keys;
    this.timer = setTimeout(() => this.cancel(), 5 * 60_000);
  }

  /**
   * Sends the second factor. Throws (keeping the keys, to try again) if it's
   * refused; the server's reply to a refusal carries a fresh passkey
   * challenge, which replaces `challenge`.
   */
  async complete(factor: SecondFactor): Promise<VaultSession> {
    if (!this.keys) throw new Error('This sign-in expired. Enter your master password again.');
    try {
      const session = await finishLogIn(this.email, this.keys, factor);
      this.cancel();
      return session;
    } catch (error) {
      const cause = error instanceof Error ? error.cause : undefined;
      if (cause instanceof ApiError && needsSecondFactor(cause)) {
        this.challenge = secondFactorChallenge(cause);
      }
      throw error;
    }
  }

  cancel(): void {
    clearTimeout(this.timer);
    if (this.keys) wipe(this.keys.stretchedMasterKey, this.keys.authHash);
    this.keys = null;
  }
}

async function finishLogIn(
  email: string,
  { stretchedMasterKey, authHash }: PasswordKeys,
  factor?: SecondFactor,
): Promise<VaultSession> {
  let token: string;
  try {
    ({ token } = await api.login(email, toBase64(authHash), factor));
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 429)) {
      throw new Error(describeLoginFailure(error), { cause: error });
    }
    throw error;
  }
  const wrapped = await api.getVaultKey(token);
  const vaultKey = await decryptVaultKey(
    fromBase64(wrapped.encrypted_vault_key),
    fromBase64(wrapped.vault_key_nonce),
    stretchedMasterKey,
  );
  return { email, token, vaultKey };
}

/**
 * Logs in: fetches the KDF salt/params, re-derives keys locally, proves
 * knowledge of the password with the authHash, then unwraps the vault key.
 * Throws {@link SecondFactorRequiredError} if a two-factor code is needed.
 */
export async function logIn(emailInput: string, password: string): Promise<VaultSession> {
  const email = normalizeEmail(emailInput);
  const { kdf_salt, kdf_params } = await api.prelogin(email);
  // derivePasswordKeys rejects params below the crypto package's floor, so a
  // malicious server can't downgrade the KDF.
  const keys = await derivePasswordKeys(password, fromBase64(kdf_salt), kdf_params);
  let handedOff = false;
  try {
    return await finishLogIn(email, keys);
  } catch (error) {
    if (needsSecondFactor(error instanceof Error ? (error.cause ?? error) : error)) {
      handedOff = true;
      const cause = (error as Error).cause;
      throw new SecondFactorRequiredError(
        email,
        keys,
        (error as Error).message,
        cause instanceof ApiError
          ? secondFactorChallenge(cause)
          : { methods: ['totp', 'recovery_code'], webauthnOptions: null },
      );
    }
    throw error;
  } finally {
    if (!handedOff) wipe(keys.stretchedMasterKey, keys.authHash);
  }
}

export class WrongPasswordError extends Error {
  constructor(message = 'Current master password is incorrect.') {
    super(message);
    this.name = 'WrongPasswordError';
  }
}

/**
 * Re-derives the auth hash from the current master password, for account
 * changes that ask for it, after checking locally that the password is right
 * (it must unwrap the vault key), so a typo doesn't use up a login attempt.
 */
export async function proveCurrentPassword(
  session: VaultSession,
  password: string,
): Promise<string> {
  const wrapped = await api.getVaultKey(session.token);
  const { stretchedMasterKey, authHash } = await derivePasswordKeys(
    password,
    fromBase64(wrapped.kdf_salt),
    wrapped.kdf_params,
  );
  try {
    wipe(
      await decryptVaultKey(
        fromBase64(wrapped.encrypted_vault_key),
        fromBase64(wrapped.vault_key_nonce),
        stretchedMasterKey,
      ),
    );
    return toBase64(authHash);
  } catch (error) {
    if (error instanceof DecryptionError) throw new WrongPasswordError();
    throw error;
  } finally {
    wipe(stretchedMasterKey, authHash);
  }
}

/**
 * Changes the master password and rotates the vault key.
 *
 * A new random vault key replaces the old one and every item is re-encrypted
 * under it, so the old password (or a vault key recovered with it) opens
 * nothing saved from now on. The server applies it all in one transaction
 * and ends every other session.
 *
 * `items` must be the whole vault, and `manifest` its current manifest. On
 * success the session's vault key is swapped for the new one in place, and
 * the re-encrypted items and the new manifest are returned.
 */
export async function changeMasterPassword(
  session: VaultSession,
  currentPassword: string,
  newPassword: string,
  items: readonly VaultItem[],
  manifest: VaultManifest,
): Promise<{ items: VaultItem[]; manifest: VaultManifest }> {
  if (newPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new Error(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`);
  }
  const wrapped = await api.getVaultKey(session.token);
  const current = await derivePasswordKeys(
    currentPassword,
    fromBase64(wrapped.kdf_salt),
    wrapped.kdf_params,
  );
  let next: PasswordKeys | null = null;
  const vaultKey = await generateVaultKey();
  try {
    // Check the current password locally first, so a typo doesn't use up one
    // of the account's limited login attempts.
    try {
      wipe(
        await decryptVaultKey(
          fromBase64(wrapped.encrypted_vault_key),
          fromBase64(wrapped.vault_key_nonce),
          current.stretchedMasterKey,
        ),
      );
    } catch (error) {
      if (error instanceof DecryptionError) throw new WrongPasswordError();
      throw error;
    }

    const salt = await generateSalt();
    const kdfParams = { ...DEFAULT_KDF_PARAMS };
    next = await derivePasswordKeys(newPassword, salt, kdfParams);
    const wrappedNew = await encryptVaultKey(vaultKey, next.stretchedMasterKey);
    const payloads = await Promise.all(
      items.map((item) => encryptNextRevision(item, item, vaultKey)),
    );
    const newManifest = nextManifest(
      manifest,
      { set: payloads.map(({ id, revision }) => ({ id, revision })) },
      CLIENT_NAME,
    );
    let response: { items: ItemResponse[] };
    try {
      response = await api.changePassword(session.token, {
        current_auth_hash: toBase64(current.authHash),
        auth_hash: toBase64(next.authHash),
        kdf_salt: toBase64(salt),
        kdf_params: kdfParams,
        encrypted_vault_key: toBase64(wrappedNew.ciphertext),
        vault_key_nonce: toBase64(wrappedNew.nonce),
        items: payloads,
        manifest: await encryptManifestPayload(newManifest, vaultKey),
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) throw new WrongPasswordError();
      throw error;
    }

    const byId = new Map(items.map((item) => [item.id, item]));
    const updated = response.items.map((saved) => toVaultItem(saved, byId.get(saved.id)!));
    wipe(session.vaultKey);
    session.vaultKey = vaultKey;
    return { items: updated, manifest: newManifest };
  } catch (error) {
    wipe(vaultKey);
    throw error;
  } finally {
    wipe(current.stretchedMasterKey, current.authHash);
    if (next) wipe(next.stretchedMasterKey, next.authHash);
  }
}
