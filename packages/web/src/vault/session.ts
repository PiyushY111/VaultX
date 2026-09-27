import {
  DEFAULT_KDF_PARAMS,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
} from '@password-manager/crypto';
import { ApiError, api, describeLoginFailure } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';

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

export function lockSession(session: VaultSession): void {
  wipe(session.vaultKey);
  session.token = '';
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
  const masterKey = await deriveMasterKey(password, salt, kdfParams);
  const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
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
    return { email, token, vaultKey };
  } catch (error) {
    wipe(vaultKey);
    throw error;
  } finally {
    wipe(masterKey, stretchedMasterKey, authHash);
  }
}

/**
 * Logs in: fetches the KDF salt/params, re-derives keys locally, proves
 * knowledge of the password with the authHash, then unwraps the vault key.
 */
export async function logIn(emailInput: string, password: string): Promise<VaultSession> {
  const email = normalizeEmail(emailInput);
  const { kdf_salt, kdf_params } = await api.prelogin(email);
  // deriveMasterKey rejects params below the crypto package's floor, so a
  // malicious server can't downgrade the KDF.
  const masterKey = await deriveMasterKey(password, fromBase64(kdf_salt), kdf_params);
  const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
  try {
    let token: string;
    try {
      ({ token } = await api.login(email, toBase64(authHash)));
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
  } finally {
    wipe(masterKey, stretchedMasterKey, authHash);
  }
}
