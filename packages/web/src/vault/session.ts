import {
  DEFAULT_KDF_PARAMS,
  DecryptionError,
  decryptVaultKey,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
} from '@password-manager/crypto';
import { ApiError, api, describeLoginFailure, type ItemResponse } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import { encryptNextRevision, toVaultItem, type VaultItem } from './items';
import { derivePasswordKeys, type PasswordKeys } from './kdf';

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
    return { email, token, vaultKey };
  } catch (error) {
    wipe(vaultKey);
    throw error;
  } finally {
    wipe(stretchedMasterKey, authHash);
  }
}

/**
 * Logs in: fetches the KDF salt/params, re-derives keys locally, proves
 * knowledge of the password with the authHash, then unwraps the vault key.
 */
export async function logIn(emailInput: string, password: string): Promise<VaultSession> {
  const email = normalizeEmail(emailInput);
  const { kdf_salt, kdf_params } = await api.prelogin(email);
  // derivePasswordKeys rejects params below the crypto package's floor, so a
  // malicious server can't downgrade the KDF.
  const { stretchedMasterKey, authHash } = await derivePasswordKeys(
    password,
    fromBase64(kdf_salt),
    kdf_params,
  );
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
    wipe(stretchedMasterKey, authHash);
  }
}

export class WrongPasswordError extends Error {
  constructor(message = 'Current master password is incorrect.') {
    super(message);
    this.name = 'WrongPasswordError';
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
 * `items` must be the whole vault. On success the session's vault key is
 * swapped for the new one in place, and the re-encrypted items are returned.
 */
export async function changeMasterPassword(
  session: VaultSession,
  currentPassword: string,
  newPassword: string,
  items: readonly VaultItem[],
): Promise<VaultItem[]> {
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
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) throw new WrongPasswordError();
      throw error;
    }

    const byId = new Map(items.map((item) => [item.id, item]));
    const updated = response.items.map((saved) => toVaultItem(saved, byId.get(saved.id)!));
    wipe(session.vaultKey);
    session.vaultKey = vaultKey;
    return updated;
  } catch (error) {
    wipe(vaultKey);
    throw error;
  } finally {
    wipe(current.stretchedMasterKey, current.authHash);
    if (next) wipe(next.stretchedMasterKey, next.authHash);
  }
}
