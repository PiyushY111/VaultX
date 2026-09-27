import { deriveKeys, deriveMasterKey, type KdfParams } from '@password-manager/crypto';

/** The two keys a master password yields. The master key itself is wiped before returning. */
export interface PasswordKeys {
  /** Unwraps the vault key. Never leaves the client. */
  stretchedMasterKey: Uint8Array;
  /** Proves the password to the server. */
  authHash: Uint8Array;
}

/** Argon2id, then HKDF, on the calling thread. */
export async function derivePasswordKeysHere(
  password: string,
  salt: Uint8Array,
  kdfParams: KdfParams,
): Promise<PasswordKeys> {
  const masterKey = await deriveMasterKey(password, salt, kdfParams);
  try {
    return await deriveKeys(masterKey);
  } finally {
    masterKey.fill(0);
  }
}
