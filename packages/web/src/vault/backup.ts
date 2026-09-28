import {
  DEFAULT_KDF_PARAMS,
  DecryptionError,
  decryptBackup,
  encryptBackup,
  generateSalt,
  validateKdfParams,
  type KdfParams,
} from '@password-manager/crypto';
import { fromBase64, toBase64 } from '../lib/base64';
import { parseItem, serializeItem, type VaultItemData } from './items';
import { derivePasswordKeys } from './kdf';
import { wipe } from './session';

/**
 * Encrypted backup files. The items are encrypted under a key derived from a
 * backup password (Argon2id with a fresh salt, then HKDF, as for logging in),
 * so the file can be restored into any VaultX account, or read with just the
 * password and this format. The file itself reveals only that it's a VaultX
 * backup, when it was made, and its size.
 */

export const BACKUP_FORMAT = 'vaultx-backup';
const BACKUP_VERSION = 1;

interface BackupFile {
  format: typeof BACKUP_FORMAT;
  version: number;
  created_at: string;
  kdf: { salt: string; params: KdfParams };
  nonce: string;
  ciphertext: string;
}

export class WrongBackupPasswordError extends Error {
  constructor() {
    super('That password doesn’t open this backup.');
    this.name = 'WrongBackupPasswordError';
  }
}

export async function createBackup(
  items: readonly VaultItemData[],
  password: string,
  now = new Date(),
): Promise<string> {
  const salt = await generateSalt();
  const params = { ...DEFAULT_KDF_PARAMS };
  const { stretchedMasterKey: key, authHash } = await derivePasswordKeys(password, salt, params);
  wipe(authHash);
  try {
    // Same item JSON as inside the vault, so the format stays one format.
    const json = JSON.stringify({
      v: 1,
      created_at: now.toISOString(),
      items: items.map((item) => JSON.parse(serializeItem(item)) as unknown),
    });
    const { ciphertext, nonce } = await encryptBackup(json, key);
    const file: BackupFile = {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      created_at: now.toISOString(),
      kdf: { salt: toBase64(salt), params },
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
    };
    return `${JSON.stringify(file, null, 2)}\n`;
  } finally {
    wipe(key);
  }
}

/** True if `text` looks like one of our backup files (rather than a CSV). */
export function isBackupFile(text: string): boolean {
  try {
    return (JSON.parse(text) as { format?: unknown }).format === BACKUP_FORMAT;
  } catch {
    return false;
  }
}

export async function readBackup(text: string, password: string): Promise<VaultItemData[]> {
  const file = JSON.parse(text) as BackupFile;
  if (file.format !== BACKUP_FORMAT || file.version !== BACKUP_VERSION) {
    throw new Error('This backup is from a newer or unknown version of VaultX.');
  }
  // A tampered file mustn't be able to make us run a weak (or huge) KDF.
  validateKdfParams(file.kdf.params);
  const { stretchedMasterKey: key, authHash } = await derivePasswordKeys(
    password,
    fromBase64(file.kdf.salt),
    file.kdf.params,
  );
  wipe(authHash);
  try {
    const json = await decryptBackup(fromBase64(file.ciphertext), fromBase64(file.nonce), key);
    const { items } = JSON.parse(json) as { items: unknown[] };
    return items.map((item) => parseItem(JSON.stringify(item)));
  } catch (error) {
    if (error instanceof DecryptionError) throw new WrongBackupPasswordError();
    throw error;
  } finally {
    wipe(key);
  }
}
