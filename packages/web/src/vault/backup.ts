import {
  DEFAULT_KDF_PARAMS,
  DecryptionError,
  decryptBackup,
  encryptBackup,
  NONCE_BYTES,
  SALT_BYTES,
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

/** The file isn't a readable VaultX backup: not one, a version we don't know, damaged, or edited. */
export class BackupFormatError extends Error {
  override name = 'BackupFormatError';
}

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function base64Field(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string' || !BASE64.test(value)) {
    throw new BackupFormatError(`This backup file is damaged (${name}).`);
  }
  return fromBase64(value);
}

/** Checks the file's shape before anything in it is used. */
function parseBackupFile(text: string): {
  salt: Uint8Array;
  params: KdfParams;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  let file: unknown;
  try {
    file = JSON.parse(text);
  } catch {
    throw new BackupFormatError('This isn’t a VaultX backup file.');
  }
  if (typeof file !== 'object' || file === null || Array.isArray(file)) {
    throw new BackupFormatError('This isn’t a VaultX backup file.');
  }
  const { format, version, kdf, nonce, ciphertext } = file as Record<string, unknown>;
  if (format !== BACKUP_FORMAT) throw new BackupFormatError('This isn’t a VaultX backup file.');
  if (version !== BACKUP_VERSION) {
    throw new BackupFormatError('This backup is from a newer or unknown version of VaultX.');
  }
  if (typeof kdf !== 'object' || kdf === null) {
    throw new BackupFormatError('This backup file is damaged (kdf).');
  }
  const { salt, params } = kdf as Record<string, unknown>;
  // A tampered file mustn't be able to make us run a weak (or huge) KDF.
  try {
    validateKdfParams(params as KdfParams);
  } catch (error) {
    throw new BackupFormatError(
      `This backup’s key settings are unsafe or damaged: ${(error as Error).message}`,
    );
  }
  const saltBytes = base64Field(salt, 'salt');
  const nonceBytes = base64Field(nonce, 'nonce');
  if (saltBytes.length !== SALT_BYTES || nonceBytes.length !== NONCE_BYTES) {
    throw new BackupFormatError('This backup file is damaged (salt or nonce length).');
  }
  return {
    salt: saltBytes,
    params: params as KdfParams,
    nonce: nonceBytes,
    ciphertext: base64Field(ciphertext, 'ciphertext'),
  };
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

/**
 * Opens a backup file. Throws {@link WrongBackupPasswordError} if the
 * password is wrong (or the ciphertext was tampered with), and
 * {@link BackupFormatError} for anything else wrong with the file; nothing else.
 */
export async function readBackup(text: string, password: string): Promise<VaultItemData[]> {
  const file = parseBackupFile(text);
  const { stretchedMasterKey: key, authHash } = await derivePasswordKeys(
    password,
    file.salt,
    file.params,
  );
  wipe(authHash);
  let json: string;
  try {
    json = await decryptBackup(file.ciphertext, file.nonce, key);
  } catch (error) {
    if (error instanceof DecryptionError) throw new WrongBackupPasswordError();
    throw error;
  } finally {
    wipe(key);
  }
  // Authentic, so written by someone with the password; still checked.
  let items: unknown;
  try {
    items = (JSON.parse(json) as { items?: unknown } | null)?.items;
  } catch {
    throw new BackupFormatError('This backup’s contents are damaged.');
  }
  if (!Array.isArray(items)) throw new BackupFormatError('This backup’s contents are damaged.');
  return items.map((item, index) => {
    try {
      return parseItem(JSON.stringify(item));
    } catch (error) {
      throw new BackupFormatError(
        `Item ${index + 1} in this backup is damaged: ${(error as Error).message}`,
      );
    }
  });
}
