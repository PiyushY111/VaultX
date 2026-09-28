import { describe, expect, it } from 'vitest';
import { WrongBackupPasswordError, createBackup, isBackupFile, readBackup } from './backup';

const ITEMS = [
  { site: 'github.com', username: 'octocat', password: 'BACKUP-ITEM-PW', notes: 'n' },
  { site: 'bank.example.com', username: 'alice', password: 'p2', notes: '' },
];
const PASSWORD = 'backup-password-orbit-lantern-58';

describe('encrypted backups', () => {
  it('round-trip with the password, and reveal nothing without it', async () => {
    const file = await createBackup(ITEMS, PASSWORD);
    expect(isBackupFile(file)).toBe(true);
    for (const value of ['BACKUP-ITEM-PW', 'octocat', 'github.com', PASSWORD]) {
      expect(file).not.toContain(value);
    }
    expect(Object.keys(JSON.parse(file)).sort()).toEqual([
      'ciphertext',
      'created_at',
      'format',
      'kdf',
      'nonce',
      'version',
    ]);
    expect(await readBackup(file, PASSWORD)).toEqual(ITEMS);
  });

  it('refuses a wrong password', async () => {
    const file = await createBackup(ITEMS, PASSWORD);
    await expect(readBackup(file, 'not-the-password')).rejects.toThrow(WrongBackupPasswordError);
  });

  it('refuses a file edited to use weak KDF settings or a different salt', async () => {
    const file = JSON.parse(await createBackup(ITEMS, PASSWORD));
    const weak = {
      ...file,
      kdf: { ...file.kdf, params: { ...file.kdf.params, memoryCost: 1024 } },
    };
    await expect(readBackup(JSON.stringify(weak), PASSWORD)).rejects.toThrow(/kdfParams/);
    const resalted = { ...file, kdf: { ...file.kdf, salt: 'AAAAAAAAAAAAAAAAAAAAAA==' } };
    await expect(readBackup(JSON.stringify(resalted), PASSWORD)).rejects.toThrow(
      WrongBackupPasswordError,
    );
  });

  it('refuses unknown versions, and tells CSVs apart', async () => {
    const file = JSON.parse(await createBackup(ITEMS, PASSWORD));
    await expect(readBackup(JSON.stringify({ ...file, version: 2 }), PASSWORD)).rejects.toThrow(
      /newer or unknown/,
    );
    expect(isBackupFile('name,url,username,password\n')).toBe(false);
  });
});
