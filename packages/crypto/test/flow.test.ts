import { describe, expect, it } from 'vitest';
import {
  DecryptionError,
  MIN_KDF_PARAMS,
  decryptItem,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  encryptItem,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
} from '../src/index.js';

describe('end-to-end: register, then log in on a new device', () => {
  it('recovers vault items with the right password and fails with the wrong one', async () => {
    const password = 'correct horse battery staple';
    const item = JSON.stringify({ site: 'example.com', password: 'hunter2' });

    // Registration: the server stores salt, kdfParams, authHash, and ciphertexts.
    const salt = await generateSalt();
    const kdfParams = MIN_KDF_PARAMS;
    const registerKeys = await deriveKeys(await deriveMasterKey(password, salt, kdfParams));
    const vaultKey = await generateVaultKey();
    const wrappedVaultKey = await encryptVaultKey(vaultKey, registerKeys.stretchedMasterKey);
    const encryptedItem = await encryptItem(item, vaultKey);

    // Login: re-derive from the password and the server-provided salt/params.
    const loginKeys = await deriveKeys(await deriveMasterKey(password, salt, kdfParams));
    expect(loginKeys.authHash).toEqual(registerKeys.authHash);
    const recoveredVaultKey = await decryptVaultKey(
      wrappedVaultKey.ciphertext,
      wrappedVaultKey.nonce,
      loginKeys.stretchedMasterKey,
    );
    expect(
      await decryptItem(encryptedItem.ciphertext, encryptedItem.nonce, recoveredVaultKey),
    ).toBe(item);

    // Wrong password: different authHash, and the vault key cannot be unwrapped.
    const wrongKeys = await deriveKeys(await deriveMasterKey(password + 'x', salt, kdfParams));
    expect(wrongKeys.authHash).not.toEqual(registerKeys.authHash);
    await expect(
      decryptVaultKey(
        wrappedVaultKey.ciphertext,
        wrappedVaultKey.nonce,
        wrongKeys.stretchedMasterKey,
      ),
    ).rejects.toThrow(DecryptionError);
  });
});
