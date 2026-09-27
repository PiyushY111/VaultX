/* global Buffer, process, console */
// Demo client for trying the API with curl. Performs the client-side crypto
// that a real client (web app / extension) would, using @password-manager/crypto.
// The server never runs this code.
//
//   node scripts/demo-client.mjs signup        <email> <password>
//   node scripts/demo-client.mjs login         <email> <password> <prelogin-response-json>
//   node scripts/demo-client.mjs encrypt-item  <password> <vault-key-response-json> <plaintext>
//   node scripts/demo-client.mjs decrypt-items <password> <vault-key-response-json> <vault-items-response-json>
import {
  DEFAULT_KDF_PARAMS,
  decryptItem,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  encryptItem,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
} from '@password-manager/crypto';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (value) => new Uint8Array(Buffer.from(value, 'base64'));

async function unlockVaultKey(password, vaultKeyResponse) {
  const vk = JSON.parse(vaultKeyResponse);
  const { stretchedMasterKey } = await deriveKeys(
    await deriveMasterKey(password, unb64(vk.kdf_salt), vk.kdf_params),
  );
  return decryptVaultKey(
    unb64(vk.encrypted_vault_key),
    unb64(vk.vault_key_nonce),
    stretchedMasterKey,
  );
}

const [command, ...args] = process.argv.slice(2);

switch (command) {
  case 'signup': {
    const [email, password] = args;
    const salt = await generateSalt();
    const kdfParams = { ...DEFAULT_KDF_PARAMS };
    const { stretchedMasterKey, authHash } = await deriveKeys(
      await deriveMasterKey(password, salt, kdfParams),
    );
    const wrapped = await encryptVaultKey(await generateVaultKey(), stretchedMasterKey);
    console.log(
      JSON.stringify({
        email,
        auth_hash: b64(authHash),
        encrypted_vault_key: b64(wrapped.ciphertext),
        vault_key_nonce: b64(wrapped.nonce),
        kdf_salt: b64(salt),
        kdf_params: kdfParams,
      }),
    );
    break;
  }
  case 'login': {
    const [email, password, preloginResponse] = args;
    const { kdf_salt, kdf_params } = JSON.parse(preloginResponse);
    const { authHash } = await deriveKeys(
      await deriveMasterKey(password, unb64(kdf_salt), kdf_params),
    );
    console.log(JSON.stringify({ email, auth_hash: b64(authHash) }));
    break;
  }
  case 'encrypt-item': {
    const [password, vaultKeyResponse, plaintext] = args;
    const { ciphertext, nonce } = await encryptItem(
      plaintext,
      await unlockVaultKey(password, vaultKeyResponse),
    );
    console.log(JSON.stringify({ encrypted_data: b64(ciphertext), nonce: b64(nonce) }));
    break;
  }
  case 'decrypt-items': {
    const [password, vaultKeyResponse, itemsResponse] = args;
    const vaultKey = await unlockVaultKey(password, vaultKeyResponse);
    for (const item of JSON.parse(itemsResponse).items) {
      console.log(
        item.id,
        await decryptItem(unb64(item.encrypted_data), unb64(item.nonce), vaultKey),
      );
    }
    break;
  }
  default:
    console.error('usage: demo-client.mjs signup|login|encrypt-item|decrypt-items ...');
    process.exit(1);
}
