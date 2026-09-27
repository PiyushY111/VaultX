// Runs Argon2id off the main thread (see kdf.ts). One worker per derivation,
// terminated right after, so no key material outlives the request here.
import type { KdfParams } from '@password-manager/crypto';
import { derivePasswordKeysHere } from './kdfCore';

export interface KdfRequest {
  password: string;
  salt: Uint8Array;
  kdfParams: KdfParams;
}

export type KdfResponse =
  | { ok: true; stretchedMasterKey: Uint8Array; authHash: Uint8Array }
  | { ok: false; message: string };

// The DOM lib types `self` as a Window; this file runs as a dedicated worker.
const scope = self as unknown as {
  onmessage: ((event: MessageEvent<KdfRequest>) => void) | null;
  postMessage(message: KdfResponse, transfer: Transferable[]): void;
};

scope.onmessage = async ({ data }) => {
  try {
    const keys = await derivePasswordKeysHere(data.password, data.salt, data.kdfParams);
    // Transfer, not copy, so the worker keeps no second copy of the keys.
    scope.postMessage({ ok: true, ...keys }, [
      keys.stretchedMasterKey.buffer,
      keys.authHash.buffer,
    ]);
  } catch (error) {
    scope.postMessage(
      { ok: false, message: error instanceof Error ? error.message : 'KDF failed' },
      [],
    );
  }
};
