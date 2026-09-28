import { validateKdfParams, type KdfParams } from '@password-manager/crypto';
import { TRUSTED_TYPES_POLICY } from '../../build/csp';
import { derivePasswordKeysHere, type PasswordKeys } from './kdfCore';
import type { KdfRequest, KdfResponse } from './kdf.worker';
// The bundled worker's URL (Vite builds it as its own module).
import kdfWorkerUrl from './kdf.worker.ts?worker&url';

export type { PasswordKeys } from './kdfCore';

class WorkerUnavailableError extends Error {}

interface TrustedTypesFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL(url: string): string },
  ): {
    createScriptURL(url: string): unknown;
  };
}

let workerPolicy: ReturnType<TrustedTypesFactory['createPolicy']> | null | undefined;

/**
 * The CSP requires Trusted Types for script URLs, so `new Worker()` needs one
 * from a policy. This is the only policy the CSP allows, and it returns only
 * the KDF worker's own URL, so it can't be used to load anything else.
 * Browsers without Trusted Types get the plain URL.
 */
function kdfWorkerScriptUrl(): string {
  if (workerPolicy === undefined) {
    const factory = (globalThis as { trustedTypes?: TrustedTypesFactory }).trustedTypes;
    workerPolicy =
      factory?.createPolicy(TRUSTED_TYPES_POLICY, {
        createScriptURL: (url) => {
          if (url !== kdfWorkerUrl) throw new TypeError(`Refusing worker script ${url}`);
          return url;
        },
      }) ?? null;
  }
  // A TrustedScriptURL where supported; the DOM typings only know strings.
  return (workerPolicy?.createScriptURL(kdfWorkerUrl) ?? kdfWorkerUrl) as string;
}

function deriveInWorker(request: KdfRequest): Promise<PasswordKeys> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(kdfWorkerScriptUrl(), { type: 'module' });
    } catch {
      reject(new WorkerUnavailableError());
      return;
    }
    worker.onmessage = ({ data }: MessageEvent<KdfResponse>) => {
      worker.terminate();
      if (data.ok)
        resolve({ stretchedMasterKey: data.stretchedMasterKey, authHash: data.authHash });
      else reject(new Error(data.message));
    };
    // Fires if the worker script can't load or run at all.
    worker.onerror = (event) => {
      event.preventDefault();
      worker.terminate();
      reject(new WorkerUnavailableError());
    };
    worker.postMessage(request);
  });
}

/**
 * Derives the stretched master key and auth hash from the master password.
 *
 * Argon2id is deliberately slow and memory-hard (64 MiB, about a second), so
 * it runs in a Web Worker to keep the page responsive. Where workers aren't
 * available (tests, or a worker that fails to load) it runs on this thread.
 */
export async function derivePasswordKeys(
  password: string,
  salt: Uint8Array,
  kdfParams: KdfParams,
): Promise<PasswordKeys> {
  // Checked here too, so a server-supplied downgrade is refused before any work starts.
  validateKdfParams(kdfParams);
  if (typeof Worker === 'undefined') return derivePasswordKeysHere(password, salt, kdfParams);
  try {
    return await deriveInWorker({ password, salt: salt.slice(), kdfParams });
  } catch (error) {
    if (error instanceof WorkerUnavailableError) {
      return derivePasswordKeysHere(password, salt, kdfParams);
    }
    throw error;
  }
}
