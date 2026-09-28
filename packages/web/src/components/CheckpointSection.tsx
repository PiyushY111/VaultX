import {
  CryptoInputError,
  compareCheckpoints,
  formatCheckpoint,
  parseCheckpoint,
  type CheckpointComparison,
  type VaultCheckpoint,
} from '@password-manager/crypto';
import { useEffect, useState, type FormEvent } from 'react';

type Result =
  { kind: CheckpointComparison; claimed: VaultCheckpoint } | { kind: 'invalid'; message: string };

/**
 * The vault checkpoint: the manifest's version and a fingerprint only the
 * vault key can compute. Comparing it across devices (or with the emergency
 * kit) is the one way to notice a server serving a whole, consistent older
 * copy of the vault to a device that has never seen a newer one.
 */
export function CheckpointSection({
  getCheckpoint,
}: {
  /** Null while the vault has no trusted manifest (a baseline waits for confirmation). */
  getCheckpoint: () => Promise<VaultCheckpoint | null>;
}) {
  const [checkpoint, setCheckpoint] = useState<VaultCheckpoint | null | undefined>(undefined);
  const [input, setInput] = useState('');
  const [result, setResult] = useState<Result | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getCheckpoint().then(
      (value) => !cancelled && setCheckpoint(value),
      () => !cancelled && setCheckpoint(null),
    );
    return () => {
      cancelled = true;
    };
  }, [getCheckpoint]);

  async function verify(event: FormEvent) {
    event.preventDefault();
    if (!checkpoint) return;
    try {
      const claimed = parseCheckpoint(input);
      setResult({ kind: await compareCheckpoints(checkpoint, claimed), claimed });
    } catch (error) {
      if (!(error instanceof CryptoInputError)) throw error;
      setResult({ kind: 'invalid', message: error.message });
    }
  }

  return (
    <div className="sheet" role="region" aria-label="Vault checkpoint">
      <h3>Vault checkpoint</h3>
      {checkpoint === undefined ? (
        <p className="quiet-state">Loading…</p>
      ) : checkpoint === null ? (
        <p className="hint">
          There’s no checkpoint until you confirm this vault as your trusted baseline.
        </p>
      ) : (
        <>
          <p>
            <code className="build-hash" data-testid="vault-checkpoint">
              {formatCheckpoint(checkpoint)}
            </code>
          </p>
          <p className="hint">
            The first number is the vault’s version, which goes up with every change. The rest is a
            fingerprint of exactly which items and revisions it holds, computed with your vault key:
            it means nothing to the server or to anyone who reads it. On a new device, compare it
            with the checkpoint from a device you trust, or from your emergency kit. The same
            version must show the same fingerprint.
          </p>
          <form onSubmit={verify} aria-label="Verify checkpoint" className="row">
            <label>
              Checkpoint from another device
              <input
                value={input}
                autoComplete="off"
                spellCheck={false}
                placeholder="42 · ABCD-EFGH-IJKL-MNOP"
                onChange={(e) => {
                  setInput(e.target.value);
                  setResult(null);
                }}
              />
            </label>
            <button type="submit" className="btn">
              Verify checkpoint
            </button>
          </form>
          {result && <CheckpointResult result={result} current={checkpoint} />}
        </>
      )}
    </div>
  );
}

function CheckpointResult({ result, current }: { result: Result; current: VaultCheckpoint }) {
  switch (result.kind) {
    case 'invalid':
      return (
        <p className="error" role="alert">
          {result.message}
        </p>
      );
    case 'match':
      return (
        <p className="notice" role="status">
          Match: this device sees the same vault (version {current.version}) as the one you copied
          the checkpoint from.
        </p>
      );
    case 'older-checkpoint':
      return (
        <p className="notice" role="status">
          That checkpoint is from an earlier version ({result.claimed.version}); this device sees
          version {current.version}. That’s expected if the vault has changed since you copied it.
          Only a checkpoint of the same version can be compared exactly.
        </p>
      );
    case 'rollback':
      return (
        <div className="warnings" role="alert">
          <strong>This device sees an older vault than your checkpoint.</strong>
          <span>
            Your checkpoint is version {result.claimed.version}, but the server gave this device
            version {current.version}. The server may be showing you an old copy, with recent
            changes missing. Don’t rely on this device’s view until you’ve checked: sign in on the
            device you copied the checkpoint from.
          </span>
        </div>
      );
    case 'mismatch':
      return (
        <div className="warnings" role="alert">
          <strong>Different fingerprint for the same version.</strong>
          <span>
            Both are version {current.version}, but they don’t hold the same items. This isn’t the
            vault your other device saw. Check that you typed it correctly; if you did, don’t trust
            this copy.
          </span>
        </div>
      );
  }
}
