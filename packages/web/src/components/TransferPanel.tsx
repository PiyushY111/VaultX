import { useState, type ChangeEvent, type FormEvent } from 'react';
import { ApiError } from '../api';
import { downloadText } from '../lib/download';
import {
  MIN_MASTER_PASSWORD_SCORE,
  STRENGTH_LABELS,
  estimateStrength,
  usePasswordStrength,
} from '../lib/passwordStrength';
import { createBackup, isBackupFile, readBackup } from '../vault/backup';
import { parseImport, withoutDuplicates, type ImportSource } from '../vault/importers';
import type { VaultItem, VaultItemData } from '../vault/items';
import { proveCurrentPassword, type VaultSession } from '../vault/session';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  session: VaultSession;
  /** Every verified item in the vault. Null while loading. */
  items: VaultItem[] | null;
  /** Items hidden by the integrity checks, which an export leaves out. */
  unverifiedCount: number;
  importItems: (items: VaultItemData[], onProgress: (saved: number) => void) => Promise<void>;
  onSessionExpired: () => void;
  onClose: () => void;
}

export function TransferPanel(props: Props) {
  return (
    <section className="security" aria-label="Import and export">
      <div className="vault-head">
        <h2>Import and export</h2>
        <button type="button" className="btn btn-quiet" onClick={props.onClose}>
          Back to vault
        </button>
      </div>
      <ImportSection {...props} />
      <ExportSection {...props} />
    </section>
  );
}

type ImportStep =
  | { kind: 'choose' }
  | { kind: 'backup-password'; text: string }
  | {
      kind: 'preview';
      source: ImportSource | 'VaultX backup';
      items: VaultItemData[];
      duplicates: number;
      skipped: number;
    }
  | { kind: 'importing'; total: number; saved: number }
  | { kind: 'done'; count: number; fromCsv: boolean };

const errorText = (err: unknown) => (err instanceof Error ? err.message : 'Something went wrong');

function ImportSection({ items, importItems, onSessionExpired }: Props) {
  const [step, setStep] = useState<ImportStep>({ kind: 'choose' });
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function preview(
    source: ImportSource | 'VaultX backup',
    incoming: VaultItemData[],
    skipped: number,
  ) {
    const { items: fresh, duplicates } = withoutDuplicates(incoming, items ?? []);
    setStep({ kind: 'preview', source, items: fresh, duplicates, skipped });
  }

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = ''; // Let the same file be chosen again.
    if (!file) return;
    setError(null);
    try {
      const text = await file.text();
      if (isBackupFile(text)) {
        setStep({ kind: 'backup-password', text });
      } else {
        const parsed = parseImport(text);
        preview(parsed.source, parsed.items, parsed.skipped);
      }
    } catch (err) {
      setError(errorText(err));
    }
  }

  async function openBackup(event: FormEvent) {
    event.preventDefault();
    if (step.kind !== 'backup-password') return;
    const submitted = password;
    setPassword('');
    setBusy(true);
    setError(null);
    try {
      preview('VaultX backup', await readBackup(step.text, submitted), 0);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function runImport() {
    if (step.kind !== 'preview') return;
    const fromCsv = step.source !== 'VaultX backup';
    const total = step.items.length;
    setStep({ kind: 'importing', total, saved: 0 });
    setError(null);
    try {
      await importItems(step.items, (saved) => setStep({ kind: 'importing', total, saved }));
      setStep({ kind: 'done', count: total, fromCsv });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(errorText(err));
      setStep({ kind: 'choose' });
    }
  }

  const errorLine = error && (
    <p className="error" role="alert">
      {error}
    </p>
  );

  return (
    <div className="sheet" role="region" aria-label="Import">
      <h3>Import</h3>
      {step.kind === 'choose' && (
        <>
          <p className="hint">
            Bring your logins from another password manager: export them as CSV from Chrome (or
            Edge, Brave), Firefox, Bitwarden or 1Password, then choose the file here. You can also
            restore a VaultX backup. The file is read on this device and each login is encrypted
            before it’s saved.
          </p>
          <label className="file-pick">
            Choose a file to import
            <input
              type="file"
              accept=".csv,.json,text/csv,application/json"
              onChange={chooseFile}
            />
          </label>
          {errorLine}
        </>
      )}
      {step.kind === 'backup-password' && (
        <form onSubmit={openBackup} aria-label="Open backup">
          <p className="hint">This is a VaultX backup. Enter the password it was saved with.</p>
          <label>
            Backup password
            <input
              type="password"
              autoComplete="off"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {errorLine}
          <div className="row sheet-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Decrypting…' : 'Open backup'}
            </button>
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => setStep({ kind: 'choose' })}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {step.kind === 'preview' && (
        <>
          <p role="status">
            Found <strong>{step.items.length + step.duplicates}</strong> login
            {step.items.length + step.duplicates === 1 ? '' : 's'} in this {step.source} file.
            {step.duplicates > 0 &&
              ` ${step.duplicates} ${step.duplicates === 1 ? 'is' : 'are'} already in your vault and will be skipped.`}
            {step.skipped > 0 &&
              ` ${step.skipped} other row${step.skipped === 1 ? '' : 's'} (not logins, or empty) will be skipped.`}
          </p>
          {step.items.length > 0 && (
            <ul className="import-preview" aria-label="Logins to import">
              {step.items.slice(0, 8).map((item, i) => (
                <li key={i}>
                  <strong>{item.site}</strong>
                  {item.username && <span className="hint"> · {item.username}</span>}
                </li>
              ))}
              {step.items.length > 8 && <li className="hint">…and {step.items.length - 8} more</li>}
            </ul>
          )}
          {errorLine}
          <div className="row sheet-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={step.items.length === 0}
              onClick={runImport}
            >
              Import {step.items.length} login{step.items.length === 1 ? '' : 's'}
            </button>
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => setStep({ kind: 'choose' })}
            >
              Cancel
            </button>
          </div>
        </>
      )}
      {step.kind === 'importing' && (
        <p className="quiet-state" role="status">
          Encrypting and saving… {step.saved} of {step.total}
        </p>
      )}
      {step.kind === 'done' && (
        <>
          <p className="notice" role="status">
            Imported {step.count} login{step.count === 1 ? '' : 's'}.
          </p>
          {step.fromCsv && (
            <p className="warning">
              Now delete the CSV file you imported (and empty the trash): it holds your passwords
              unencrypted.
            </p>
          )}
          <div className="row sheet-actions">
            <button type="button" className="btn" onClick={() => setStep({ kind: 'choose' })}>
              Import another file
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ExportSection({ session, items, unverifiedCount, onSessionExpired }: Props) {
  const [master, setMaster] = useState('');
  const [separate, setSeparate] = useState(false);
  const [backupPassword, setBackupPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const strength = usePasswordStrength(separate ? backupPassword : '', [session.email]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!items) return;
    setDone(false);
    setError(null);
    if (separate) {
      if (
        (await estimateStrength(backupPassword, [session.email])).score < MIN_MASTER_PASSWORD_SCORE
      ) {
        setError(
          `Choose a backup password rated at least “${STRENGTH_LABELS[MIN_MASTER_PASSWORD_SCORE]}”. Anyone who gets the file can try to guess it offline.`,
        );
        return;
      }
      if (backupPassword !== confirm) {
        setError('Backup passwords do not match.');
        return;
      }
    }
    const [masterPassword, filePassword] = [master, separate ? backupPassword : master];
    setMaster('');
    setBackupPassword('');
    setConfirm('');
    setBusy(true);
    try {
      // Only the account's owner can take everything out in one file.
      await proveCurrentPassword(session, masterPassword);
      const file = await createBackup(items, filePassword);
      const date = new Date().toISOString().slice(0, 10);
      downloadText(`vaultx-backup-${date}.json`, file, 'application/json');
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="sheet" onSubmit={handleSubmit} aria-label="Export">
      <h3>Export an encrypted backup</h3>
      <p className="hint">
        Downloads every login in your vault as one encrypted file. Restore it with Import above, in
        this or any VaultX account. Anyone with the file and its password can read every login in
        it, so keep it somewhere safe.
      </p>
      {unverifiedCount > 0 && (
        <p className="warning">
          {unverifiedCount} item(s) that failed the vault’s integrity checks won’t be included.
        </p>
      )}
      <label>
        Master password
        <input
          type="password"
          autoComplete="current-password"
          required
          value={master}
          onChange={(e) => setMaster(e.target.value)}
        />
      </label>
      <label className="inline">
        <input type="checkbox" checked={separate} onChange={(e) => setSeparate(e.target.checked)} />
        Protect the backup with a different password
      </label>
      {separate && (
        <>
          <label>
            Backup password
            <input
              type="password"
              autoComplete="new-password"
              required
              value={backupPassword}
              onChange={(e) => setBackupPassword(e.target.value)}
            />
          </label>
          <StrengthMeter strength={strength} />
          <label>
            Confirm backup password
            <input
              type="password"
              autoComplete="new-password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </label>
        </>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {done && (
        <p className="notice" role="status">
          Backup downloaded. It opens with{' '}
          {separate ? 'the backup password you chose' : 'your master password'}.
        </p>
      )}
      <div className="row sheet-actions">
        <button type="submit" className="btn btn-primary" disabled={busy || items === null}>
          {busy ? 'Encrypting…' : 'Download encrypted backup'}
        </button>
      </div>
    </form>
  );
}
