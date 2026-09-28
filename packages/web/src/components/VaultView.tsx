import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError } from '../api';
import { AUTO_LOCK_OPTIONS_MINUTES } from '../lib/autoLockSetting';
import { emptyItem, filterItems, type VaultItem, type VaultItemData } from '../vault/items';
import { createRevisionLedger } from '../vault/revisionLedger';
import type { VaultSession } from '../vault/session';
import {
  VaultChangedError,
  VaultSync,
  countWarnings,
  type LoadedVault,
  type VaultWarnings,
} from '../vault/sync';
import { EmergencyKit } from './EmergencyKit';
import { Emblem, KeyholeIcon } from './Emblem';
import { ItemForm } from './ItemForm';
import { ItemRow } from './ItemRow';
import { PasswordGenerator } from './PasswordGenerator';
import { SecurityPanel } from './SecurityPanel';
import { TransferPanel } from './TransferPanel';

interface Props {
  session: VaultSession;
  autoLockMinutes: number;
  onChangeAutoLock: (minutes: number) => void;
  /** Pass a reason only when the lock wasn't the user's own action. */
  onLock: (reason?: string) => void;
  onLogOut: () => void;
  onAccountDeleted: () => void;
  /** Offer the emergency kit right away (after signing up). */
  justSignedUp?: boolean;
}

type Editing = { mode: 'new' } | { mode: 'edit'; item: VaultItem } | null;

const SESSION_EXPIRED = 'Your session expired. Enter your master password to continue.';

const NO_WARNINGS: VaultWarnings = {
  failedIds: [],
  rolledBackIds: [],
  missingIds: [],
  unexpectedIds: [],
  manifest: null,
};

const isStaleRevision = (err: unknown) =>
  err instanceof ApiError && err.status === 409 && 'current_revision' in err.details;

const formatTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

const CLIENT_LABELS: Record<string, string> = { web: 'the web vault', extension: 'the extension' };

/**
 * Holds every decrypted item in component state. When the vault locks, App
 * unmounts this component and all of it is discarded.
 */
export function VaultView({
  session,
  autoLockMinutes,
  onChangeAutoLock,
  onLock,
  onLogOut,
  onAccountDeleted,
  justSignedUp = false,
}: Props) {
  const [items, setItems] = useState<VaultItem[] | null>(null);
  const [warnings, setWarnings] = useState<VaultWarnings>(NO_WARNINGS);
  const [lastChanged, setLastChanged] = useState<LoadedVault['lastChanged']>(null);
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<Editing>(null);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [showTransfer, setShowTransfer] = useState(false);
  const [showKit, setShowKit] = useState(justSignedUp);
  const [error, setError] = useState<string | null>(null);
  const ledger = useMemo(() => createRevisionLedger(session.email), [session.email]);
  const sync = useRef<VaultSync | null>(null);
  sync.current ??= new VaultSync(session, ledger);

  function handleError(err: unknown) {
    if (err instanceof ApiError && err.status === 401) onLock(SESSION_EXPIRED);
    else setError(err instanceof Error ? err.message : 'Something went wrong');
  }

  const load = useCallback(async () => {
    const loaded = await sync.current!.load();
    setWarnings(loaded.warnings);
    setLastChanged(loaded.lastChanged);
    setItems(loaded.items);
  }, []);

  useEffect(() => {
    let active = true;
    load().catch((err: unknown) => {
      if (active) handleError(err);
    });
    return () => {
      active = false;
    };
    // Load once per session; handleError only reads props that change with it.
  }, [load]);

  // Search runs over the decrypted items in memory; the query never leaves the browser.
  const visible = useMemo(() => filterItems(items ?? [], query), [items, query]);

  async function save(data: VaultItemData) {
    try {
      if (editing?.mode === 'edit') {
        const saved = await sync.current!.update(editing.item, data);
        setItems((prev) => (prev ?? []).map((item) => (item.id === saved.id ? saved : item)));
      } else {
        const saved = await sync.current!.create(data);
        setItems((prev) => [...(prev ?? []), saved]);
      }
      setEditing(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onLock(SESSION_EXPIRED);
      if (isStaleRevision(err) || err instanceof VaultChangedError) {
        // Saved from another device or the extension since this page loaded.
        await load().catch(handleError);
        throw new Error(
          'Your vault was changed elsewhere since you opened this. It has been reloaded; open the item again to make your change.',
          { cause: err },
        );
      }
      throw err;
    }
  }

  async function remove(item: VaultItem) {
    if (!window.confirm(`Delete ${item.site}?`)) return;
    try {
      await sync.current!.remove(item.id);
      setItems((prev) => (prev ?? []).filter((other) => other.id !== item.id));
    } catch (err) {
      if (err instanceof VaultChangedError) {
        await load().catch(handleError);
        setError('Your vault was changed elsewhere, so it has been reloaded. Try again.');
      } else {
        handleError(err);
      }
    }
  }

  const count = items?.length ? `${items.length} ${items.length === 1 ? 'login' : 'logins'}` : null;

  return (
    <div className="vault">
      <header className="topbar">
        <div className="topbar-brand">
          <Emblem className="mark" />
          <h1 className="topbar-title">VaultX</h1>
        </div>
        <span className="topbar-who">
          Signed in as <strong>{session.email}</strong>
        </span>
        <div className="topbar-actions">
          <label className="inline autolock">
            Auto-lock after
            <select
              value={autoLockMinutes}
              onChange={(e) => onChangeAutoLock(Number(e.target.value))}
            >
              {AUTO_LOCK_OPTIONS_MINUTES.map((minutes) => (
                <option key={minutes} value={minutes}>
                  {minutes} min
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="btn btn-quiet"
            aria-pressed={showSecurity}
            onClick={() => {
              setEditing(null);
              setShowTransfer(false);
              setShowSecurity((v) => !v);
            }}
          >
            Security
          </button>
          <button type="button" className="btn btn-seal" onClick={() => onLock()}>
            <span className="btn-seal-glyph">
              <KeyholeIcon />
            </span>
            Lock now
          </button>
          <button type="button" className="btn btn-quiet" onClick={onLogOut}>
            Log out
          </button>
        </div>
      </header>

      <main className="vault-main" aria-label="Vault">
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <WarningList warnings={warnings} />
        {showKit && (
          <EmergencyKit email={session.email} onDone={() => setShowKit(false)} firstTime />
        )}

        {showTransfer ? (
          <TransferPanel
            session={session}
            items={items}
            unverifiedCount={countWarnings(warnings)}
            importItems={async (data, onProgress) => {
              try {
                const saved = await sync.current!.createMany(data, onProgress);
                setItems((prev) => [...(prev ?? []), ...saved]);
              } catch (err) {
                // Some batches may have been saved: show what the server has now.
                await load().catch(handleError);
                throw err;
              }
            }}
            onSessionExpired={() => onLock(SESSION_EXPIRED)}
            onClose={() => setShowTransfer(false)}
          />
        ) : showSecurity ? (
          <SecurityPanel
            session={session}
            items={items}
            changeBlockedReason={
              countWarnings(warnings) > 0
                ? 'Some items couldn’t be verified (see above), so the vault can’t be re-encrypted under a new key without losing them.'
                : null
            }
            currentManifest={() => sync.current!.currentManifest()}
            onPasswordChanged={(updated, manifest) => {
              sync.current!.replaceManifest(manifest);
              ledger.record(updated);
              setItems(updated);
            }}
            onShowEmergencyKit={() => {
              setShowSecurity(false);
              setShowKit(true);
            }}
            onSignedOutEverywhere={onLogOut}
            onAccountDeleted={onAccountDeleted}
            onSessionExpired={() => onLock(SESSION_EXPIRED)}
            onClose={() => setShowSecurity(false)}
          />
        ) : editing ? (
          <ItemForm
            key={editing.mode === 'edit' ? editing.item.id : 'new'}
            initial={editing.mode === 'edit' ? editing.item : emptyItem()}
            isNew={editing.mode === 'new'}
            onSave={save}
            onCancel={() => setEditing(null)}
          />
        ) : (
          <>
            <div className="vault-head">
              <h2>Your vault</h2>
              {count && <span className="vault-count">{count}</span>}
            </div>
            {lastChanged && (
              <p className="hint" data-testid="last-changed">
                Last changed {formatTime(lastChanged.at)} from{' '}
                {CLIENT_LABELS[lastChanged.by] ?? 'another app'}. If you changed it more recently
                than that, the server may be showing you an old copy.
              </p>
            )}
            <div className="vault-tools">
              <input
                type="search"
                className="search"
                placeholder="Search site, username or notes"
                aria-label="Search vault"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setEditing({ mode: 'new' })}
              >
                Add item
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setShowSecurity(false);
                  setShowTransfer(true);
                }}
              >
                Import / export
              </button>
              <button
                type="button"
                className="btn"
                aria-expanded={showGenerator}
                onClick={() => setShowGenerator((v) => !v)}
              >
                {showGenerator ? 'Hide generator' : 'Password generator'}
              </button>
            </div>
            {showGenerator && <PasswordGenerator />}
            {items === null ? (
              <p className="quiet-state">Decrypting vault…</p>
            ) : visible.length === 0 ? (
              <div className="quiet-state">
                {items.length === 0 ? (
                  <>
                    <p>Your vault is empty.</p>
                    <p className="hint">
                      Add your first login. It’s encrypted on this device before it’s saved.
                    </p>
                  </>
                ) : (
                  <p>No items match your search.</p>
                )}
              </div>
            ) : (
              <ul className="ledger">
                {visible.map((item) => (
                  <ItemRow
                    key={item.id}
                    item={item}
                    onEdit={() => setEditing({ mode: 'edit', item })}
                    onDelete={() => remove(item)}
                  />
                ))}
              </ul>
            )}
          </>
        )}
      </main>
    </div>
  );
}

/** Everything the vault's integrity checks found, one alert per kind. */
function WarningList({ warnings }: { warnings: VaultWarnings }) {
  const messages: string[] = [];
  const { failedIds, rolledBackIds, missingIds, unexpectedIds, manifest } = warnings;
  if (failedIds.length) {
    messages.push(
      `${failedIds.length} item(s) could not be decrypted. They may have been corrupted or tampered with on the server.`,
    );
  }
  if (rolledBackIds.length) {
    messages.push(
      `${rolledBackIds.length} item(s) are older than a version this browser has already seen, so they’re hidden. The server may have rolled them back.`,
    );
  }
  if (missingIds.length) {
    messages.push(
      `${missingIds.length} item(s) in your vault weren’t returned by the server. It may be hiding them.`,
    );
  }
  if (unexpectedIds.length) {
    messages.push(
      `${unexpectedIds.length} item(s) returned by the server aren’t part of your vault (for example, deleted items brought back), so they’re hidden.`,
    );
  }
  if (manifest === 'tampered') {
    messages.push(
      'Your vault’s item list failed its integrity check. It may have been tampered with.',
    );
  }
  if (manifest === 'stale') {
    messages.push(
      'The server returned an older copy of your vault than this browser has already seen. It may have been rolled back.',
    );
  }
  if (manifest === 'missing') {
    messages.push(
      'Your vault’s item list is missing from the server, though this browser has seen one before.',
    );
  }
  return (
    <>
      {messages.map((message) => (
        <p key={message} className="error" role="alert">
          {message}
        </p>
      ))}
    </>
  );
}
