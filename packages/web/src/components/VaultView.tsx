import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, api } from '../api';
import { AUTO_LOCK_OPTIONS_MINUTES } from '../lib/autoLockSetting';
import {
  decryptVaultItems,
  emptyItem,
  encryptNewItem,
  encryptNextRevision,
  filterItems,
  isLegacyItem,
  toVaultItem,
  type VaultItem,
  type VaultItemData,
} from '../vault/items';
import { createRevisionLedger } from '../vault/revisionLedger';
import type { VaultSession } from '../vault/session';
import { Emblem, KeyholeIcon } from './Emblem';
import { ItemForm } from './ItemForm';
import { ItemRow } from './ItemRow';
import { PasswordGenerator } from './PasswordGenerator';
import { SecurityPanel } from './SecurityPanel';

interface Props {
  session: VaultSession;
  autoLockMinutes: number;
  onChangeAutoLock: (minutes: number) => void;
  /** Pass a reason only when the lock wasn't the user's own action. */
  onLock: (reason?: string) => void;
  onLogOut: () => void;
}

type Editing = { mode: 'new' } | { mode: 'edit'; item: VaultItem } | null;

const SESSION_EXPIRED = 'Your session expired. Enter your master password to continue.';

const isStaleRevision = (err: unknown) =>
  err instanceof ApiError && err.status === 409 && 'current_revision' in err.details;

/**
 * Holds every decrypted item in component state. When the vault locks, App
 * unmounts this component and all of it is discarded.
 */
export function VaultView({ session, autoLockMinutes, onChangeAutoLock, onLock, onLogOut }: Props) {
  const [items, setItems] = useState<VaultItem[] | null>(null);
  const [failedIds, setFailedIds] = useState<string[]>([]);
  const [rolledBackIds, setRolledBackIds] = useState<string[]>([]);
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<Editing>(null);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ledger = useMemo(() => createRevisionLedger(session.email), [session.email]);

  function handleError(err: unknown) {
    if (err instanceof ApiError && err.status === 401) onLock(SESSION_EXPIRED);
    else setError(err instanceof Error ? err.message : 'Something went wrong');
  }

  /**
   * Re-saves items from before ciphertexts were bound to their id and
   * revision, so they get the same rollback and swap protection. Best
   * effort: anything that fails is retried on the next load.
   */
  const upgradeLegacyItems = useCallback(
    async (loaded: VaultItem[]): Promise<VaultItem[]> => {
      const upgraded = [...loaded];
      for (const [index, item] of loaded.entries()) {
        if (!isLegacyItem(item)) continue;
        try {
          const response = await api.updateItem(
            session.token,
            await encryptNextRevision(item, item, session.vaultKey),
          );
          upgraded[index] = toVaultItem(response, item);
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) throw err;
        }
      }
      ledger.record(upgraded);
      return upgraded;
    },
    [session, ledger],
  );

  const load = useCallback(async () => {
    const { items: encrypted } = await api.listItems(session.token);
    const result = await decryptVaultItems(encrypted, session.vaultKey, ledger);
    setFailedIds(result.failedIds);
    setRolledBackIds(result.rolledBackIds);
    setItems(await upgradeLegacyItems(result.items));
  }, [session, ledger, upgradeLegacyItems]);

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
        const payload = await encryptNextRevision(editing.item, data, session.vaultKey);
        const response = await api.updateItem(session.token, payload);
        ledger.record([response]);
        setItems((prev) =>
          (prev ?? []).map((item) =>
            item.id === response.id ? toVaultItem(response, data) : item,
          ),
        );
      } else {
        const response = await api.createItem(
          session.token,
          await encryptNewItem(data, session.vaultKey),
        );
        ledger.record([response]);
        setItems((prev) => [...(prev ?? []), toVaultItem(response, data)]);
      }
      setEditing(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onLock(SESSION_EXPIRED);
      if (isStaleRevision(err)) {
        // Saved from another device or the extension since this page loaded.
        await load().catch(handleError);
        throw new Error(
          'This item was changed elsewhere since you opened it. The vault has been reloaded; open the item again to make your change.',
          { cause: err },
        );
      }
      throw err;
    }
  }

  async function remove(item: VaultItem) {
    if (!window.confirm(`Delete ${item.site}?`)) return;
    try {
      await api.deleteItem(session.token, item.id);
      ledger.markDeleted(item.id);
      setItems((prev) => (prev ?? []).filter((other) => other.id !== item.id));
    } catch (err) {
      handleError(err);
    }
  }

  const count = items?.length ? `${items.length} ${items.length === 1 ? 'login' : 'logins'}` : null;
  const unreadable = failedIds.length + rolledBackIds.length;

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
        {failedIds.length > 0 && (
          <p className="error" role="alert">
            {failedIds.length} item(s) could not be decrypted. They may have been corrupted or
            tampered with on the server.
          </p>
        )}
        {rolledBackIds.length > 0 && (
          <p className="error" role="alert">
            {rolledBackIds.length} item(s) are older than a version this browser has already seen,
            so they’re hidden. The server may have rolled them back.
          </p>
        )}

        {showSecurity ? (
          <SecurityPanel
            session={session}
            items={items}
            changeBlockedReason={
              unreadable > 0
                ? 'Some items couldn’t be read (see above), so the vault can’t be re-encrypted under a new key without losing them.'
                : null
            }
            onPasswordChanged={(updated) => {
              ledger.record(updated);
              setItems(updated);
            }}
            onSignedOutEverywhere={onLogOut}
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
