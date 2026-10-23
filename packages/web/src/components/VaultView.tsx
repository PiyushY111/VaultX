import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError } from '../api';
import { AUTO_LOCK_OPTIONS_MINUTES } from '../lib/autoLockSetting';
import {
  emptyItem,
  filterItems,
  isTrashed,
  normalizeFolder,
  withPasswordHistory,
  type VaultItem,
  type VaultItemData,
} from '../vault/items';
import {
  buildFolderTree,
  folderPaths,
  moveFolder,
  parentFolder,
  withFolder,
} from '../vault/folders';
import { createRevisionLedger } from '../vault/revisionLedger';
import type { VaultSession } from '../vault/session';
import {
  VaultChangedError,
  VaultSync,
  countWarnings,
  type LoadedVault,
  type PendingBaseline,
  type VaultWarnings,
} from '../vault/sync';
import { formatCheckpoint, vaultCheckpoint } from '@password-manager/crypto';
import { BaselinePrompt } from './BaselinePrompt';
import { EmergencyKit } from './EmergencyKit';
import { FolderTree } from './FolderTree';
import { HealthPanel } from './HealthPanel';
import { Emblem, KeyholeIcon } from './Emblem';
import { ItemForm } from './ItemForm';
import { ItemRow } from './ItemRow';
import { MoveToFolderBar } from './MoveToFolderBar';
import { PasswordGenerator } from './PasswordGenerator';
import { SecurityPanel } from './SecurityPanel';
import { TransferPanel } from './TransferPanel';
import { TrashView } from './TrashView';

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

/** `from` is where to go back to when the form closes. */
type Editing = { mode: 'new' } | { mode: 'edit'; item: VaultItem; from?: View } | null;

/** The screen shown instead of the item list. */
type View = 'vault' | 'security' | 'transfer' | 'health' | 'trash';

const SESSION_EXPIRED = 'Your session expired. Enter your master password to continue.';
const CHANGED_ELSEWHERE = 'Your vault was changed elsewhere, so it has been reloaded. Try again.';

/** How long "Moved to trash · Undo" stays up. */
const UNDO_MS = 8000;

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
  const [baseline, setBaseline] = useState<PendingBaseline | null>(null);
  const [baselineDeclined, setBaselineDeclined] = useState(false);
  const [kitCheckpoint, setKitCheckpoint] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [tag, setTag] = useState<string | null>(null);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  /** null for all items, '' for items in no folder, or a folder's path. */
  const [folder, setFolder] = useState<string | null>(null);
  /** Ids picked to move to a folder, while selecting (null otherwise). */
  const [selecting, setSelecting] = useState<ReadonlySet<string> | null>(null);
  const [editing, setEditing] = useState<Editing>(null);
  const [showGenerator, setShowGenerator] = useState(false);
  const [view, setView] = useState<View>('vault');
  const [showKit, setShowKit] = useState(justSignedUp);
  const [error, setError] = useState<string | null>(null);
  /** The item just moved to the trash, while its Undo is offered. */
  const [justTrashed, setJustTrashed] = useState<VaultItem | null>(null);
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
    setBaseline(loaded.baseline);
    setItems(loaded.items);
  }, []);

  const getCheckpoint = useCallback(async () => {
    const manifest = sync.current!.trustedManifest();
    return manifest ? vaultCheckpoint(manifest, session.vaultKey) : null;
  }, [session.vaultKey]);

  // The emergency kit prints the checkpoint as of now.
  useEffect(() => {
    if (!showKit || items === null) return;
    let active = true;
    void getCheckpoint().then((checkpoint) => {
      if (active) setKitCheckpoint(checkpoint ? formatCheckpoint(checkpoint) : null);
    });
    return () => {
      active = false;
    };
  }, [showKit, items, getCheckpoint]);

  async function acceptBaseline() {
    try {
      const upgraded = await sync.current!.acceptBaseline(items ?? []);
      setItems(upgraded);
      setBaseline(null);
      setBaselineDeclined(false);
    } catch (err) {
      handleError(err);
    }
  }

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

  useEffect(() => {
    if (!justTrashed) return;
    const timer = setTimeout(() => setJustTrashed(null), UNDO_MS);
    return () => clearTimeout(timer);
  }, [justTrashed]);

  // Search runs over the decrypted items in memory; the query never leaves the browser.
  // filterItems leaves out the trash, so it's only ever listed in its own view.
  const visible = useMemo(
    () => filterItems(items ?? [], query, { tag, favoritesOnly, folder }),
    [items, query, tag, favoritesOnly, folder],
  );
  const live = useMemo(() => (items ?? []).filter((item) => !isTrashed(item)), [items]);
  const trashed = useMemo(() => (items ?? []).filter(isTrashed), [items]);
  const folderTree = useMemo(() => buildFolderTree(live), [live]);
  const allFolders = useMemo(() => folderPaths(folderTree), [folderTree]);
  const allTags = useMemo(() => {
    const seen = new Map<string, string>();
    for (const item of live)
      for (const t of item.tags ?? []) if (!seen.has(t.toLowerCase())) seen.set(t.toLowerCase(), t);
    return [...seen.values()].sort((a, b) =>
      a.localeCompare(b, undefined, { sensitivity: 'base' }),
    );
  }, [live]);

  function closeEditor() {
    if (editing?.mode === 'edit' && editing.from) setView(editing.from);
    setEditing(null);
  }

  async function save(data: VaultItemData) {
    try {
      if (editing?.mode === 'edit') {
        const saved = await sync.current!.update(
          editing.item,
          withPasswordHistory(editing.item, data),
        );
        setItems((prev) => (prev ?? []).map((item) => (item.id === saved.id ? saved : item)));
      } else {
        const saved = await sync.current!.create(data);
        setItems((prev) => [...(prev ?? []), saved]);
      }
      closeEditor();
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

  /** For writes made from a button: a vault changed elsewhere is reloaded first. */
  async function handleWriteError(err: unknown) {
    if (err instanceof VaultChangedError || isStaleRevision(err)) {
      await load().catch(handleError);
      setError(CHANGED_ELSEWHERE);
    } else {
      handleError(err);
    }
  }

  const replaceItem = (saved: VaultItem) =>
    setItems((prev) => (prev ?? []).map((other) => (other.id === saved.id ? saved : other)));
  const dropItems = (ids: readonly string[]) =>
    setItems((prev) => (prev ?? []).filter((other) => !ids.includes(other.id)));

  async function toggleFavorite(item: VaultItem) {
    try {
      replaceItem(await sync.current!.update(item, { ...item, favorite: !item.favorite }));
    } catch (err) {
      await handleWriteError(err);
    }
  }

  // No "are you sure?": it's undoable, from the notice and from the trash.
  async function moveToTrash(item: VaultItem) {
    try {
      const saved = await sync.current!.trash(item);
      replaceItem(saved);
      setJustTrashed(saved);
    } catch (err) {
      await handleWriteError(err);
    }
  }

  async function restore(item: VaultItem) {
    setJustTrashed(null);
    try {
      replaceItem(await sync.current!.restore(item));
    } catch (err) {
      await handleWriteError(err);
    }
  }

  /** For batch writes: also reloads if one stopped partway, as some batches went through. */
  async function handleBatchError(err: unknown) {
    await handleWriteError(err);
    const partial = err instanceof Error && !(err instanceof ApiError) && err.cause;
    if (partial && !(err instanceof VaultChangedError)) await load().catch(handleError);
  }

  async function deleteForever(ids: string[]) {
    try {
      await sync.current!.removeMany(ids);
      dropItems(ids);
    } catch (err) {
      await handleBatchError(err);
    }
  }

  /** Saves folder changes, in as few requests as the batch size allows. True if all saved. */
  async function saveFolderChanges(
    changes: { item: VaultItem; data: VaultItemData }[],
  ): Promise<boolean> {
    try {
      const saved = new Map((await sync.current!.updateMany(changes)).map((it) => [it.id, it]));
      setItems((prev) => (prev ?? []).map((other) => saved.get(other.id) ?? other));
      return true;
    } catch (err) {
      await handleBatchError(err);
      return false;
    }
  }

  // Folder changes cover the trash too, so a restored item comes back to the renamed folder.
  async function renameFolder(from: string, to: string) {
    const target = normalizeFolder(to); // Throws for a path too deep or too long.
    if (!target) throw new Error('Enter a folder name.');
    if (await saveFolderChanges(moveFolder(items ?? [], from, target))) setFolder(target);
  }

  async function deleteFolder(path: string) {
    const parent = parentFolder(path);
    if (await saveFolderChanges(moveFolder(items ?? [], path, parent))) setFolder(parent ?? null);
  }

  async function moveSelected(target: string) {
    const changes = (items ?? [])
      .filter((item) => selecting?.has(item.id))
      .map((item) => ({ item, data: withFolder(item, target) }))
      .filter(({ item, data }) => data.folder !== item.folder);
    if (await saveFolderChanges(changes)) setSelecting(null);
  }

  const toggleSelected = (id: string, on: boolean) =>
    setSelecting((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  const count = live.length ? `${live.length} ${live.length === 1 ? 'item' : 'items'}` : null;

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
            aria-pressed={view === 'security'}
            onClick={() => {
              setEditing(null);
              setView((current) => (current === 'security' ? 'vault' : 'security'));
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
        {baseline && (
          <BaselinePrompt
            baseline={baseline}
            declined={baselineDeclined}
            onAccept={acceptBaseline}
            onDecline={() => setBaselineDeclined(true)}
            onReview={() => setBaselineDeclined(false)}
          />
        )}
        {showKit && (
          <EmergencyKit
            email={session.email}
            onDone={() => setShowKit(false)}
            firstTime
            checkpoint={kitCheckpoint}
          />
        )}

        {view === 'health' ? (
          <HealthPanel
            items={items && live}
            onEdit={(item) => {
              setView('vault');
              setEditing({ mode: 'edit', item, from: 'health' });
            }}
            onClose={() => setView('vault')}
          />
        ) : view === 'transfer' ? (
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
            onClose={() => setView('vault')}
          />
        ) : view === 'trash' ? (
          <TrashView
            items={trashed}
            now={new Date()}
            onRestore={restore}
            onDeleteForever={(item) => deleteForever([item.id])}
            onEmpty={() => deleteForever(trashed.map((item) => item.id))}
            onClose={() => setView('vault')}
          />
        ) : view === 'security' ? (
          <SecurityPanel
            session={session}
            items={items}
            changeBlockedReason={
              baseline
                ? 'Confirm this vault as your trusted baseline first (see the vault page).'
                : countWarnings(warnings) > 0
                  ? 'Some items couldn’t be verified (see above), so the vault can’t be re-encrypted under a new key without losing them.'
                  : null
            }
            getCheckpoint={getCheckpoint}
            currentManifest={() => sync.current!.currentManifest()}
            onPasswordChanged={(updated, manifest) => {
              sync.current!.replaceManifest(manifest);
              ledger.record(updated);
              setItems(updated);
            }}
            onShowEmergencyKit={() => {
              setView('vault');
              setShowKit(true);
            }}
            onSignedOutEverywhere={onLogOut}
            onAccountDeleted={onAccountDeleted}
            onSessionExpired={() => onLock(SESSION_EXPIRED)}
            onClose={() => setView('vault')}
          />
        ) : editing ? (
          <ItemForm
            key={editing.mode === 'edit' ? editing.item.id : 'new'}
            initial={
              editing.mode === 'edit' ? editing.item : withFolder(emptyItem(), folder || undefined) // A new item starts in the folder being viewed.
            }
            isNew={editing.mode === 'new'}
            onSave={save}
            onCancel={closeEditor}
            folders={allFolders}
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
                disabled={baseline !== null}
                title={baseline ? 'Confirm this vault first' : undefined}
                onClick={() => setEditing({ mode: 'new' })}
              >
                Add item
              </button>
              <button type="button" className="btn" onClick={() => setView('transfer')}>
                Import / export
              </button>
              <button type="button" className="btn" onClick={() => setView('health')}>
                Password health
              </button>
              <button
                type="button"
                className="btn"
                aria-expanded={showGenerator}
                onClick={() => setShowGenerator((v) => !v)}
              >
                {showGenerator ? 'Hide generator' : 'Password generator'}
              </button>
              {live.length > 0 && (
                <button
                  type="button"
                  className="btn btn-quiet"
                  aria-pressed={selecting !== null}
                  onClick={() => setSelecting((prev) => (prev ? null : new Set()))}
                >
                  {selecting ? 'Done selecting' : 'Select'}
                </button>
              )}
              {trashed.length > 0 && (
                <button type="button" className="btn btn-quiet" onClick={() => setView('trash')}>
                  Trash ({trashed.length})
                </button>
              )}
            </div>
            {justTrashed && (
              <p className="notice row" role="status">
                Moved {justTrashed.site} to the trash.
                <button
                  type="button"
                  className="btn btn-quiet"
                  onClick={() => void restore(justTrashed)}
                >
                  Undo
                </button>
              </p>
            )}
            {showGenerator && <PasswordGenerator />}
            {selecting && (
              <MoveToFolderBar
                count={selecting.size}
                folders={allFolders}
                onMove={moveSelected}
                onCancel={() => setSelecting(null)}
              />
            )}
            {folderTree.length > 0 && (
              <FolderTree
                tree={folderTree}
                total={live.length}
                looseCount={live.filter((item) => !item.folder).length}
                selected={folder}
                onSelect={setFolder}
                onRename={renameFolder}
                onDelete={(path) => void deleteFolder(path)}
              />
            )}
            {(allTags.length > 0 || live.some((item) => item.favorite)) && (
              <div className="chips" role="group" aria-label="Filter by tag">
                <button
                  type="button"
                  className="chip"
                  aria-pressed={favoritesOnly}
                  onClick={() => setFavoritesOnly((v) => !v)}
                >
                  ★ Favorites
                </button>
                {allTags.map((t) => (
                  <button
                    key={t}
                    type="button"
                    className="chip"
                    aria-pressed={tag?.toLowerCase() === t.toLowerCase()}
                    onClick={() => setTag((current) => (current === t ? null : t))}
                  >
                    {t}
                  </button>
                ))}
              </div>
            )}
            {items === null ? (
              <p className="quiet-state">Decrypting vault…</p>
            ) : visible.length === 0 ? (
              <div className="quiet-state">
                {live.length === 0 ? (
                  <>
                    <p>Your vault is empty.</p>
                    <p className="hint">
                      Add your first login. It’s encrypted on this device before it’s saved.
                    </p>
                  </>
                ) : (
                  <p>No items match your search or filters.</p>
                )}
              </div>
            ) : (
              <ul className="ledger">
                {visible.map((item) => (
                  <ItemRow
                    key={item.id}
                    item={item}
                    onEdit={() => setEditing({ mode: 'edit', item })}
                    onTrash={() => moveToTrash(item)}
                    onToggleFavorite={() => toggleFavorite(item)}
                    {...(selecting && {
                      selected: selecting.has(item.id),
                      onSelectedChange: (on: boolean) => toggleSelected(item.id, on),
                    })}
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
