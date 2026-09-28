import { useState } from 'react';
import type { PendingBaseline } from '../vault/sync';

const formatDate = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

const REASONS: Record<PendingBaseline['reason'], string> = {
  none: 'This vault was created before VaultX kept an encrypted list of your items, so there is nothing to check what the server sent against.',
  missing:
    'This browser has seen an encrypted list of your items for this vault before, but the server no longer has one. That can mean the server lost data, or is hiding changes.',
  tampered:
    'The server’s encrypted list of your items doesn’t open with your vault key, so it can’t be trusted: it was damaged, or written by someone without your key.',
};

/**
 * Asks before adopting a vault with no trustworthy manifest as the baseline.
 * Accepting makes the items shown the standard that later loads are checked
 * against; that's only as good as those items, which is why it's asked.
 */
export function BaselinePrompt({
  baseline,
  declined,
  onAccept,
  onDecline,
  onReview,
}: {
  baseline: PendingBaseline;
  declined: boolean;
  onAccept: () => Promise<void>;
  onDecline: () => void;
  onReview: () => void;
}) {
  const [busy, setBusy] = useState(false);

  if (declined) {
    return (
      <div className="warnings" role="status" aria-label="Vault not confirmed">
        <strong>This vault isn’t confirmed yet, so it’s read-only.</strong>
        <span>Nothing can be added, changed or deleted until you confirm it.</span>
        <div className="row">
          <button type="button" className="btn" onClick={onReview}>
            Review
          </button>
        </div>
      </div>
    );
  }

  const { itemCount, oldestUpdate, newestUpdate, reason, previouslySeenVersion } = baseline;
  return (
    <section className="sheet baseline" role="region" aria-label="Confirm this vault">
      <h3>Use this as the trusted baseline?</h3>
      <p>{REASONS[reason]}</p>
      <p>
        The server sent <strong>{itemCount}</strong> item{itemCount === 1 ? '' : 's'} that opened
        with your key
        {newestUpdate &&
          oldestUpdate &&
          `, last changed between ${formatDate(oldestUpdate)} and ${formatDate(newestUpdate)} (the server’s dates)`}
        .
        {previouslySeenVersion > 0 &&
          ` Before, this browser had seen version ${previouslySeenVersion} of the list.`}
      </p>
      <p className="hint">
        If this looks like your whole vault, confirm it: VaultX will save an encrypted list of these
        items, and every later load, on any device, is checked against it. If something is missing
        or looks old, choose “Not now”: the vault stays read-only, and you can check from another
        device first (compare the vault checkpoint on the Security page).
      </p>
      <div className="row sheet-actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void onAccept().finally(() => setBusy(false));
          }}
        >
          {busy ? 'Saving…' : 'Use as trusted baseline'}
        </button>
        <button type="button" className="btn btn-quiet" onClick={onDecline} disabled={busy}>
          Not now
        </button>
      </div>
    </section>
  );
}
