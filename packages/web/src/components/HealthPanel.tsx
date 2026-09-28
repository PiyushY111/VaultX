import { useEffect, useState } from 'react';
import { OLD_AFTER_DAYS, checkPasswordHealth, type HealthReport } from '../lib/passwordHealth';
import type { VaultItem } from '../vault/items';

interface Props {
  /** Every verified item in the vault. Null while loading. */
  items: VaultItem[] | null;
  onEdit: (item: VaultItem) => void;
  onClose: () => void;
}

type Filter = 'all' | 'weak' | 'reused' | 'old';

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

export function HealthPanel({ items, onEdit, onClose }: Props) {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [filter, setFilter] = useState<Filter>('all');

  useEffect(() => {
    if (!items) return;
    let active = true;
    setReport(null);
    checkPasswordHealth(items).then((result) => active && setReport(result));
    return () => {
      active = false;
    };
  }, [items]);

  const shown =
    report?.issues.filter(
      (issue) =>
        filter === 'all' ||
        (filter === 'weak' && issue.weak) ||
        (filter === 'reused' && issue.reusedWith) ||
        (filter === 'old' && issue.ageDays !== null),
    ) ?? [];

  const tiles: [Filter, string, number][] = report
    ? [
        ['weak', 'Weak', report.weak],
        ['reused', 'Reused', report.reused],
        ['old', 'Old', report.old],
      ]
    : [];

  return (
    <section className="security" aria-label="Password health">
      <div className="vault-head">
        <h2>Password health</h2>
        <button type="button" className="btn btn-quiet" onClick={onClose}>
          Back to vault
        </button>
      </div>
      <p className="hint">
        Checked on this device only; nothing about your passwords is sent anywhere.
      </p>

      {report === null ? (
        <p className="quiet-state">Checking your passwords…</p>
      ) : report.checked === 0 ? (
        <p className="quiet-state">There are no passwords in your vault to check yet.</p>
      ) : (
        <>
          <p role="status" className={report.issues.length ? 'warning' : 'notice'}>
            {report.issues.length === 0
              ? `All ${plural(report.checked, 'password')} look good.`
              : `${plural(report.issues.length, 'login')} of ${report.checked} could use a better password.`}
          </p>
          <div className="health-tiles" role="group" aria-label="Filter by problem">
            <button
              type="button"
              className="health-tile"
              aria-pressed={filter === 'all'}
              onClick={() => setFilter('all')}
            >
              <strong>{report.issues.length}</strong> All problems
            </button>
            {tiles.map(([key, label, count]) => (
              <button
                key={key}
                type="button"
                className="health-tile"
                data-kind={key}
                aria-pressed={filter === key}
                onClick={() => setFilter(key)}
              >
                <strong>{count}</strong> {label}
              </button>
            ))}
          </div>

          {shown.length > 0 && (
            <ul className="ledger" aria-label="Logins to fix">
              {shown.map(({ item, weak, reusedWith, ageDays }) => (
                <li key={item.id} className="entry health-entry" aria-label={item.site}>
                  <div className="entry-body">
                    <strong className="entry-site">{item.site}</strong>
                    {item.username && <span className="entry-user">{item.username}</span>}
                    <ul className="health-reasons">
                      {weak && (
                        <li data-kind="weak">
                          Weak ({weak.label.toLowerCase()}){weak.warning ? `: ${weak.warning}` : ''}
                        </li>
                      )}
                      {reusedWith > 0 && (
                        <li data-kind="reused">
                          Same password as {plural(reusedWith, 'other login')}
                        </li>
                      )}
                      {ageDays !== null && (
                        <li data-kind="old">Not saved in {Math.floor(ageDays / 30)} months</li>
                      )}
                    </ul>
                  </div>
                  <div className="entry-actions">
                    <button type="button" className="btn" onClick={() => onEdit(item)}>
                      Change password
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          <p className="hint">
            “Old” means the login hasn’t been saved in over {OLD_AFTER_DAYS / 365} year (VaultX
            doesn’t record when just the password changed). Reused passwords are the most urgent:
            one breached site exposes the others. Use the generator in the edit form for a strong,
            unique one.
          </p>
        </>
      )}
    </section>
  );
}
