import { useEffect, useState } from 'react';
import { checkBreaches } from '../lib/breachCheck';
import { OLD_AFTER_DAYS, checkPasswordHealth, type HealthReport } from '../lib/passwordHealth';
import { isLogin, type VaultItem } from '../vault/items';

interface Props {
  /** Every verified item in the vault. Null while loading. */
  items: VaultItem[] | null;
  onEdit: (item: VaultItem) => void;
  onClose: () => void;
}

type Filter = 'all' | 'breached' | 'weak' | 'reused' | 'old';
type BreachState =
  | { kind: 'idle' }
  | { kind: 'checking'; done: number; total: number }
  | { kind: 'done'; counts: Map<string, number> }
  | { kind: 'error'; message: string };

const plural = (count: number, word: string, pluralWord = `${word}s`) =>
  `${count} ${count === 1 ? word : pluralWord}`;

export function HealthPanel({ items, onEdit, onClose }: Props) {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [breach, setBreach] = useState<BreachState>({ kind: 'idle' });
  const breaches = breach.kind === 'done' ? breach.counts : undefined;

  useEffect(() => {
    if (!items) return;
    let active = true;
    setReport(null);
    checkPasswordHealth(items, new Date(), breaches).then((result) => active && setReport(result));
    return () => {
      active = false;
    };
  }, [items, breaches]);

  async function runBreachCheck() {
    if (!items) return;
    const passwords = items.filter((item) => isLogin(item) && item.password).map((i) => i.password);
    setBreach({ kind: 'checking', done: 0, total: 0 });
    try {
      const counts = await checkBreaches(passwords, {
        onProgress: (done, total) => setBreach({ kind: 'checking', done, total }),
      });
      setBreach({ kind: 'done', counts });
    } catch (error) {
      setBreach({
        kind: 'error',
        message: error instanceof Error ? error.message : 'The breach check failed.',
      });
    }
  }

  const shown =
    report?.issues.filter(
      (issue) =>
        filter === 'all' ||
        (filter === 'breached' && issue.breaches) ||
        (filter === 'weak' && issue.weak) ||
        (filter === 'reused' && issue.reusedWith) ||
        (filter === 'old' && issue.ageDays !== null),
    ) ?? [];

  const tiles: [Filter, string, number][] = report
    ? [
        ...(report.breached !== null
          ? [['breached', 'Breached', report.breached] as [Filter, string, number]]
          : []),
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
        Checked on this device; nothing about your passwords is sent anywhere unless you run the
        breach check below.
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
              {shown.map(({ item, weak, reusedWith, ageDays, breaches: found }) => (
                <li key={item.id} className="entry health-entry" aria-label={item.site}>
                  <div className="entry-body">
                    <strong className="entry-site">{item.site}</strong>
                    {item.username && <span className="entry-user">{item.username}</span>}
                    <ul className="health-reasons">
                      {found ? (
                        <li data-kind="breached">
                          Found in {plural(found, 'known data breach', 'known data breaches')}:
                          change it now
                        </li>
                      ) : null}
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
                        <li data-kind="old">
                          Password unchanged for {Math.floor(ageDays / 30)} months
                        </li>
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
            “Old” means the password has been in use for over {OLD_AFTER_DAYS / 365} year, going by
            its password history (or, for logins from before history was kept, when the item was
            created). Reused passwords are the most urgent: one breached site exposes the others.
            Use the generator in the edit form for a strong, unique one.
          </p>
        </>
      )}

      <div className="sheet" role="region" aria-label="Breach check">
        <h3>Check for breached passwords</h3>
        <p className="hint">
          Compares your passwords with Have I Been Pwned’s list of passwords exposed in data
          breaches. Only the first five characters of each password’s hash are sent, never the
          password or the full hash; the comparison happens here. That service will still learn that
          someone checked some passwords from your address, which is why this is off unless you run
          it.
        </p>
        {breach.kind === 'error' && (
          <p className="error" role="alert">
            {breach.message}
          </p>
        )}
        {breach.kind === 'done' && report?.breached !== null && report !== null && (
          <p role="status" className={report.breached ? 'warning' : 'notice'}>
            {report.breached
              ? `${plural(report.breached, 'password')} appear in known breaches. Change them first.`
              : 'None of your passwords appear in known breaches.'}
          </p>
        )}
        <div className="row sheet-actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={breach.kind === 'checking' || !items}
            onClick={runBreachCheck}
          >
            {breach.kind === 'checking'
              ? `Checking… ${breach.done} of ${breach.total || '?'}`
              : breach.kind === 'done'
                ? 'Check again'
                : 'Check against Have I Been Pwned'}
          </button>
        </div>
      </div>
    </section>
  );
}
