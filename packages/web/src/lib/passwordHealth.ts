import { isLogin, passwordChangedAt, type VaultItem } from '../vault/items';
import { MIN_MASTER_PASSWORD_SCORE, estimateStrength, type Strength } from './passwordStrength';

/**
 * The password health report: which logins have weak, reused, old or (if
 * the user opted into the breach check) breached passwords. It runs over the
 * decrypted items in memory; only the breach check talks to the network,
 * and only with hash prefixes (see breachCheck.ts).
 */

/** A password counts as old once it has been in use for this long. */
export const OLD_AFTER_DAYS = 365;

export interface HealthIssue {
  item: VaultItem;
  /** Rated below "Strong" by zxcvbn. */
  weak: Strength | null;
  /** How many other logins use the same password (0 if none). */
  reusedWith: number;
  /** Days since the password was set, if that's more than {@link OLD_AFTER_DAYS}. */
  ageDays: number | null;
  /** Known breaches the password appears in (null if not checked). */
  breaches: number | null;
}

export interface HealthReport {
  /** Logins with at least one problem, worst first. */
  issues: HealthIssue[];
  checked: number;
  weak: number;
  reused: number;
  old: number;
  /** Null until the breach check has run. */
  breached: number | null;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export async function checkPasswordHealth(
  items: readonly VaultItem[],
  now = new Date(),
  breaches?: ReadonlyMap<string, number>,
): Promise<HealthReport> {
  const logins = items.filter((item) => isLogin(item) && item.password);

  const uses = new Map<string, number>();
  for (const item of logins) uses.set(item.password, (uses.get(item.password) ?? 0) + 1);

  const issues: HealthIssue[] = [];
  for (const item of logins) {
    const strength = await estimateStrength(item.password, [item.site, item.username]);
    const ageDays = Math.floor(
      (now.getTime() - new Date(passwordChangedAt(item)).getTime()) / DAY_MS,
    );
    const issue: HealthIssue = {
      item,
      weak: strength.score < MIN_MASTER_PASSWORD_SCORE ? strength : null,
      reusedWith: uses.get(item.password)! - 1,
      ageDays: Number.isFinite(ageDays) && ageDays > OLD_AFTER_DAYS ? ageDays : null,
      breaches: breaches ? (breaches.get(item.password) ?? 0) : null,
    };
    if (issue.weak || issue.reusedWith || issue.ageDays !== null || issue.breaches) {
      issues.push(issue);
    }
  }

  // Breached, then weak and reused, then old; within those, the worst first.
  const rank = (issue: HealthIssue) =>
    (issue.breaches ? 100 : 0) +
    (issue.weak ? 4 - issue.weak.score : 0) * 10 +
    (issue.reusedWith ? 5 + Math.min(issue.reusedWith, 4) : 0) +
    (issue.ageDays !== null ? 1 : 0);
  issues.sort(
    (a, b) =>
      rank(b) - rank(a) ||
      a.item.site.localeCompare(b.item.site, undefined, { sensitivity: 'base' }),
  );

  return {
    issues,
    checked: logins.length,
    weak: issues.filter((issue) => issue.weak).length,
    reused: issues.filter((issue) => issue.reusedWith).length,
    old: issues.filter((issue) => issue.ageDays !== null).length,
    breached: breaches ? issues.filter((issue) => issue.breaches).length : null,
  };
}
