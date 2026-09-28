import type { VaultItem } from '../vault/items';
import { MIN_MASTER_PASSWORD_SCORE, estimateStrength, type Strength } from './passwordStrength';

/**
 * The password health report: which logins have weak, reused or old
 * passwords. It runs entirely on this device, over the decrypted items in
 * memory; nothing about it is sent anywhere.
 */

/** A login counts as old once it hasn't been saved for this long. */
export const OLD_AFTER_DAYS = 365;

export interface HealthIssue {
  item: VaultItem;
  /** Rated below "Strong" by zxcvbn. */
  weak: Strength | null;
  /** How many other logins use the same password (0 if none). */
  reusedWith: number;
  /** Days since the login was last saved, if that's more than {@link OLD_AFTER_DAYS}. */
  ageDays: number | null;
}

export interface HealthReport {
  /** Logins with at least one problem, worst first. */
  issues: HealthIssue[];
  checked: number;
  weak: number;
  reused: number;
  old: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export async function checkPasswordHealth(
  items: readonly VaultItem[],
  now = new Date(),
): Promise<HealthReport> {
  const withPassword = items.filter((item) => item.password);

  const uses = new Map<string, number>();
  for (const item of withPassword) uses.set(item.password, (uses.get(item.password) ?? 0) + 1);

  const issues: HealthIssue[] = [];
  for (const item of withPassword) {
    const strength = await estimateStrength(item.password, [item.site, item.username]);
    const ageDays = Math.floor((now.getTime() - new Date(item.updatedAt).getTime()) / DAY_MS);
    const issue: HealthIssue = {
      item,
      weak: strength.score < MIN_MASTER_PASSWORD_SCORE ? strength : null,
      reusedWith: uses.get(item.password)! - 1,
      ageDays: Number.isFinite(ageDays) && ageDays > OLD_AFTER_DAYS ? ageDays : null,
    };
    if (issue.weak || issue.reusedWith || issue.ageDays !== null) issues.push(issue);
  }

  // Weak and reused matter more than old; within those, the weakest first.
  const rank = (issue: HealthIssue) =>
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
    checked: withPassword.length,
    weak: issues.filter((issue) => issue.weak).length,
    reused: issues.filter((issue) => issue.reusedWith).length,
    old: issues.filter((issue) => issue.ageDays !== null).length,
  };
}
