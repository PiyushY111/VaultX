import { describe, expect, it } from 'vitest';
import type { VaultItem } from '../vault/items';
import { checkPasswordHealth } from './passwordHealth';

const NOW = new Date('2026-09-28T00:00:00Z');
const STRONG = 'orbit-lantern-quilt-58-marrow';

let n = 0;
const item = (site: string, password: string, createdAt = '2026-09-01T00:00:00Z'): VaultItem => ({
  id: `id-${n++}`,
  revision: 1,
  site,
  username: 'alice',
  password,
  notes: '',
  createdAt,
  updatedAt: '2026-09-27T00:00:00Z',
});

describe('checkPasswordHealth', () => {
  it('is clean for strong, unique, recently saved passwords', async () => {
    const report = await checkPasswordHealth(
      [item('a.example.com', STRONG), item('b.example.com', `${STRONG}-b`)],
      NOW,
    );
    expect(report).toMatchObject({ checked: 2, weak: 0, reused: 0, old: 0, issues: [] });
  });

  it('flags weak passwords, with zxcvbn’s verdict', async () => {
    const report = await checkPasswordHealth([item('a.example.com', 'password1')], NOW);
    expect(report.weak).toBe(1);
    expect(report.issues[0]!.weak!.score).toBeLessThan(3);
  });

  it('counts a password built from the site name as weak', async () => {
    const report = await checkPasswordHealth([item('github.com', 'github.com2024')], NOW);
    expect(report.weak).toBe(1);
  });

  it('flags every login that shares a password, even a strong one', async () => {
    const report = await checkPasswordHealth(
      [item('a.example.com', STRONG), item('b.example.com', STRONG), item('c.example.com', STRONG)],
      NOW,
    );
    expect(report.reused).toBe(3);
    expect(report.issues.map((issue) => issue.reusedWith)).toEqual([2, 2, 2]);
  });

  it('dates a password from its history when there is one', async () => {
    const changed = {
      ...item('a.example.com', STRONG, '2020-01-01T00:00:00Z'),
      history: [{ password: 'previous', changedAt: '2026-09-20T00:00:00Z' }],
    };
    expect((await checkPasswordHealth([changed], NOW)).old).toBe(0);
  });

  it('only checks logins', async () => {
    const note = { ...item('Note', 'not-a-password'), type: 'note' as const };
    expect((await checkPasswordHealth([note], NOW)).checked).toBe(0);
  });

  it('reports breached passwords first once counts are given', async () => {
    const items = [item('a.example.com', STRONG), item('b.example.com', 'password1')];
    const report = await checkPasswordHealth(items, NOW, new Map([[STRONG, 3]]));
    expect(report.breached).toBe(1);
    expect(report.issues.map((issue) => [issue.item.site, issue.breaches])).toEqual([
      ['a.example.com', 3],
      ['b.example.com', 0],
    ]);
    expect((await checkPasswordHealth(items, NOW)).breached).toBeNull();
  });

  it('flags passwords in use for over a year', async () => {
    const report = await checkPasswordHealth(
      [
        item('old.example.com', STRONG, '2025-06-01T00:00:00Z'),
        item('new.example.com', `${STRONG}!`),
      ],
      NOW,
    );
    expect(report.old).toBe(1);
    expect(report.issues[0]).toMatchObject({ item: { site: 'old.example.com' }, ageDays: 484 });
  });

  it('puts the worst first, and skips logins with no password', async () => {
    const report = await checkPasswordHealth(
      [
        item('old.example.com', `${STRONG}-x`, '2024-01-01T00:00:00Z'),
        item('weak.example.com', 'password'),
        item('empty.example.com', ''),
      ],
      NOW,
    );
    expect(report.checked).toBe(2);
    expect(report.issues.map((issue) => issue.item.site)).toEqual([
      'weak.example.com',
      'old.example.com',
    ]);
  });
});
