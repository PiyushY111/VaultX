import { beforeEach, describe, expect, it } from 'vitest';
import { createRevisionLedger, revisionStorageKey } from './revisionLedger';

const EMAIL = 'alice@example.com';

beforeEach(() => {
  localStorage.clear();
});

describe('revision ledger', () => {
  it('flags only items older than the highest revision seen', () => {
    const ledger = createRevisionLedger(EMAIL);
    ledger.record([
      { id: 'a', revision: 3 },
      { id: 'b', revision: 1 },
    ]);
    ledger.record([{ id: 'a', revision: 2 }]); // never lowers
    const rollbacks = ledger.findRollbacks([
      { id: 'a', revision: 2 },
      { id: 'b', revision: 2 },
      { id: 'new', revision: 1 },
    ]);
    expect([...rollbacks]).toEqual(['a']);
  });

  it('remembers across page loads, per account, and stores only ids and numbers', () => {
    createRevisionLedger(EMAIL).record([{ id: 'a', revision: 5 }]);
    expect(createRevisionLedger(EMAIL).findRollbacks([{ id: 'a', revision: 4 }]).size).toBe(1);
    expect(
      createRevisionLedger('bob@example.com').findRollbacks([{ id: 'a', revision: 4 }]).size,
    ).toBe(0);
    expect(JSON.parse(localStorage.getItem(revisionStorageKey(EMAIL))!)).toEqual({ a: 5 });
  });

  it('treats a deleted item that reappears as rolled back', () => {
    const ledger = createRevisionLedger(EMAIL);
    ledger.record([{ id: 'a', revision: 2 }]);
    ledger.markDeleted('a');
    expect(ledger.findRollbacks([{ id: 'a', revision: 2 }]).size).toBe(1);
  });

  it('still works in memory when storage is unavailable or corrupt', () => {
    localStorage.setItem(revisionStorageKey(EMAIL), 'not json');
    const ledger = createRevisionLedger(EMAIL);
    ledger.record([{ id: 'a', revision: 2 }]);
    expect(ledger.findRollbacks([{ id: 'a', revision: 1 }]).size).toBe(1);

    const memoryOnly = createRevisionLedger(EMAIL, null);
    memoryOnly.record([{ id: 'b', revision: 2 }]);
    expect(memoryOnly.findRollbacks([{ id: 'b', revision: 1 }]).size).toBe(1);
  });
});
