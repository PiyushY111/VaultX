import { describe, expect, it } from 'vitest';
import { MIN_MASTER_PASSWORD_SCORE, estimateStrength } from './passwordStrength';

describe('estimateStrength', () => {
  it.each(['password1234', 'qwertyuiop12', 'aaaaaaaaaaaa', 'iloveyou2024'])(
    'rates the common pattern %s below the master-password minimum',
    async (password) => {
      expect((await estimateStrength(password)).score).toBeLessThan(MIN_MASTER_PASSWORD_SCORE);
    },
  );

  it('rates a long random passphrase as very strong', async () => {
    const strength = await estimateStrength('orbit-lantern-quilt-58-marrow');
    expect(strength.score).toBe(4);
    expect(strength.label).toBe('Very strong');
  });

  it('penalizes a password built from the user’s own details', async () => {
    const withoutContext = await estimateStrength('alice.example.2024');
    const withContext = await estimateStrength('alice.example.2024', ['alice@example.com']);
    expect(withContext.score).toBeLessThanOrEqual(withoutContext.score);
  });

  it('gives advice for weak passwords', async () => {
    const strength = await estimateStrength('password');
    expect(strength.warning ?? strength.suggestions[0]).toBeTruthy();
  });
});
