import { useEffect, useState } from 'react';

/**
 * Password strength estimates from zxcvbn (via zxcvbn-ts), which scores a
 * password by how quickly a guesser using common passwords, words, names,
 * keyboard patterns and dates would find it. It runs entirely in the browser;
 * the password is never sent anywhere.
 *
 * The dictionaries are large, so they're loaded on first use.
 */

export type Score = 0 | 1 | 2 | 3 | 4;

export interface Strength {
  score: Score;
  label: string;
  warning: string | null;
  suggestions: string[];
}

export const STRENGTH_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;

/**
 * The master password is the only thing standing between a stolen database
 * and the vault, so accounts need at least "Strong". Only this client can
 * enforce it: the server never sees the password.
 */
export const MIN_MASTER_PASSWORD_SCORE: Score = 3;

export const WEAK_MASTER_PASSWORD = `Choose a master password rated at least “${STRENGTH_LABELS[MIN_MASTER_PASSWORD_SCORE]}”. It’s the only thing protecting your vault if the server’s data is ever stolen.`;

// zxcvbn's matching is superlinear in length, and past this point a password
// is strong for length alone.
const MAX_CHECKED_LENGTH = 100;

type Checker = (password: string, userInputs: string[]) => Strength;
let checker: Promise<Checker> | null = null;

function loadChecker(): Promise<Checker> {
  checker ??= Promise.all([
    import('@zxcvbn-ts/core'),
    import('@zxcvbn-ts/language-common'),
    import('@zxcvbn-ts/language-en'),
  ]).then(([core, common, en]) => {
    const zxcvbn = new core.ZxcvbnFactory({
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
      translations: en.translations,
    });
    return (password, userInputs) => {
      const result = zxcvbn.check(password.slice(0, MAX_CHECKED_LENGTH), userInputs);
      return {
        score: result.score,
        label: STRENGTH_LABELS[result.score],
        warning: result.feedback.warning,
        suggestions: result.feedback.suggestions,
      };
    };
  });
  return checker;
}

/**
 * Estimates `password`'s strength. `userInputs` are things a guesser would
 * try first for this user or item, such as the email or site name.
 */
export async function estimateStrength(
  password: string,
  userInputs: readonly string[] = [],
): Promise<Strength> {
  const check = await loadChecker();
  return check(password, userInputs.filter(Boolean));
}

/** The strength of `password`, re-estimated shortly after it stops changing. Null while empty. */
export function usePasswordStrength(
  password: string,
  userInputs: readonly string[] = [],
): Strength | null {
  const [strength, setStrength] = useState<Strength | null>(null);
  const inputsKey = userInputs.join('\0');
  useEffect(() => {
    if (!password) {
      setStrength(null);
      return;
    }
    let active = true;
    const timer = setTimeout(() => {
      estimateStrength(password, inputsKey.split('\0'))
        .then((result) => active && setStrength(result))
        .catch(() => active && setStrength(null));
    }, 120);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [password, inputsKey]);
  return password ? strength : null;
}
