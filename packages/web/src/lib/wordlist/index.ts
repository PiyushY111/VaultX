let loading: Promise<readonly string[]> | null = null;

/**
 * The EFF word list for passphrases (about 60 kB), loaded as its own chunk the
 * first time it's needed so it isn't in the main bundle. A failed load (e.g.
 * offline after an update) is retried on the next call.
 */
export function loadWordlist(): Promise<readonly string[]> {
  loading ??= import('./effLarge').then(
    (module) => module.EFF_LARGE,
    (error: unknown) => {
      loading = null;
      throw error;
    },
  );
  return loading;
}
