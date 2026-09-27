import type { Settings } from '../shared/messages';
import { normalizeServerUrl } from '../shared/urls';
import type { KeyValueStore } from './storage';

// Settings are not secret and live in chrome.storage.local.

export const AUTO_LOCK_OPTIONS_MINUTES = [5, 15, 30, 60] as const;

export const DEFAULT_SETTINGS: Readonly<Settings> = Object.freeze({
  serverUrl: 'http://127.0.0.1:3000',
  autoLockMinutes: 15,
});

const SETTINGS_KEY = 'settings';
const LAST_EMAIL_KEY = 'lastEmail';

export function validateSettings(input: unknown): Settings {
  const value = (input ?? {}) as Partial<Record<keyof Settings, unknown>>;
  if (typeof value.serverUrl !== 'string') throw new Error('Server URL is required');
  const autoLockMinutes = Number(value.autoLockMinutes);
  if (!(AUTO_LOCK_OPTIONS_MINUTES as readonly number[]).includes(autoLockMinutes)) {
    throw new Error(`Auto-lock must be one of ${AUTO_LOCK_OPTIONS_MINUTES.join(', ')} minutes`);
  }
  return { serverUrl: normalizeServerUrl(value.serverUrl), autoLockMinutes };
}

export async function loadSettings(store: KeyValueStore): Promise<Settings> {
  try {
    return validateSettings({
      ...DEFAULT_SETTINGS,
      ...(await store.get<Partial<Settings>>(SETTINGS_KEY)),
    });
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(store: KeyValueStore, input: unknown): Promise<Settings> {
  const settings = validateSettings(input);
  await store.set(SETTINGS_KEY, settings);
  return settings;
}

export const loadLastEmail = async (store: KeyValueStore): Promise<string | null> =>
  (await store.get<string>(LAST_EMAIL_KEY)) ?? null;

export const saveLastEmail = (store: KeyValueStore, email: string): Promise<void> =>
  store.set(LAST_EMAIL_KEY, email);
