/** Minimal async key-value interface over chrome.storage areas (and in-memory fakes in tests). */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
}

export function chromeStore(area: chrome.storage.StorageArea): KeyValueStore {
  return {
    async get<T>(key: string) {
      const result = await area.get(key);
      return result[key] as T | undefined;
    },
    set: (key, value) => area.set({ [key]: value }),
    remove: (key) => area.remove(key),
    clear: () => area.clear(),
  };
}
