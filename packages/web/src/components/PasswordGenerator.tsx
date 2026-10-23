import { useEffect, useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  DEFAULT_PASSPHRASE_OPTIONS,
  MAX_PASSPHRASE_WORDS,
  MAX_PASSWORD_LENGTH,
  MIN_PASSPHRASE_WORDS,
  MIN_PASSWORD_LENGTH,
  PASSPHRASE_SEPARATORS,
  entropyBits,
  generatePassphrase,
  generatePassword,
  passphraseEntropyBits,
  type GeneratorOptions,
  type PassphraseOptions,
  type PassphraseSeparator,
} from '../lib/passwordGenerator';
import { loadWordlist } from '../lib/wordlist';

interface Props {
  /** When provided, shows a button to use the generated password (e.g. in the item form). */
  onUse?: (password: string) => void;
}

type Mode = 'characters' | 'passphrase';

// A non-secret preference, so localStorage is fine for it.
const MODE_STORAGE_KEY = 'password-manager.generatorMode';

const SEPARATOR_LABELS: Record<PassphraseSeparator, string> = {
  '-': 'Hyphen (-)',
  '.': 'Period (.)',
  _: 'Underscore (_)',
  ' ': 'Space',
};

function readMode(): Mode {
  try {
    return localStorage.getItem(MODE_STORAGE_KEY) === 'passphrase' ? 'passphrase' : 'characters';
  } catch {
    return 'characters';
  }
}

function saveMode(mode: Mode): void {
  try {
    localStorage.setItem(MODE_STORAGE_KEY, mode);
  } catch {
    // Storage unavailable (private mode): the choice lasts for this page only.
  }
}

export function PasswordGenerator({ onUse }: Props) {
  const [mode, setMode] = useState<Mode>(readMode);
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_GENERATOR_OPTIONS);
  const [phrase, setPhrase] = useState<PassphraseOptions>(DEFAULT_PASSPHRASE_OPTIONS);
  const [wordlist, setWordlist] = useState<readonly string[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  // Empty while the word list loads, so a character password never shows under "Passphrase".
  const [password, setPassword] = useState(() =>
    mode === 'characters' ? generatePassword(DEFAULT_GENERATOR_OPTIONS) : '',
  );

  async function regenerate(
    nextMode: Mode,
    nextOptions: GeneratorOptions,
    nextPhrase: PassphraseOptions,
  ) {
    if (nextMode === 'characters') {
      setPassword(generatePassword(nextOptions));
      return;
    }
    if (!wordlist) setPassword('');
    try {
      const list = wordlist ?? (await loadWordlist());
      setWordlist(list);
      setLoadFailed(false);
      setPassword(generatePassphrase(nextPhrase, list));
    } catch {
      setLoadFailed(true);
    }
  }

  // Opened in passphrase mode (remembered from last time): load the words.
  useEffect(() => {
    if (mode === 'passphrase' && !wordlist) void regenerate(mode, options, phrase);
    // Only on mount; later changes regenerate from their event handlers.
  }, []);

  const chooseMode = (next: Mode) => {
    if (next === mode) return;
    setMode(next);
    saveMode(next);
    void regenerate(next, options, phrase);
  };
  const updateOptions = (changes: Partial<GeneratorOptions>) => {
    const next = { ...options, ...changes };
    setOptions(next);
    void regenerate(mode, next, phrase);
  };
  const updatePhrase = (changes: Partial<PassphraseOptions>) => {
    const next = { ...phrase, ...changes };
    setPhrase(next);
    void regenerate(mode, options, next);
  };

  const bits =
    mode === 'characters'
      ? entropyBits(options)
      : wordlist && passphraseEntropyBits(phrase, wordlist.length);
  const output =
    password || (loadFailed ? 'Couldn’t load the word list. Try again.' : 'Loading words…');

  return (
    <fieldset className="generator" aria-label="Password generator">
      <legend>Password generator</legend>
      <div className="chips" role="group" aria-label="Generate">
        <button
          type="button"
          className="chip"
          aria-pressed={mode === 'characters'}
          onClick={() => chooseMode('characters')}
        >
          Characters
        </button>
        <button
          type="button"
          className="chip"
          aria-pressed={mode === 'passphrase'}
          onClick={() => chooseMode('passphrase')}
        >
          Passphrase
        </button>
      </div>
      <output className="generated" aria-label="Generated password" aria-busy={!password}>
        {output}
      </output>
      {mode === 'characters' ? (
        <>
          <label className="length">
            <span>
              Length <strong>{options.length}</strong>
            </span>
            <input
              type="range"
              min={MIN_PASSWORD_LENGTH}
              max={MAX_PASSWORD_LENGTH}
              value={options.length}
              onChange={(e) => updateOptions({ length: Number(e.target.value) })}
            />
          </label>
          <div className="toggles">
            <label className="inline">
              <input
                type="checkbox"
                checked={options.numbers}
                onChange={(e) => updateOptions({ numbers: e.target.checked })}
              />
              Numbers
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={options.symbols}
                onChange={(e) => updateOptions({ symbols: e.target.checked })}
              />
              Symbols
            </label>
            <p className="hint">~{bits} bits of entropy</p>
          </div>
        </>
      ) : (
        <>
          <label className="length">
            <span>
              Words <strong>{phrase.words}</strong>
            </span>
            <input
              type="range"
              min={MIN_PASSPHRASE_WORDS}
              max={MAX_PASSPHRASE_WORDS}
              value={phrase.words}
              onChange={(e) => updatePhrase({ words: Number(e.target.value) })}
            />
          </label>
          <div className="toggles">
            <label className="inline">
              Separator
              <select
                value={phrase.separator}
                onChange={(e) => updatePhrase({ separator: e.target.value as PassphraseSeparator })}
              >
                {PASSPHRASE_SEPARATORS.map((separator) => (
                  <option key={separator} value={separator}>
                    {SEPARATOR_LABELS[separator]}
                  </option>
                ))}
              </select>
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={phrase.capitalize}
                onChange={(e) => updatePhrase({ capitalize: e.target.checked })}
              />
              Capitalize
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={phrase.includeNumber}
                onChange={(e) => updatePhrase({ includeNumber: e.target.checked })}
              />
              Add a number
            </label>
            {bits !== null && <p className="hint">~{bits} bits of entropy</p>}
          </div>
        </>
      )}
      <div className="row">
        <button
          type="button"
          className="btn"
          onClick={() => void regenerate(mode, options, phrase)}
        >
          Regenerate
        </button>
        {onUse && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={!password}
            onClick={() => onUse(password)}
          >
            Use this password
          </button>
        )}
      </div>
    </fieldset>
  );
}
