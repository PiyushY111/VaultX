import { useState } from 'react';
import {
  DEFAULT_GENERATOR_OPTIONS,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  entropyBits,
  generatePassword,
  type GeneratorOptions,
} from '../lib/passwordGenerator';

interface Props {
  /** When provided, shows a button to use the generated password (e.g. in the item form). */
  onUse?: (password: string) => void;
}

export function PasswordGenerator({ onUse }: Props) {
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_GENERATOR_OPTIONS);
  const [password, setPassword] = useState(() => generatePassword(DEFAULT_GENERATOR_OPTIONS));

  const update = (changes: Partial<GeneratorOptions>) => {
    const next = { ...options, ...changes };
    setOptions(next);
    setPassword(generatePassword(next));
  };

  return (
    <fieldset className="generator" aria-label="Password generator">
      <legend>Password generator</legend>
      <output className="generated" aria-label="Generated password">
        {password}
      </output>
      <label className="length">
        <span>
          Length <strong>{options.length}</strong>
        </span>
        <input
          type="range"
          min={MIN_PASSWORD_LENGTH}
          max={MAX_PASSWORD_LENGTH}
          value={options.length}
          onChange={(e) => update({ length: Number(e.target.value) })}
        />
      </label>
      <div className="toggles">
        <label className="inline">
          <input
            type="checkbox"
            checked={options.numbers}
            onChange={(e) => update({ numbers: e.target.checked })}
          />
          Numbers
        </label>
        <label className="inline">
          <input
            type="checkbox"
            checked={options.symbols}
            onChange={(e) => update({ symbols: e.target.checked })}
          />
          Symbols
        </label>
        <p className="hint">~{entropyBits(options)} bits of entropy</p>
      </div>
      <div className="row">
        <button
          type="button"
          className="btn"
          onClick={() => setPassword(generatePassword(options))}
        >
          Regenerate
        </button>
        {onUse && (
          <button type="button" className="btn btn-primary" onClick={() => onUse(password)}>
            Use this password
          </button>
        )}
      </div>
    </fieldset>
  );
}
