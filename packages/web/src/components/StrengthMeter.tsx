import type { Strength } from '../lib/passwordStrength';

interface Props {
  strength: Strength | null;
  /** Shown under the bar when the password doesn't meet a required score. */
  requirement?: string | undefined;
}

/** A five-step bar with zxcvbn's verdict and advice. Renders nothing for an empty password. */
export function StrengthMeter({ strength, requirement }: Props) {
  if (!strength) return null;
  const { score, label, warning, suggestions } = strength;
  return (
    <div className="strength" data-score={score}>
      <div
        className="strength-bar"
        role="meter"
        aria-label="Password strength"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={score}
        aria-valuetext={label}
      >
        {[0, 1, 2, 3, 4].map((step) => (
          <span key={step} className={step <= score ? 'is-on' : undefined} />
        ))}
      </div>
      <p className="strength-label">
        Strength: <strong>{label}</strong>
      </p>
      {(warning || suggestions.length > 0 || requirement) && (
        <ul className="strength-advice">
          {warning && <li>{warning}</li>}
          {suggestions.map((suggestion) => (
            <li key={suggestion}>{suggestion}</li>
          ))}
          {requirement && <li>{requirement}</li>}
        </ul>
      )}
    </div>
  );
}
