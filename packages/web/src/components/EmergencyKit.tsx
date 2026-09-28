import { downloadText } from '../lib/download';

interface Props {
  email: string;
  onDone: () => void;
  /** Shown straight after signup, with more urgency. */
  firstTime?: boolean;
}

/** The kit's text. It never includes the master password: that's written in by hand. */
export function emergencyKitText(email: string, server: string, date = new Date()): string {
  return [
    'VAULTX EMERGENCY KIT',
    '====================',
    '',
    `Created:  ${date.toLocaleDateString(undefined, { dateStyle: 'long' })}`,
    `Email:    ${email}`,
    `Server:   ${server}`,
    '',
    'Master password (write it here by hand, never type it into a file):',
    '',
    '    ____________________________________________',
    '',
    'Why this matters',
    '----------------',
    'VaultX is zero-knowledge: your master password never leaves your devices,',
    'and nobody can reset it, not even whoever runs the server. If you forget',
    'it, your vault cannot be recovered.',
    '',
    'Keep this sheet somewhere safe and private, such as with other important',
    'papers. If you use two-factor login, keep your recovery codes separately.',
    '',
  ].join('\n');
}

/**
 * The "emergency kit": a sheet to print or download, with where the vault
 * lives and a blank for the master password to be written in by hand.
 */
export function EmergencyKit({ email, onDone, firstTime = false }: Props) {
  const server = window.location.origin;
  const text = emergencyKitText(email, server);
  return (
    <section className="sheet kit" aria-label="Emergency kit">
      <h2>{firstTime ? 'Save your emergency kit' : 'Emergency kit'}</h2>
      <p className="warning">
        Your master password can’t be reset or recovered by anyone. Print or download this sheet,
        write your master password on it by hand, and keep it somewhere safe.
      </p>
      <pre className="kit-sheet">{text}</pre>
      <div className="row sheet-actions">
        <button
          type="button"
          className="btn"
          onClick={() => downloadText('VaultX Emergency Kit.txt', text)}
        >
          Download
        </button>
        <button type="button" className="btn" onClick={() => window.print()}>
          Print
        </button>
        <button type="button" className="btn btn-primary" onClick={onDone}>
          {firstTime ? 'I’ve saved it' : 'Done'}
        </button>
      </div>
    </section>
  );
}
