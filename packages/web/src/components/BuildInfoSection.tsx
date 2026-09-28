import { useEffect, useState } from 'react';
import { loadBuildInfo, type BuildInfo } from '../lib/buildInfo';

/** Groups a hex string in fours, so two values are easier to compare by eye. */
const grouped = (hex: string) => hex.replace(/(.{4})(?=.)/g, '$1 ');

/**
 * Shows which build of the web vault is running, to compare with the value
 * published for the release. Deliberately explains its own limit: the page
 * reporting this number is the code being checked.
 */
export function BuildInfoSection() {
  const [info, setInfo] = useState<BuildInfo | null | undefined>(undefined);
  useEffect(() => {
    let cancelled = false;
    void loadBuildInfo().then((result) => {
      if (!cancelled) setInfo(result);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="sheet" role="region" aria-label="This build">
      <h3>This build</h3>
      {info === undefined ? (
        <p className="quiet-state">Loading…</p>
      ) : info === null ? (
        <p className="hint">
          No build manifest was found, so there’s no build hash to show (this happens on the
          development server).
        </p>
      ) : (
        <>
          <p>
            Build hash:{' '}
            <code className="build-hash" data-testid="build-hash" aria-label={info.buildHash}>
              {grouped(info.buildHash)}
            </code>
          </p>
          {info.commit && (
            <p className="hint">
              Built from commit <code>{info.commit.slice(0, 12)}</code>
              {info.dirty ? ' with uncommitted changes' : ''}.
            </p>
          )}
          {info.problems.length > 0 && (
            <ul className="warning" role="alert">
              {info.problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          )}
          <p className="hint">
            Compare this with the build hash published for your server’s release. If they differ,
            this isn’t the published code. If they match, that’s reassuring but not proof: this
            number comes from the page itself, and modified code could show the published value. For
            a check the server can’t fake, verify the files from outside the browser (see the web
            vault README), or use the browser extension, whose code doesn’t come from the server.
          </p>
        </>
      )}
    </div>
  );
}
