import type { SessionInfo } from '../api';

const CLIENT_NAMES = { web: 'Web vault', extension: 'Browser extension' } as const;

// Order matters: Edge and Opera also say "Chrome", and Chrome also says "Safari".
const BROWSERS: [RegExp, string][] = [
  [/Edg\//, 'Edge'],
  [/OPR\//, 'Opera'],
  [/Firefox\//, 'Firefox'],
  [/Chrome\//, 'Chrome'],
  [/Safari\//, 'Safari'],
];

const SYSTEMS: [RegExp, string][] = [
  [/iPhone|iPad/, 'iOS'],
  [/Android/, 'Android'],
  [/Mac OS X|Macintosh/, 'macOS'],
  [/Windows/, 'Windows'],
  [/CrOS/, 'ChromeOS'],
  [/Linux/, 'Linux'],
];

const first = (patterns: [RegExp, string][], text: string) =>
  patterns.find(([pattern]) => pattern.test(text))?.[1];

/** A short, human label for a session, e.g. "Browser extension · Chrome on macOS". */
export function describeSession(session: Pick<SessionInfo, 'client' | 'user_agent'>): string {
  const client = session.client ? CLIENT_NAMES[session.client] : 'Unknown app';
  const ua = session.user_agent ?? '';
  const browser = first(BROWSERS, ua);
  const system = first(SYSTEMS, ua);
  const device = browser && system ? `${browser} on ${system}` : (browser ?? system);
  return device ? `${client} · ${device}` : client;
}
