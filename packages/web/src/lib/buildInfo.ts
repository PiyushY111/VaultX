import { MANIFEST_FILE, buildHashOf, sumsText } from '../../build/sums';

/**
 * Which build this page is running, for the Security panel: the build hash
 * (SHA-256 of the build's SHA256SUMS), recomputed here from the build
 * manifest's file list, plus checks that the entry script and stylesheet
 * this page loaded are the ones the manifest lists.
 *
 * This is a convenience, not a guarantee. The number is computed by the very
 * code it describes: a server that ships modified code can ship code that
 * shows the published hash anyway. It helps someone notice an unannounced or
 * accidental change, never a deliberate one. A check the server can't fake
 * has to happen outside this page (`npm run verify-build`, see README).
 */

export interface BuildInfo {
  buildHash: string;
  commit: string | null;
  dirty: boolean | null;
  /** Inconsistencies between this page and its manifest; empty when they agree. */
  problems: string[];
}

interface Manifest {
  build_hash: string;
  files: Record<string, string>;
  integrity: Record<string, string>;
  git?: { commit?: unknown; dirty?: unknown } | undefined;
}

const HEX_64 = /^[0-9a-f]{64}$/;

function parseManifest(value: unknown): Manifest | null {
  if (!value || typeof value !== 'object') return null;
  const { build_hash, files, integrity, git } = value as Record<string, unknown>;
  const isRecord = (v: unknown): v is Record<string, string> =>
    !!v && typeof v === 'object' && Object.values(v).every((x) => typeof x === 'string');
  if (typeof build_hash !== 'string' || !isRecord(files) || !isRecord(integrity)) return null;
  if (!Object.values(files).every((hash) => HEX_64.test(hash))) return null;
  return { build_hash, files, integrity, git: git as Manifest['git'] };
}

/** The script and stylesheet tags this page loaded, as manifest paths → their integrity attribute. */
function loadedAssets(doc: Document): [string, string | null][] {
  const tags = [
    ...doc.querySelectorAll<HTMLScriptElement>('script[src]'),
    ...doc.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"][href]'),
  ];
  return tags.map((tag) => {
    const url = new URL(tag instanceof HTMLScriptElement ? tag.src : tag.href, doc.baseURI);
    return [url.pathname.replace(/^\//, ''), tag.getAttribute('integrity')];
  });
}

/** Null when there's no manifest (the dev server, or a build without one). */
export async function loadBuildInfo(doc: Document = document): Promise<BuildInfo | null> {
  let response: Response;
  try {
    response = await fetch(`/${MANIFEST_FILE}`, { cache: 'no-store', credentials: 'omit' });
  } catch {
    return null;
  }
  if (!response.ok) return null;
  const manifest = parseManifest(await response.json().catch(() => null));
  if (!manifest) return null;

  const buildHash = await buildHashOf(sumsText(manifest.files));
  const problems: string[] = [];
  if (buildHash !== manifest.build_hash) {
    problems.push('The build manifest’s file list doesn’t match its own build hash.');
  }
  for (const [path, integrity] of loadedAssets(doc)) {
    if (!(path in manifest.files))
      problems.push(`This page loaded ${path}, which isn’t in the build.`);
    else if (integrity === null) problems.push(`${path} was loaded without an integrity check.`);
    else if (manifest.integrity[path] !== integrity) {
      problems.push(`${path} on this page isn’t the file the build manifest lists.`);
    }
  }
  const commit = manifest.git?.commit;
  const dirty = manifest.git?.dirty;
  return {
    buildHash,
    commit: typeof commit === 'string' ? commit : null,
    dirty: typeof dirty === 'boolean' ? dirty : null,
    problems,
  };
}
