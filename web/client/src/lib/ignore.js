/* Client-side mirror of the server upload ignore filter (web/upload.py).
   Builds a matcher from the /api/ignore-patterns payload so heavy / non-source
   files are dropped before they ever cross the wire. */

export function buildIgnoreMatcher(p) {
  const dirs = new Set(p.dirs || []);
  const names = new Set(p.file_names || []);
  const suffixes = p.file_suffixes || [];
  return (relpath) => {
    const parts = relpath.split('/');
    for (let i = 0; i < parts.length - 1; i++) {
      if (dirs.has(parts[i])) return true; // ignored directory segment
    }
    const base = parts[parts.length - 1];
    if (names.has(base)) return true;
    const lower = base.toLowerCase();
    return suffixes.some((s) => lower.endsWith(s));
  };
}
