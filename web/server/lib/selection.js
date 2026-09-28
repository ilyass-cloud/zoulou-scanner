// Which tools a scan request asks for.
//
// The family switches of the scan form used to be cosmetic: the brain only
// selects tools from Auto-Scan or an explicit list, so ticking families alone
// planned nothing and the scan « succeeded » with an empty report. Families now
// restrict the automatic selection, and ticking them without Auto-Scan turns it
// on. A request that can run nothing at all is refused up front.

export const FAMILIES = ['sast', 'deps', 'secrets', 'container'];

/**
 * @param {{auto_scan?: boolean, selected_tools?: string[]}} params
 * @param {Record<string, boolean>} pluginEnabled  switches of the form
 * @returns {{ok: true, auto_scan: boolean, families?: string[]} | {ok: false, error: string}}
 */
export function resolveToolSelection(params, pluginEnabled) {
  const explicit = Boolean(params.selected_tools?.length);
  const autoScan = Boolean(params.auto_scan);
  if (explicit) return { ok: true, auto_scan: autoScan };

  const families = FAMILIES.filter((f) => pluginEnabled[f]);
  if (families.length) return { ok: true, auto_scan: true, families };
  if (autoScan || pluginEnabled.network) return { ok: true, auto_scan: autoScan };
  return {
    ok: false,
    error: 'Aucun outil à lancer : cochez au moins une famille d’outils, ou choisissez des outils précis.',
  };
}
