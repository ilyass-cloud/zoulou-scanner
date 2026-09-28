/* Pure helpers for the live-log view.

   Kept out of the component so the batching and retention rules — the parts
   that decide whether a verbose scan locks up the tab — can be tested without a
   React test harness. */

// Lines kept in the DOM. The backend caps its own retention too; this is the
// browser-side equivalent, and it bounds reconciliation cost per flush.
export const MAX_LOG_LINES = 2000;

export function lineClass(line) {
  if (line.includes('[ERROR]') || line.includes('[CRITICAL]')) return 'log-line-error';
  if (line.includes('[WARNING]') || line.includes('[WARN]')) return 'log-line-warn';
  if (line.includes('[INFO]')) return 'log-line-info';
  if (line.includes('[DEBUG]')) return 'log-line-debug';
  return '';
}

/**
 * Append a batch and drop the oldest lines beyond the cap.
 *
 * Returns `existing` unchanged when the batch is empty so React can bail out of
 * the update entirely.
 */
export function appendCapped(existing, batch, max = MAX_LOG_LINES) {
  if (!batch.length) return existing;
  const next = existing.length ? existing.concat(batch) : batch;
  return next.length > max ? next.slice(next.length - max) : next;
}

// Family of each scanner in tools_registry.yaml. The containerised runner logs
// per tool (« live_plugin[semgrep]: executing … »), not per family, so the
// progress card needs this map to know which family a tool belongs to.
export const TOOL_FAMILY = {
  semgrep: 'sast', bandit: 'sast',
  'pip-audit': 'deps', 'npm-audit': 'deps', safety: 'deps',
  gitleaks: 'secrets', trufflehog: 'secrets',
  trivy: 'container', grype: 'container',
  nmap: 'network',
};

/**
 * Fold a batch of log lines into the plugin-progress map in one pass.
 *
 * Two log dialects are understood: the all-in-one runner's per-family lines
 * (« starting plugin 'sast' ») and the containerised runner's per-tool lines
 * (« live_plugin[bandit]: executing / finished / FAILED »). A family is shown
 * as failed once any of its tools failed; « Runner complete » closes whatever
 * is still running.
 *
 * A burst of scanner output should cost one state update, not one per line.
 * Returns the original object when nothing matched, so React can skip the
 * re-render.
 */
export function applyPluginProgress(current, batch) {
  let next = current;
  const set = (family, state) => {
    if (!family || !(family in current) || next[family] === state) return;
    if (next[family] === 'error' && state === 'done') return; // a failure sticks
    if (next === current) next = { ...current }; // copy once, and only if needed
    next[family] = state;
  };
  for (const { text } of batch) {
    const startMatch = text.match(/starting plugin '(\w+)'/);
    const doneMatch = text.match(/plugin '(\w+)' finished.*?–\s*(\w+)/);
    const errMatch = text.match(/plugin '(\w+)'.*?(FAILED|exception)/i);
    if (startMatch) set(startMatch[1], 'running');
    if (doneMatch) set(doneMatch[1], doneMatch[2].toLowerCase() === 'ok' ? 'done' : 'error');
    if (errMatch && !doneMatch) set(errMatch[1], 'error');

    const tool = text.match(/live_plugin\[([\w.-]+)\]: (executing|finished|FAILED)/);
    if (tool) {
      const family = TOOL_FAMILY[tool[1]];
      const state = { executing: 'running', finished: 'done', FAILED: 'error' }[tool[2]];
      if (state === 'running' && next[family] === 'error') continue;
      set(family, state);
    }
    if (/Runner complete/.test(text)) {
      for (const [family, state] of Object.entries(next)) if (state === 'running') set(family, 'done');
    }
  }
  return next;
}
