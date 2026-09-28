// Port of web/scan_manager.py — the orchestrator "brain" side of the two-tier
// split, driven from Node.
//
// For each scan the backend:
//   1. Plans     – spawns `python -m orchestrator.main plan` → plan.json
//   2. Executes  – `docker run` the scanner-runner with run-plan → artifacts.json
//   3. Post-proc – spawns `python -m orchestrator.main postprocess` → report.json/.md
//
// The heavy scanners live only in the runner image; the planning brain and LLM
// analysis live in the Python CLI invoked here.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { config, CONTAINER_TARGET, CONTAINER_SCANS, UPLOADS_SUBDIR } from '../config.js';

const SCANS_DIR = path.resolve(config.projectRoot, config.scansDir);
const UPLOADS_DIR = path.join(SCANS_DIR, UPLOADS_SUBDIR);

const jobs = new Map(); // run_id -> ScanJob

// ── Resource limits ─────────────────────────────────────────
// Every scan holds its entire log in memory and launches a container. Without
// ceilings, a long-running backend grows without bound and an unlucky burst of
// requests starts as many containers as there are requests.

// Lines retained per job. Scanners are verbose (semgrep over a large repo emits
// tens of thousands of lines) and the log is replayed to every SSE subscriber.
const MAX_LOG_LINES = parseInt(process.env.MAX_LOG_LINES || '5000', 10);

// Finished jobs kept in memory. Their meta.json remains on disk and listJobs()
// merges it back, so eviction costs only the in-memory log tail.
const MAX_FINISHED_JOBS = parseInt(process.env.MAX_FINISHED_JOBS || '50', 10);

// Scans allowed to execute at once; the rest queue. Each one runs a container.
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '2', 10);

const TERMINAL = new Set(['done', 'error', 'cancelled']);

// Code de sortie par lequel l'orchestrateur rend un verdict de risque plutôt
// qu'une panne (orchestrator/main.py : RISK_GATE_EXIT).
const RISK_GATE_EXIT = 2;

/**
 * Lire le code de sortie du post-traitement.
 *
 * Deux choses très différentes s'y expriment. Un code non nul signale d'ordinaire
 * que l'étape a échoué — mais RISK_GATE_EXIT dit l'inverse : le scan a abouti,
 * ses rapports sont écrits, et son résultat enfreint la politique de risque
 * configurée. Les confondre afficherait un échec en rouge, avec zéro résultat,
 * par-dessus un rapport complet — c'est-à-dire le contraire de ce qui s'est
 * produit, sur l'outil dont toute la valeur tient à ce qu'il rapporte juste.
 *
 * Extrait de runScan pour être vérifiable sans lancer de processus.
 */
export function classifyPostprocessExit(code) {
  if (code === 0) return { ok: true, gateTripped: false };
  if (code === RISK_GATE_EXIT) return { ok: true, gateTripped: true };
  return { ok: false, gateTripped: false };
}

const queue = []; // jobs waiting for a concurrency slot
let running = 0;

// ── Job model ───────────────────────────────────────────────
class ScanJob {
  constructor(runId, params) {
    this.run_id = runId;
    this.params = params;
    this.status = 'pending'; // pending|running|done|error|cancelled
    this.started_at = null;
    this.finished_at = null;
    this.finding_count = 0;
    // Le scan a réussi mais son résultat enfreint la politique de risque :
    // distinct de `error`, qui signale que le scan n'a pas abouti.
    this.risk_gate_tripped = false;
    this.error = null;
    this.logs = [];
    this.dropped_log_lines = 0;
    this.subscribers = new Set(); // { onLine, onDone }
    this.cancelled = false;
    this.child = null; // current child process
  }

  // A subscriber whose socket died must not take the scan down with it, so
  // delivery failures are isolated per subscriber rather than propagating into
  // the stdout handler that called this.
  pushLog(line) {
    this.logs.push(line);
    if (this.logs.length > MAX_LOG_LINES) {
      this.logs.splice(0, this.logs.length - MAX_LOG_LINES);
      this.dropped_log_lines++;
    }
    for (const sub of this.subscribers) {
      try {
        sub.onLine(line);
      } catch {
        this.subscribers.delete(sub);
      }
    }
  }

  finish() {
    for (const sub of this.subscribers) {
      try {
        sub.onDone(this.status);
      } catch {
        this.subscribers.delete(sub);
      }
    }
  }

  toDict() {
    return {
      run_id: this.run_id,
      status: this.status,
      started_at: this.started_at,
      finished_at: this.finished_at,
      finding_count: this.finding_count,
      risk_gate_tripped: this.risk_gate_tripped,
      error: this.error,
      params: this.params,
    };
  }
}

// ── Process spawning (streams stdout+stderr line-by-line to the job log) ──
function runStreaming(job, cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: config.projectRoot, ...opts });
    job.child = child;

    let buf = { out: '', err: '' };
    const onChunk = (key) => (chunk) => {
      buf[key] += chunk.toString();
      const lines = buf[key].split('\n');
      buf[key] = lines.pop();
      for (const l of lines) job.pushLog(l.replace(/\r$/, ''));
    };
    const captured = [];
    child.stdout.on('data', (c) => { captured.push(c.toString()); onChunk('out')(c); });
    child.stderr.on('data', onChunk('err'));

    child.on('error', (e) => {
      job.pushLog(`[WEB] Failed to launch ${cmd}: ${e.message}`);
      resolve({ code: -1, stdout: captured.join(''), spawnError: e });
    });
    child.on('close', (code) => {
      for (const key of ['out', 'err']) {
        if (buf[key]) { job.pushLog(buf[key].replace(/\r$/, '')); buf[key] = ''; }
      }
      job.child = null;
      resolve({ code, stdout: captured.join('') });
    });
  });
}

// ── Pipeline steps ──────────────────────────────────────────
function runDir(runId) {
  return path.join(SCANS_DIR, runId);
}

function planArgs(job) {
  const p = job.params;
  const out = runDir(job.run_id);
  const args = [
    '-m', 'orchestrator.main', 'plan',
    '--repo', p.repo_path,
    '--out', out,
    '--run-id', job.run_id,
    '--runner-repo', CONTAINER_TARGET,
    '--runner-out', `${CONTAINER_SCANS}/${job.run_id}`,
    '--verbose',
  ];
  if (p.config_path) args.push('--config', p.config_path);
  if (p.auto_scan) args.push('--auto-scan');
  if (p.families) args.push('--families', p.families.join(','));
  if (p.selected_tools?.length) args.push('--tools', p.selected_tools.join(','));
  if (p._runner_allowlist) args.push('--network-allowlist', p._runner_allowlist);
  if (p._runner_net_input) args.push('--network-input', p._runner_net_input);
  if (!p.llm_enabled) args.push('--no-llm');
  return args;
}

function dockerArgs(job) {
  const p = job.params;
  const args = [
    'run', '--rm', '--name', `scan-${job.run_id}`,
    '-v', `${p.repo_path}:${CONTAINER_TARGET}:ro`,
    '-v', `${SCANS_DIR}:${CONTAINER_SCANS}`,
  ];
  for (const m of p._extra_mounts || []) args.push(...m);
  args.push(config.scannerImage);
  args.push('python', '-m', 'orchestrator.main', 'run-plan',
    '--plan', `${CONTAINER_SCANS}/${job.run_id}/plan.json`, '--verbose');
  return args;
}

function postprocessArgs(job) {
  const p = job.params;
  const args = [
    '-m', 'orchestrator.main', 'postprocess',
    '--out', runDir(job.run_id),
    '--run-id', job.run_id,
    '--repo', p.repo_path || '',
    '--verbose',
  ];
  if (p.config_path) args.push('--config', p.config_path);
  if (!p.llm_enabled) args.push('--no-llm');
  return args;
}

// Resolve network input files to runner-side mount paths.
function computeNetworkMounts(params) {
  const extra = [];
  if (params.network_allowlist) {
    const runnerPath = `/scan/${path.basename(params.network_allowlist)}`;
    params._runner_allowlist = runnerPath;
    extra.push(['-v', `${params.network_allowlist}:${runnerPath}:ro`]);
  }
  if (params.network_input) {
    const runnerPath = `/scan/${path.basename(params.network_input)}`;
    params._runner_net_input = runnerPath;
    extra.push(['-v', `${params.network_input}:${runnerPath}:ro`]);
  }
  params._extra_mounts = extra;
}

async function runScan(job) {
  job.status = 'running';
  job.started_at = new Date().toISOString();

  try {
    // Inside the try: this used to sit above it, so a scans dir that could not
    // be created (misconfigured SCANS_DIR, full disk, wrong permissions) threw
    // out of a fire-and-forget promise and terminated the whole backend —
    // killing every other in-flight scan along with it.
    fs.mkdirSync(runDir(job.run_id), { recursive: true });

    computeNetworkMounts(job.params);

    // 1. Plan (brain)
    job.pushLog('[WEB] Planning scan…');
    const plan = await runStreaming(job, config.python, planArgs(job));
    if (plan.spawnError && plan.spawnError.code === 'ENOENT') {
      throw new Error(`Python not found ('${config.python}'). The backend image needs Python + the orchestrator package.`);
    }
    if (plan.code !== 0) throw new Error(`Planning failed (exit ${plan.code})`);

    if (job.cancelled) { job.status = 'cancelled'; return; }

    // 2. Execute (runner container)
    job.pushLog(`[WEB] Starting scanner-runner: docker ${dockerArgs(job).join(' ')}`);
    const run = await runStreaming(job, 'docker', dockerArgs(job));
    if (run.spawnError && run.spawnError.code === 'ENOENT') {
      throw new Error('Docker CLI not found. The backend needs the docker socket and CLI to launch runner containers.');
    }
    if (job.cancelled) { job.status = 'cancelled'; job.pushLog('[WEB] Scan cancelled – runner terminated'); return; }
    if (run.code !== 0) throw new Error(`Scanner-runner exited with code ${run.code}`);

    // 3. Post-process (brain)
    job.pushLog('[WEB] Analysing artifacts…');
    const post = await runStreaming(job, config.python, postprocessArgs(job));
    const verdict = classifyPostprocessExit(post.code);
    if (!verdict.ok) throw new Error(`Post-processing failed (exit ${post.code})`);

    job.finding_count = parseFindingCount(post.stdout);
    job.risk_gate_tripped = verdict.gateTripped;
    if (verdict.gateTripped) {
      job.pushLog('[WEB] Risk policy breached – see fail_on_critical / fail_on_score');
    }
    job.status = 'done';
  } catch (e) {
    if (job.status !== 'cancelled') {
      job.status = 'error';
      job.error = e.message;
    }
  } finally {
    // Nothing here may throw: this is the last code to touch the job, and an
    // exception would escape as an unhandled rejection and end the process.
    job.finished_at = new Date().toISOString();
    try { saveMeta(job); } catch (e) { job.error ||= `Could not persist meta.json: ${e.message}`; }
    try { job.pushLog(`[DONE] status=${job.status}`); } catch { /* subscriber died */ }
    try { job.finish(); } catch { /* subscriber died */ }
  }
}

function parseFindingCount(stdout) {
  // postprocess prints a final JSON line: {"finding_count": N}
  const lines = stdout.trim().split('\n').reverse();
  for (const l of lines) {
    try {
      const obj = JSON.parse(l);
      if (typeof obj.finding_count === 'number') return obj.finding_count;
    } catch { /* not json */ }
  }
  return 0;
}

// ── Persistence ─────────────────────────────────────────────
// Written atomically: loadDiskRuns() reads these concurrently, and a reader that
// caught a partially-written file failed JSON.parse and silently dropped the run
// from the scan list. Rename within the same directory is atomic on POSIX.
function saveMeta(job) {
  const dir = runDir(job.run_id);
  fs.mkdirSync(dir, { recursive: true });
  const target = path.join(dir, 'meta.json');
  const tmp = path.join(dir, `.meta.json.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(job.toDict(), null, 2));
  fs.renameSync(tmp, target);
}

function loadDiskRuns() {
  const out = {};
  if (!fs.existsSync(SCANS_DIR)) return out;
  for (const entry of fs.readdirSync(SCANS_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const metaPath = path.join(SCANS_DIR, entry.name, 'meta.json');
    try {
      const data = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
      out[data.run_id] = data;
    } catch { /* no/invalid meta */ }
  }
  return out;
}

// ── Upload sweep (orphaned _uploads cleanup) ────────────────
function uploadIdFor(repoPath) {
  if (!repoPath) return null;
  try {
    const rel = path.relative(path.resolve(UPLOADS_DIR), path.resolve(repoPath));
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return rel.split(path.sep)[0] || null;
  } catch { return null; }
}

function referencedUploadIds() {
  const ids = new Set();
  const all = [...[...jobs.values()].map((j) => j.params), ...Object.values(loadDiskRuns()).map((m) => m.params || {})];
  for (const p of all) {
    const uid = uploadIdFor((p || {}).repo_path);
    if (uid) ids.add(uid);
  }
  return ids;
}

export function sweepOrphanUploads(maxAgeHours = config.uploadMaxAgeHours) {
  if (!fs.existsSync(UPLOADS_DIR)) return 0;
  const referenced = referencedUploadIds();
  const cutoff = Date.now() - maxAgeHours * 3600 * 1000;
  let removed = 0;
  for (const entry of fs.readdirSync(UPLOADS_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory() || referenced.has(entry.name)) continue;
    const full = path.join(UPLOADS_DIR, entry.name);
    try {
      if (fs.statSync(full).mtimeMs < cutoff) {
        fs.rmSync(full, { recursive: true, force: true });
        removed++;
      }
    } catch { /* ignore */ }
  }
  return removed;
}

// ── Public API ──────────────────────────────────────────────
export function createJob(params) {
  try { sweepOrphanUploads(); } catch { /* cleanup must never block a scan */ }
  const runId = crypto.randomUUID().slice(0, 8);
  const job = new ScanJob(runId, params);
  jobs.set(runId, job);
  evictFinishedJobs();
  return job;
}

// Finished jobs are already persisted to meta.json and listJobs() merges them
// back from disk, so dropping the oldest costs only its in-memory log tail.
// Without this the registry — and every log line it holds — grows forever.
function evictFinishedJobs() {
  const finished = [...jobs.values()].filter((j) => TERMINAL.has(j.status));
  if (finished.length <= MAX_FINISHED_JOBS) return;
  finished
    .sort((a, b) => String(a.finished_at || '').localeCompare(String(b.finished_at || '')))
    .slice(0, finished.length - MAX_FINISHED_JOBS)
    .forEach((j) => {
      if (j.subscribers.size === 0) jobs.delete(j.run_id);
    });
}

/**
 * Queue a scan, honouring the concurrency ceiling.
 *
 * runScan() is deliberately not awaited — the HTTP handler returns 202
 * immediately — which is exactly why it must never reject: an unhandled
 * rejection ends the process. The catch here is the backstop; runScan's own
 * finally is the primary guard.
 */
export function startJob(job) {
  queue.push(job);
  job.pushLog(
    running >= MAX_CONCURRENT_SCANS
      ? `[WEB] Queued – ${running} scan(s) already running (limit ${MAX_CONCURRENT_SCANS})`
      : '[WEB] Starting…'
  );
  drainQueue();
}

function drainQueue() {
  while (running < MAX_CONCURRENT_SCANS && queue.length) {
    const job = queue.shift();
    if (job.cancelled) {
      job.status = 'cancelled';
      try { job.finish(); } catch { /* subscriber died */ }
      continue;
    }
    running++;
    runScan(job)
      .catch((e) => {
        // Should be unreachable; runScan handles its own failures.
        job.status = 'error';
        job.error = `Internal scan failure: ${e.message}`;
      })
      .finally(() => {
        running--;
        drainQueue();
      });
  }
}

export function getJob(runId) {
  return jobs.get(runId) || null;
}

export function listJobs() {
  const live = {};
  for (const j of jobs.values()) live[j.run_id] = j.toDict();
  for (const [runId, meta] of Object.entries(loadDiskRuns())) {
    if (!(runId in live)) live[runId] = meta;
  }
  return Object.values(live).sort((a, b) =>
    String(b.started_at || '').localeCompare(String(a.started_at || ''))
  );
}

export function cancelJob(runId) {
  const job = getJob(runId);
  if (!job || TERMINAL.has(job.status)) return false;

  // Set first: runScan checks this flag between pipeline stages, and a job
  // still waiting in the queue is discarded by drainQueue on the same flag.
  job.cancelled = true;

  if (job.status === 'running') {
    try { spawn('docker', ['stop', `scan-${runId}`]); } catch { /* ignore */ }
    if (job.child) { try { job.child.kill(); } catch { /* ignore */ } }
  }
  job.status = 'cancelled';
  return true;
}

export function deleteJob(runId) {
  const dir = runDir(runId);
  let repoPath = null;
  const job = jobs.get(runId);
  if (job) repoPath = job.params.repo_path;
  if (repoPath == null && fs.existsSync(path.join(dir, 'meta.json'))) {
    try {
      const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf-8'));
      repoPath = (meta.params || {}).repo_path;
    } catch { /* ignore */ }
  }

  // Stop the scan before removing its directory: deleting a running job used to
  // leave the container running and the pipeline writing into a path that no
  // longer existed.
  if (job && !TERMINAL.has(job.status)) cancelJob(runId);

  jobs.delete(runId);
  const existed = fs.existsSync(dir);
  if (existed) fs.rmSync(dir, { recursive: true, force: true });

  const uid = uploadIdFor(repoPath);
  if (uid && !referencedUploadIds().has(uid)) {
    fs.rmSync(path.join(UPLOADS_DIR, uid), { recursive: true, force: true });
  }
  return existed;
}

// SSE: replay backlog, then stream live lines + heartbeats, end on done.
export function streamLogs(job, res) {
  // Writing to a closed or already-ended response throws, and pushLog runs
  // inside a child process' stdout handler, so an unguarded write here would
  // surface as a failure of the scan rather than of one viewer's connection.
  const send = (obj) => {
    if (res.writableEnded || res.destroyed) return false;
    try {
      res.write(`data: ${JSON.stringify(obj)}\n\n`);
      return true;
    } catch {
      return false;
    }
  };

  if (job.dropped_log_lines) {
    send({ line: `[WEB] … ${job.dropped_log_lines} earlier line(s) dropped (log capped at ${MAX_LOG_LINES})` });
  }
  for (const line of job.logs) send({ line });

  if (TERMINAL.has(job.status)) {
    send({ done: true, status: job.status });
    res.end();
    return;
  }

  let hb = null;
  const cleanup = () => {
    if (hb) clearInterval(hb);
    hb = null;
    job.subscribers.delete(sub);
  };

  const sub = {
    onLine: (line) => send({ line }),
    onDone: (status) => {
      send({ done: true, status });
      cleanup();
      if (!res.writableEnded) res.end();
    },
  };
  job.subscribers.add(sub);
  hb = setInterval(() => {
    // A client that vanished without a 'close' event stops the heartbeat here
    // rather than leaving an interval running for the life of the process.
    if (!send({ heartbeat: true })) cleanup();
  }, 15000);
  // The HTTP listener keeps the server alive; an open SSE heartbeat should not
  // independently hold the event loop open and prevent a clean shutdown.
  hb.unref?.();

  res.on('close', cleanup);
  res.on('error', cleanup);
}

export { SCANS_DIR, UPLOADS_DIR };
