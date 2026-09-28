// Scan endpoints: start a scan, list/inspect/cancel/delete runs, stream logs.
import { Router } from 'express';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { marked } from 'marked';
import sanitizeHtml from 'sanitize-html';

import { config } from '../config.js';
import {
  createJob, startJob, getJob, listJobs, cancelJob, deleteJob, streamLogs, SCANS_DIR,
} from '../lib/jobManager.js';
import { resolveScanTarget, safeJoin } from '../lib/paths.js';
import { resolveToolSelection } from '../lib/selection.js';

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

const UPLOADS_DIR = path.resolve(config.projectRoot, 'uploads');
const TRUTHY = new Set(['on', 'true', '1']);
const isTruthy = (v) => TRUTHY.has(String(v).toLowerCase());

// Allowed subset for rendered reports: everything Markdown legitimately emits,
// and nothing that executes. Scripts, styles, event handlers, and javascript:
// URLs are all dropped, and links are forced to open detached from this origin.
const REPORT_SANITIZE_OPTIONS = {
  allowedTags: [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'br', 'hr', 'blockquote',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    'strong', 'em', 'b', 'i', 'del', 'code', 'pre', 'span', 'div',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'a', 'img',
  ],
  allowedAttributes: {
    a: ['href', 'title'],
    img: ['src', 'alt', 'title'],
    '*': ['class'],
  },
  allowedSchemes: ['http', 'https', 'mailto'],
  transformTags: {
    a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }),
  },
};

const sanitizeReport = (html) => sanitizeHtml(html, REPORT_SANITIZE_OPTIONS);

const scanUpload = upload.fields([
  { name: 'plugin_file_sast' }, { name: 'plugin_file_deps' },
  { name: 'plugin_file_secrets' }, { name: 'plugin_file_container' },
  { name: 'network_allowlist_file' }, { name: 'network_input_file' },
]);

// originalname comes straight from the browser and may contain '../', so it is
// resolved against UPLOADS_DIR and rejected if it escapes.
function saveUpload(file) {
  const dest = safeJoin(UPLOADS_DIR, path.posix.basename(file.originalname.replace(/\\/g, '/')));
  if (!dest) throw new Error(`Rejected unsafe upload filename: ${file.originalname}`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, file.buffer);
  return dest;
}

// POST /api/scan — accepts multipart/form-data or JSON.
router.post('/scan', scanUpload, (req, res) => {
  const body = req.body || {};
  const files = req.files || {};
  const params = {};

  // Jailed: this path is bind-mounted into the runner container and fed to the
  // scanner command templates, so it must stay inside the permitted roots.
  const target = resolveScanTarget(body.repo_path);
  if (!target.ok) return res.status(400).json({ error: target.error });
  params.repo_path = target.path;

  if (body.config_path) params.config_path = body.config_path;
  if (body.output_dir) params.output_dir = body.output_dir;

  params.llm_enabled = isTruthy(body.llm_enabled ?? 'off');
  params.auto_scan = isTruthy(body.auto_scan ?? 'off');

  if (body.selected_tools) {
    params.selected_tools = String(body.selected_tools).split(',').map((t) => t.trim()).filter(Boolean);
  }

  const pluginEnabled = {};
  for (const p of ['sast', 'deps', 'secrets', 'container', 'network']) {
    pluginEnabled[p] = isTruthy(body[`plugin_enabled_${p}`] ?? 'off');
  }
  params.plugin_enabled = pluginEnabled;

  const selection = resolveToolSelection(params, pluginEnabled);
  if (!selection.ok) return res.status(400).json({ error: selection.error });
  params.auto_scan = selection.auto_scan;
  if (selection.families) params.families = selection.families;

  // Network input files (saved here, mounted read-only into the runner).
  if (files.network_allowlist_file?.[0]) params.network_allowlist = saveUpload(files.network_allowlist_file[0]);
  if (files.network_input_file?.[0]) params.network_input = saveUpload(files.network_input_file[0]);

  // Per-plugin input overrides (collected for parity; brain reads config paths).
  const pluginInputs = {};
  for (const p of ['sast', 'deps', 'secrets', 'container']) {
    const f = files[`plugin_file_${p}`]?.[0];
    if (f) pluginInputs[p] = saveUpload(f);
  }
  if (Object.keys(pluginInputs).length) params.plugin_inputs = pluginInputs;

  if (pluginEnabled.network && !params.network_allowlist) {
    return res.status(400).json({
      error:
        'Network plugin is enabled but no network_allowlist was provided. ' +
        '⚠️  Only scan targets you are authorized to scan.',
    });
  }

  const job = createJob(params);
  startJob(job);
  res.status(202).json({ run_id: job.run_id, status: job.status });
});

router.get('/scans', (_req, res) => res.json(listJobs()));

router.get('/scans/:runId', (req, res) => {
  const job = getJob(req.params.runId);
  if (job) return res.json(job.toDict());
  const reportPath = path.join(SCANS_DIR, req.params.runId, 'report.json');
  if (fs.existsSync(reportPath)) return res.json(JSON.parse(fs.readFileSync(reportPath, 'utf-8')));
  res.status(404).json({ error: 'Scan not found' });
});

router.get('/scans/:runId/report', (req, res) => {
  const reportPath = path.join(SCANS_DIR, req.params.runId, 'report.json');
  if (!fs.existsSync(reportPath)) return res.status(404).json({ error: 'Report not found' });
  res.json(JSON.parse(fs.readFileSync(reportPath, 'utf-8')));
});

// report.md is built from scanner findings and raw LLM output, so its contents
// are untrusted — scanning a hostile repository is the whole point of this tool,
// and a finding's code snippet or file path lands verbatim in the Markdown. The
// client injects this response with dangerouslySetInnerHTML, so it is sanitized
// here rather than shipped raw.
router.get('/scans/:runId/report.md', (req, res) => {
  const mdPath = path.join(SCANS_DIR, req.params.runId, 'report.md');
  if (!fs.existsSync(mdPath)) return res.status(404).json({ error: 'Markdown report not found' });
  const html = marked.parse(fs.readFileSync(mdPath, 'utf-8'));
  res.type('html').send(sanitizeReport(html));
});

router.get('/scans/:runId/logs', (req, res) => {
  const job = getJob(req.params.runId);
  if (!job) return res.status(404).json({ error: 'Scan not found' });
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  streamLogs(job, res);
});

router.post('/scans/:runId/cancel', (req, res) => {
  if (cancelJob(req.params.runId)) return res.json({ status: 'cancelled' });
  res.status(400).json({ error: 'Cannot cancel: scan not running or not found' });
});

router.delete('/scans/:runId', (req, res) => {
  if (deleteJob(req.params.runId)) return res.json({ deleted: true });
  res.status(404).json({ error: 'Scan not found' });
});

export default router;
