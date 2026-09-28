// Repo helpers: directory browser, upload ignore list, folder upload, and the
// env-detect / auto-plan brain endpoints (spawn Python, return JSON).
import { Router } from 'express';
import multer from 'multer';

import { authRequired } from '../lib/auth.js';
import { listDir } from '../lib/browse.js';
import { resolveScanTarget } from '../lib/paths.js';
import { ignorePatternsPayload, newUploadDir, saveUploadedRepo } from '../lib/ignore.js';
import { runPythonJson } from '../lib/python.js';
import { SCANS_DIR } from '../lib/jobManager.js';

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

// Public (exempted in lib/auth.js): lets the client decide whether to render
// the login gate. Deliberately exposes nothing beyond the on/off flag.
router.get('/auth/status', (req, res) => {
  res.json({ auth_required: authRequired(), authenticated: Boolean(req.session?.user_id) });
});

router.get('/browse', (req, res) => {
  res.json(listDir(req.query.path));
});

router.get('/ignore-patterns', (_req, res) => {
  res.json(ignorePatternsPayload());
});

// Receive a filtered project folder; unpack onto the shared scans volume.
router.post('/upload-repo', upload.array('files'), (req, res) => {
  const files = req.files || [];
  let paths = req.body.paths || [];
  if (!Array.isArray(paths)) paths = [paths];

  if (!files.length) return res.status(400).json({ error: 'No files were uploaded' });
  if (files.length !== paths.length) return res.status(400).json({ error: 'Mismatched files/paths in upload' });

  const dest = newUploadDir(SCANS_DIR);
  const result = saveUploadedRepo(files, paths, dest);
  if (result.file_count === 0) return res.status(400).json({ error: 'Upload was empty after filtering' });
  res.json(result);
});

router.post('/env-detect', async (req, res) => {
  const target = resolveScanTarget(req.body.repo_path);
  if (!target.ok) return res.status(400).json({ error: target.error });
  try {
    res.json(await runPythonJson(['env-detect', '--repo', target.path]));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/auto-plan', async (req, res) => {
  const useLlm = req.body.use_llm !== false;
  const target = resolveScanTarget(req.body.repo_path);
  if (!target.ok) return res.status(400).json({ error: target.error });
  const repoPath = target.path;
  try {
    const args = ['auto-plan', '--repo', repoPath];
    if (req.body.config_path) args.push('--config', req.body.config_path);
    if (!useLlm) args.push('--no-llm');
    res.json(await runPythonJson(args));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
