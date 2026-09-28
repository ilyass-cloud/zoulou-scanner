// Config-file endpoints: list/read built-in & saved orchestrator configs, save new ones.
import { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';

const router = Router();

const EXAMPLES_DIR = path.resolve(config.projectRoot, 'examples');
const CONFIGS_DIR = path.resolve(config.projectRoot, 'configs');
const SEARCH_DIRS = [EXAMPLES_DIR, CONFIGS_DIR];

router.get('/configs', (_req, res) => {
  const files = [];
  for (const dir of SEARCH_DIRS) {
    if (!fs.existsSync(dir)) continue;
    const names = fs.readdirSync(dir).filter((n) => n.endsWith('.yaml') || n.endsWith('.json')).sort();
    for (const name of names) files.push({ name, path: path.join(dir, name) });
  }
  res.json(files);
});

router.get('/configs/:filename', (req, res) => {
  for (const dir of SEARCH_DIRS) {
    const p = path.join(dir, path.basename(req.params.filename)); // prevent traversal
    if (fs.existsSync(p)) return res.type('text/plain').send(fs.readFileSync(p, 'utf-8'));
  }
  res.status(404).json({ error: 'Config not found' });
});

router.post('/configs', (req, res) => {
  const filename = (req.body.filename || '').trim();
  const content = req.body.content || '';
  if (!filename) return res.status(400).json({ error: 'filename is required' });
  if (!(filename.endsWith('.yaml') || filename.endsWith('.json')))
    return res.status(400).json({ error: 'filename must end in .yaml or .json' });

  fs.mkdirSync(CONFIGS_DIR, { recursive: true });
  const dest = path.join(CONFIGS_DIR, path.basename(filename)); // prevent traversal
  fs.writeFileSync(dest, content, 'utf-8');
  res.json({ saved: dest });
});

export default router;
