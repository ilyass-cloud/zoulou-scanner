// Tools-registry endpoints. The registry is a plain YAML file (tools_registry.yaml),
// so Node reads/writes it directly with js-yaml — no Python needed. Install
// checks shell out to the tool's own --version command.
import { Router } from 'express';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { config } from '../config.js';

const router = Router();
const REGISTRY_PATH = path.resolve(config.projectRoot, config.toolsRegistryPath);

const DEFAULTS = {
  label: '', output_format: 'sarif', output_file_flag: '', install_check: '',
  description: '', enabled: true, timeout_seconds: 300, env: {}, extra_args: [],
};

function loadRegistry() {
  if (!fs.existsSync(REGISTRY_PATH)) return { tools: [] };
  const data = yaml.load(fs.readFileSync(REGISTRY_PATH, 'utf-8')) || {};
  return { tools: Array.isArray(data.tools) ? data.tools : [] };
}

function saveRegistry(reg) {
  fs.writeFileSync(REGISTRY_PATH, yaml.dump({ tools: reg.tools }, { lineWidth: 100 }), 'utf-8');
}

router.get('/tools', (_req, res) => {
  try {
    res.json(loadRegistry().tools);
  } catch (e) {
    res.json({ error: e.message, tools: [] });
  }
});

router.post('/tools', (req, res) => {
  const tools = (req.body.tools || []).map((t) => ({ ...DEFAULTS, ...t }));
  try {
    saveRegistry({ tools });
    res.json({ saved: REGISTRY_PATH, count: tools.length });
  } catch (e) {
    res.status(400).json({ error: `Failed to save tools registry: ${e.message}` });
  }
});

router.post('/tools/add', (req, res) => {
  const body = req.body || {};
  if (!body.name || !body.command)
    return res.status(400).json({ error: 'Invalid tool definition: name and command are required' });
  const tool = { ...DEFAULTS, ...body };
  const reg = loadRegistry();
  reg.tools = reg.tools.filter((t) => t.name !== tool.name); // replace if exists
  reg.tools.push(tool);
  saveRegistry(reg);
  res.json({ saved: tool.name });
});

router.delete('/tools/:name', (req, res) => {
  const reg = loadRegistry();
  const before = reg.tools.length;
  reg.tools = reg.tools.filter((t) => t.name !== req.params.name);
  if (reg.tools.length === before) return res.status(404).json({ error: 'Tool not found' });
  saveRegistry(reg);
  res.json({ deleted: req.params.name });
});

router.post('/tools/:name/toggle', (req, res) => {
  const reg = loadRegistry();
  const tool = reg.tools.find((t) => t.name === req.params.name);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });
  tool.enabled = !tool.enabled;
  saveRegistry(reg);
  res.json({ name: tool.name, enabled: tool.enabled });
});

// Best-effort install check: scanners live in the runner image, so this will
// usually report installed:false when run from the backend container.
router.post('/tools/:name/check', (req, res) => {
  const reg = loadRegistry();
  const tool = reg.tools.find((t) => t.name === req.params.name);
  if (!tool) return res.status(404).json({ error: 'Tool not found' });

  const checkCmd = (tool.install_check || `${tool.name} --version`).trim();
  const [bin, ...args] = checkCmd.split(/\s+/);
  let out = '';
  let done = false;
  const finish = (installed, version) => {
    if (done) return;
    done = true;
    res.json({
      name: tool.name, installed, version: version || null,
      note: 'Checks local env; scanners live in the backend/runner container.',
    });
  };
  try {
    const child = spawn(bin, args);
    child.stdout.on('data', (c) => (out += c.toString()));
    child.stderr.on('data', (c) => (out += c.toString()));
    child.on('error', () => finish(false));
    child.on('close', (code) => finish(code === 0, out.split('\n')[0]?.trim()));
  } catch {
    finish(false);
  }
});

export default router;
