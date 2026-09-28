// Invoke the Python orchestrator brain and parse its JSON stdout.
// Used by the env-detect / auto-plan endpoints (logs go to stderr, the JSON
// payload is the final stdout line).
import { spawn } from 'node:child_process';
import { config } from '../config.js';

export function runPythonJson(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(config.python, ['-m', 'orchestrator.main', ...args], {
      cwd: config.projectRoot,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => (out += c.toString()));
    child.stderr.on('data', (c) => (err += c.toString()));
    child.on('error', (e) =>
      reject(new Error(`Failed to launch Python ('${config.python}'): ${e.message}`))
    );
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(err.trim() || `orchestrator exited with code ${code}`));
        return;
      }
      const lines = out.trim().split('\n').reverse();
      for (const l of lines) {
        try {
          return resolve(JSON.parse(l));
        } catch { /* keep scanning back */ }
      }
      reject(new Error('No JSON payload on orchestrator stdout'));
    });
  });
}
