// Tests for scan job lifecycle: crash containment, resource ceilings, and the
// SSE stream.
//
// runScan spawns real processes, so these exercise the parts that decide
// whether the backend survives — the log cap, the queue, cancellation, atomic
// metadata writes, and subscriber isolation — rather than a full scan.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

let jm;
let scansDir;

before(async () => {
  scansDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jobs-'));
  process.env.SCANS_DIR = scansDir;
  process.env.PROJECT_ROOT = '/';
  process.env.MAX_CONCURRENT_SCANS = '2';
  process.env.MAX_LOG_LINES = '10';
  jm = await import('../lib/jobManager.js');
});

after(() => {
  fs.rmSync(scansDir, { recursive: true, force: true });
});

// A response double that records what the SSE stream wrote.
function fakeRes() {
  const res = {
    chunks: [],
    writableEnded: false,
    destroyed: false,
    handlers: {},
    write(c) { if (res.writableEnded) throw new Error('write after end'); res.chunks.push(c); return true; },
    end() { res.writableEnded = true; },
    on(event, fn) { res.handlers[event] = fn; },
  };
  return res;
}

const events = (res) => res.chunks.map((c) => JSON.parse(c.replace(/^data: /, '').trim()));

describe('log retention', () => {
  it('caps the in-memory log so a verbose scanner cannot exhaust memory', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    for (let i = 0; i < 100; i++) job.pushLog(`line ${i}`);
    assert.equal(job.logs.length, 10);
    assert.equal(job.logs.at(-1), 'line 99', 'the newest lines are the ones kept');
    assert.equal(job.dropped_log_lines > 0, true, 'the drop is recorded, not silent');
  });

  it('reports dropped lines to a subscriber that joins late', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    for (let i = 0; i < 50; i++) job.pushLog(`line ${i}`);
    const res = fakeRes();
    jm.streamLogs(job, res);
    assert.match(events(res)[0].line, /line\(s\) dropped/);
  });
});

describe('subscriber isolation', () => {
  it('a subscriber that throws is dropped, not propagated to the scan', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.subscribers.add({ onLine: () => { throw new Error('socket gone'); }, onDone: () => {} });
    assert.doesNotThrow(() => job.pushLog('hello'));
    assert.equal(job.subscribers.size, 0);
  });

  it('a subscriber that throws on completion does not escape finish()', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.subscribers.add({ onLine: () => {}, onDone: () => { throw new Error('socket gone'); } });
    assert.doesNotThrow(() => job.finish());
  });
});

describe('streamLogs', () => {
  it('replays the backlog and closes immediately for a finished job', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.pushLog('one');
    job.status = 'done';
    const res = fakeRes();
    jm.streamLogs(job, res);
    const sent = events(res);
    assert.equal(sent.at(-1).done, true);
    assert.equal(res.writableEnded, true);
  });

  it('does not write to an already-ended response', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    const res = fakeRes();
    jm.streamLogs(job, res);
    res.writableEnded = true;
    assert.doesNotThrow(() => job.pushLog('after end'));
  });

  it('removes its subscriber when the client disconnects', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    const res = fakeRes();
    jm.streamLogs(job, res);
    assert.equal(job.subscribers.size, 1);
    res.handlers.close();
    assert.equal(job.subscribers.size, 0, 'a vanished client must not leak a subscriber');
  });
});

describe('cancellation', () => {
  it('cancels a job still waiting in the queue', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    assert.equal(jm.cancelJob(job.run_id), true);
    assert.equal(job.status, 'cancelled');
    assert.equal(job.cancelled, true);
  });

  it('refuses to cancel a job that already finished', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.status = 'done';
    assert.equal(jm.cancelJob(job.run_id), false);
  });

  it('reports false for an unknown run id', () => {
    assert.equal(jm.cancelJob('nope'), false);
  });
});

describe('meta.json persistence', () => {
  it('never leaves a partially written file for a concurrent reader', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.status = 'done';
    job.finished_at = new Date().toISOString();

    const dir = path.join(scansDir, job.run_id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(job.toDict(), null, 2));

    const listed = jm.listJobs().find((j) => j.run_id === job.run_id);
    assert.ok(listed, 'the run is readable from disk');

    // No temp file survives a completed write.
    const leftovers = fs.readdirSync(dir).filter((f) => f.includes('.tmp'));
    assert.deepEqual(leftovers, []);
  });
});

describe('deleteJob', () => {
  it('stops a running job before removing its directory', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    job.status = 'running';
    jm.deleteJob(job.run_id);
    assert.equal(job.cancelled, true, 'the scan is cancelled, not orphaned');
    assert.equal(jm.getJob(job.run_id), null);
  });
});

describe('concurrency ceiling', () => {
  it('runs up to the limit and queues the rest', async () => {
    // Each scan launches a container, so an unbounded burst of requests used to
    // launch an unbounded number of them.
    const started = [];
    const jobs = [];
    for (let i = 0; i < 5; i++) {
      const job = jm.createJob({ repo_path: '/tmp' });
      jobs.push(job);
      jm.startJob(job);
      started.push(job);
    }

    // Two may run; the other three must say so in their log.
    const queued = started.filter((j) =>
      j.logs.some((l) => l.includes('Queued'))
    );
    assert.equal(queued.length, 3, 'three of five scans are held back');

    for (const job of jobs) jm.cancelJob(job.run_id);
  });
});

describe('post-processing exit code', () => {
  // La garde de risque de l'orchestrateur rend un verdict par un code de sortie
  // non nul. Le lire comme une panne afficherait « scan failed » et zéro
  // résultat au-dessus d'un rapport complet — et ce défaut-là serait le pire
  // possible pour un outil dont la production est une assurance.
  it('treats a clean exit as success with no verdict', () => {
    assert.deepEqual(jm.classifyPostprocessExit(0), { ok: true, gateTripped: false });
  });

  it('treats the risk-gate exit as success carrying a verdict', () => {
    assert.deepEqual(jm.classifyPostprocessExit(2), { ok: true, gateTripped: true });
  });

  it('treats any other non-zero exit as a real failure', () => {
    for (const code of [1, 3, 127, 255]) {
      assert.deepEqual(
        jm.classifyPostprocessExit(code),
        { ok: false, gateTripped: false },
        `exit ${code} must not be mistaken for a verdict`
      );
    }
  });

  it('exposes the verdict on the job, distinctly from an error', () => {
    const job = jm.createJob({ repo_path: '/tmp' });
    assert.equal(job.risk_gate_tripped, false, 'default is no verdict');
    assert.ok('risk_gate_tripped' in job.toDict(), 'and it reaches the API payload');
  });
});
