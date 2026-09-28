// Express entry point for the Security Orchestrator backend.
//
// This replaces the old Flask app (web/app.py + web/api/routes.py). It owns all
// HTTP, SSE, uploads, and the Postgres layer; the Python orchestrator "brain"
// is invoked only as a CLI (see lib/jobManager.js), and scans run in the
// ephemeral scanner-runner container via `docker run`.
import express from 'express';
import session from 'express-session';
import path from 'node:path';
import fs from 'node:fs';

import { config } from './config.js';
import { initDb } from './lib/pg.js';
import { authRequired, ensureBootstrapAdmin, requireAuth } from './lib/auth.js';

import scansRouter from './routes/scans.js';
import toolsRouter from './routes/tools.js';
import configsRouter from './routes/configs.js';
import miscRouter from './routes/misc.js';
import dbRouter from './routes/db.js';
import reposRouter from './routes/repos.js';
import gitRouter from './routes/git.js';

const app = express();
app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' }));
app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 },
  })
);

// ── API ─────────────────────────────────────────────────────
// Guard first: every router below is mounted behind it, so a new route cannot
// accidentally be added unauthenticated. See lib/auth.js for when it applies.
app.use('/api', requireAuth);

// Order matters only where paths overlap; these prefixes are disjoint.
app.use('/api', miscRouter); // /browse /ignore-patterns /upload-repo /configs(list) /env-detect /auto-plan
app.use('/api', scansRouter); // /scan /scans/*
app.use('/api', toolsRouter); // /tools/*
app.use('/api', configsRouter); // /configs/*
app.use('/api', dbRouter); // /api-keys /users /auth /reports /settings
app.use('/api', reposRouter); // /repos /repos/:id/{test,clone}
app.use('/api', gitRouter); // /git/github/* /git/accounts/*

// ── Static SPA (production) ─────────────────────────────────
if (fs.existsSync(config.clientDist)) {
  app.use(express.static(config.clientDist));
  // Client-side routing fallback: serve index.html for non-API GETs.
  app.get(/^\/(?!api\/).*/, (_req, res) => {
    res.sendFile(path.join(config.clientDist, 'index.html'));
  });
} else {
  app.get('/', (_req, res) =>
    res.type('text').send('Backend up. Run the React dev server (web/client) or build it to web/client/dist.')
  );
}

// ── Boot ────────────────────────────────────────────────────
(async () => {
  try {
    const ready = await initDb();
    console.log(ready ? '🗄️  Database connected – schema ready' : '🗄️  No DATABASE_URL set – persistence endpoints disabled');
  } catch (e) {
    console.warn(`⚠️  Database init failed (${e.message}); persistence endpoints will 503`);
  }

  if (authRequired()) {
    try {
      const created = await ensureBootstrapAdmin();
      if (created) console.log(`👤 Bootstrap admin created: ${created}`);
    } catch (e) {
      console.warn(`⚠️  Could not create the bootstrap admin (${e.message})`);
    }
    console.log('🔐 Authentication required – /api needs a valid session');
  } else {
    console.warn(
      '🔓 Authentication DISABLED – /api is fully open. Set DATABASE_URL (or REQUIRE_AUTH=1)\n' +
      '   before exposing this app beyond localhost: /api/tools + /api/scan can execute commands.'
    );
  }

  app.listen(config.port, config.host, () => {
    console.log(`\n🔒 Security Orchestrator backend → http://${config.host}:${config.port}\n`);
  });
})();
