// Central runtime configuration, mirroring the env vars the old Flask app used.
import crypto from 'node:crypto';
import path from 'node:path';

const ROOT = path.resolve(process.cwd(), '..', '..'); // project root (web/server -> ..)

const PLACEHOLDER_SECRET = 'dev-secret-change-in-production';

/**
 * Session signing key.
 *
 * The old fallback shipped a fixed, publicly-known string, so any deployment
 * that forgot APP_SECRET_KEY had forgeable session cookies — which now also
 * means forgeable logins. In production that is refused outright; in
 * development a random per-process key is generated instead, which is safe by
 * construction and merely invalidates sessions across restarts.
 */
function resolveSessionSecret() {
  const secret = process.env.APP_SECRET_KEY;
  const isProduction = process.env.NODE_ENV === 'production';

  if (secret && secret !== PLACEHOLDER_SECRET) return secret;

  if (isProduction) {
    throw new Error(
      'APP_SECRET_KEY must be set to a unique random value when NODE_ENV=production ' +
      `(it is ${secret ? 'still the placeholder' : 'unset'}). ` +
      'Generate one with: node -e "console.log(crypto.randomUUID())"'
    );
  }

  console.warn(
    '⚠️  APP_SECRET_KEY is unset or still the placeholder – using a random key for this\n' +
    '   process. Sessions will not survive a restart. Set APP_SECRET_KEY for a real deployment.'
  );
  return crypto.randomBytes(32).toString('hex');
}

export const config = {
  host: process.env.HOST || '0.0.0.0',
  port: parseInt(process.env.PORT || '5000', 10),

  // Project root so we can resolve orchestrator/, tools_registry.yaml, examples/.
  projectRoot: process.env.PROJECT_ROOT || ROOT,

  // Where scan run dirs (plan.json, artifacts.json, reports) are written. MUST
  // resolve to the same absolute path on host and in this container so it can
  // be bind-mounted into the runner container (see docker-compose).
  scansDir: process.env.SCANS_DIR || 'scans',

  // Ephemeral scanner-runner image that contains the scanners.
  scannerImage: process.env.SCANNER_IMAGE || 'security-orchestrator',

  // Python executable used to invoke the orchestrator brain (plan/postprocess).
  python: process.env.PYTHON_BIN || 'python',

  // Default config / tools registry search paths.
  toolsRegistryPath: process.env.TOOLS_REGISTRY_PATH || 'tools_registry.yaml',

  // Uploaded folders older than this (and unreferenced) get swept.
  uploadMaxAgeHours: parseFloat(process.env.UPLOAD_MAX_AGE_HOURS || '24'),

  sessionSecret: resolveSessionSecret(),

  // Public base URL of this app, used to build the OAuth2 redirect URI. Must
  // match the "Authorization callback URL" registered on the OAuth app.
  appBaseUrl: (process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || '5000'}`).replace(/\/+$/, ''),

  // GitHub OAuth App credentials (Settings → Developer settings → OAuth Apps).
  // Leave unset to disable the "Connect GitHub account" feature.
  github: {
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    // 'repo' grants clone access to private repos; 'read:user' reads the profile.
    scope: process.env.GITHUB_OAUTH_SCOPE || 'repo read:user',
    apiBase: process.env.GITHUB_API_BASE || 'https://api.github.com',
    authBase: process.env.GITHUB_AUTH_BASE || 'https://github.com',
  },

  // Static SPA build (web/client/dist) served in production.
  clientDist: process.env.CLIENT_DIST || path.resolve(process.cwd(), '..', 'client', 'dist'),
};

// Paths *inside* the runner container (must match the old scan_manager.py).
export const CONTAINER_TARGET = '/scan/target';
export const CONTAINER_SCANS = '/app/scans';
export const UPLOADS_SUBDIR = '_uploads';
