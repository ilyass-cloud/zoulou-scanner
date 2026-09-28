// GitHub OAuth2 (authorization-code flow) + minimal REST API client. Used to
// connect a GitHub account once and then list that account's repositories.
// Tokens live in the git_accounts table; this module only talks to GitHub.
import { config } from '../config.js';

const gh = config.github;

export function isConfigured() {
  return Boolean(gh.clientId && gh.clientSecret);
}

export function redirectUri() {
  return `${config.appBaseUrl}/api/git/github/callback`;
}

// URL the browser is sent to so the user can authorize the OAuth app.
export function authorizeUrl(state) {
  const p = new URLSearchParams({
    client_id: gh.clientId,
    redirect_uri: redirectUri(),
    scope: gh.scope,
    state,
    allow_signup: 'false',
  });
  return `${gh.authBase}/login/oauth/authorize?${p}`;
}

// Exchange the ?code from the callback for an access token.
export async function exchangeCode(code) {
  const res = await fetch(`${gh.authBase}/login/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_id: gh.clientId,
      client_secret: gh.clientSecret,
      code,
      redirect_uri: redirectUri(),
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error || !data.access_token) {
    throw new Error(data.error_description || data.error || `Token exchange failed (HTTP ${res.status})`);
  }
  return { access_token: data.access_token, refresh_token: data.refresh_token || null, scopes: data.scope || '' };
}

async function api(token, path, params) {
  const url = new URL(`${gh.apiBase}${path}`);
  if (params) for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'security-orchestrator',
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.message || `GitHub API ${path} failed (HTTP ${res.status})`);
  }
  return res.json();
}

// The authenticated user's profile.
export const fetchUser = (token) => api(token, '/user');

// List repositories accessible to the token (owner + collaborator + org),
// newest-pushed first. Paginates up to `max` repos.
export async function listRepos(token, { max = 200 } = {}) {
  const out = [];
  for (let page = 1; out.length < max; page++) {
    const batch = await api(token, '/user/repos', {
      per_page: '100', page: String(page), sort: 'pushed', affiliation: 'owner,collaborator,organization_member',
    });
    if (!batch.length) break;
    for (const r of batch) {
      out.push({
        full_name: r.full_name,
        name: r.name,
        clone_url: r.clone_url,
        private: r.private,
        default_branch: r.default_branch,
        pushed_at: r.pushed_at,
      });
    }
    if (batch.length < 100) break;
  }
  return out;
}
