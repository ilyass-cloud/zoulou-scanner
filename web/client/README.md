# Security Orchestrator — React UI

A Vite + React single-page app that replaces the old Jinja templates +
vanilla JS frontend. It is a **pure frontend**: every data call goes to the
existing Flask backend under `/api/*` (see `web/api/routes.py`). No backend
logic was moved or rewritten — the Python orchestrator brain is untouched.

## Develop

The Flask backend must be running (it serves `/api`):

```bash
# terminal 1 – backend (from the project root)
python -m web.app --port 5000

# terminal 2 – frontend dev server (from web/client)
npm install
npm run dev          # http://localhost:5173
```

Vite proxies `/api` (including the SSE live-log stream) to Flask on
`http://127.0.0.1:5000`. Point it elsewhere with:

```bash
VITE_API_TARGET=http://my-host:5000 npm run dev
```

## Build for production

```bash
npm run build        # emits static assets to web/client/dist/
```

`dist/` is a static SPA. Serve it behind any static host (nginx, Caddy, a
CDN, or Flask's `send_from_directory`) and reverse-proxy `/api/*` to the Flask
backend. Because the app uses client-side routing (React Router), the static
host must fall back to `index.html` for unknown paths (SPA history fallback).

## Layout

```
src/
  main.jsx              app entry (Router + ThemeProvider)
  App.jsx               route table
  index.css             styles (carried over verbatim from the old UI)
  lib/
    api.js              all /api/* calls in one place
    format.js           severity/date/location formatting helpers
    ignore.js           client mirror of the upload ignore filter
    theme.jsx           light/dark theme context
  components/
    Layout.jsx          navbar + footer shell
    Badges.jsx          SeverityBadge / StatusBadge / ScoreBar
    BarChart.jsx        canvas bar chart (no chart lib)
    FindingModal.jsx    finding detail modal
  pages/
    Dashboard.jsx  ScanForm.jsx  ScanLive.jsx  ScansList.jsx
    ScanDetail.jsx  ScanReport.jsx  ToolsConfig.jsx
```

The routes mirror the old URLs (`/`, `/scan/new`, `/scan/:id/live`,
`/scans`, `/scans/:id`, `/scans/:id/report`, `/tools`) so existing deep links
keep working.
