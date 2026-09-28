# Technical reference

Detailed usage of the command line, configuration files, network plugin,
input formats and web API. For an overview, see the [README](../README.md).

---

## Architecture

```
orchestrator/
├── main.py          CLI entry point
├── config.py        YAML/JSON config loader
├── models.py        Pydantic data models (Finding, ScanResult, …)
├── planner.py       Selects which plugins to run
├── runner.py        Executes plugins, captures timing/errors
├── normalize.py     Converts raw outputs → Finding[]
├── correlate.py     Deduplication + cross-finding correlation
├── scoring.py       Deterministic risk scoring (0–100)
├── llm_client.py    LM Studio HTTP client
├── llm_analysis.py  LLM triage / remediation / summary
├── report.py        Writes report.json + report.md
└── plugins/
    ├── base.py          BasePlugin interface
    ├── sast_stub.py     Reads SARIF/JSON file
    ├── deps_stub.py     Reads JSON findings file
    ├── secrets_stub.py  Reads JSON findings file
    ├── container_stub.py Reads JSON findings file
    └── network.py       Authorized network inventory (parse-only or execute)
```

---

## Installation

```bash
pip install pydantic pyyaml
# Optional – only needed for execute mode network scanning:
# brew install nmap   (macOS)
# apt install nmap    (Debian/Ubuntu)
```

Python 3.11+ recommended.

---

## Quick Start – Parse-Only Mode (no live scanning)

This mode uses pre-generated scanner outputs and a pre-captured nmap XML file. **No live scanning occurs.**

### 1. Run with all stub scanners + network parse-only

```bash
python -m orchestrator.main scan \
  --repo . \
  --config examples/config.yaml \
  --out out/ \
  --network-allowlist examples/allowlist.txt \
  --network-input examples/sample_nmap.xml \
  --no-llm
```

`--no-llm` skips LM Studio calls (useful offline or in CI).

### 2. Run with LLM analysis (LM Studio must be running)

```bash
python -m orchestrator.main scan \
  --repo . \
  --config examples/config.yaml \
  --out out/ \
  --network-allowlist examples/allowlist.txt \
  --network-input examples/sample_nmap.xml
```

LM Studio default endpoint: `http://localhost:1234`. Override via `llm.base_url` in config.

### 3. View outputs

```
out/
├── report.json          Full machine-readable report
├── report.md            Human-readable Markdown report
└── raw/
    ├── sast/            Copied SARIF/JSON input
    ├── deps/            Copied deps JSON input
    ├── secrets/         Copied secrets JSON input
    ├── container/       Copied container JSON input
    └── network/         Copied nmap XML input
```

---

## Configuration

Copy `examples/config.yaml` and edit as needed:

```yaml
llm:
  base_url: "http://localhost:1234"
  model: "local-model"
  enabled: true

network:
  allow_cidr: false          # true to permit CIDR ranges in allowlist
  default_exposure: "internal"

plugins:
  sast:
    input_file: "path/to/your.sarif.json"
  deps:
    input_file: "path/to/deps-findings.json"
```

---

## Network Plugin

### Allowlist format (`allowlist.txt`)

```
# Comments start with #
10.0.0.1
10.0.0.2
webserver.internal
```

- One IP or hostname per line
- CIDR ranges (e.g. `10.0.0.0/24`) are **rejected by default**; set `network.allow_cidr: true` to permit them
- Empty lines and comments are ignored
- Every entry must be an IP address, a CIDR range, or a hostname. Entries are
  passed to the scanner as arguments, so anything beginning with `-` is
  **rejected**: an allowlist line like `--script=vuln` would otherwise turn this
  passive inventory plugin into an active exploitation scan
- Validation fails closed — one bad entry rejects the whole file, rather than
  scanning the valid remainder
- Address ranges must be written as CIDR. nmap's `10.0.0.1-20` syntax is
  rejected: authorization is resolved to a concrete set of addresses before
  scanning, and a range that cannot be expanded cannot be verified
- **Hostnames are resolved before the scan starts, and the scanner is given the
  resolved address**, never the name. This is what makes the allowlist an
  authorization control rather than a label: the address that was checked is the
  address that gets scanned. An entry that does not resolve aborts the run
- Results are matched back to the allowlist by address membership. A host that
  was not authorized cannot appear in the report by claiming an allowlisted
  hostname in the scan XML

### Parse-only mode (recommended for MVP)

Pass `--network-input path/to/nmap.xml`. The plugin parses the XML and produces findings without executing any scan.

### Execute mode

Omit `--network-input`. The plugin calls `nmap` (or the configured binary) with conservative inventory flags:

```
nmap -sV --open -T2 --version-intensity 2 <targets>
```

No exploit modules, no brute-force, no vulnerability scanning.

---

## Scoring Formula

```
risk_score = clamp(
    SEVERITY_BASE[severity]          # CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20, INFO=5
  + external_exposure_boost          # +15 if exposure=external (configurable)
  - low_confidence_penalty           # -10 if confidence=LOW (configurable)
  + min(related_count × 5, 15)       # correlation boost, capped at 15
, 0, 100)
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Expected output: all tests pass (allowlist, fingerprint, scoring, network XML parse).

---

## Stub Input File Formats

### SAST (`sample_sast.sarif.json`)
Standard SARIF 2.1 format. Any SARIF-compliant tool output works.

### Deps (`sample_deps.json`)
```json
[{ "package": "requests", "version": "2.25.0", "cve": "CVE-2023-32681",
   "severity": "MEDIUM", "description": "...", "manifest": "requirements.txt" }]
```

### Secrets (`sample_secrets.json`)
```json
[{ "rule_id": "aws-access-key", "description": "...", "file": "deploy.sh",
   "line": 23, "severity": "HIGH", "evidence": "AKIA..." }]
```

### Container (`sample_container.json`)
```json
[{ "image": "myapp:latest", "package": "openssl", "version": "1.1.1t",
   "cve": "CVE-2023-0286", "severity": "HIGH", "description": "..." }]
```

---

## LLM Grounding Rule

The LLM is instructed: *"If the `evidence` field is null or empty, you MUST state: 'insufficient evidence to assess this finding.' Do NOT invent CVE details, exploit paths, or package names not present in the data."*

The LLM **does not replace scanners**. It only interprets structured findings to produce executive summaries and remediation guidance.

---

## Web GUI

A full browser-based interface for configuring, running, and reviewing scans.

The UI is a **React SPA** (`web/client`) served by a **Node/Express backend**
(`web/server`). The Express server owns all HTTP/SSE/uploads/Postgres and
invokes the Python orchestrator *brain* as a CLI (`plan` / `postprocess` /
`env-detect` / `auto-plan`); scans run in the ephemeral scanner-runner
container via `docker run`. There is no Flask layer anymore.

### Installation

```bash
pip install pydantic pyyaml          # orchestrator brain deps
cd web/server && npm install         # backend
cd ../client && npm install          # frontend
```

### Launch (development)

```bash
# 1. backend (from web/server) – serves /api on :5000
npm start

# 2. frontend dev server (from web/client) – proxies /api to :5000
npm run dev          # → http://localhost:5173
```

### Launch (production / single process)

```bash
cd web/client && npm run build       # emits web/client/dist
cd ../server   && npm start          # serves the SPA + /api on :5000
# → http://127.0.0.1:5000
```

Or build the all-in-one image (Node + React + Python brain + docker CLI):
`docker build -f web/Dockerfile -t security-orchestrator-web .`

### File structure

```
web/
├── server/              Node/Express backend (replaces the old Flask app)
│   ├── index.js         App entry: mounts /api routers, serves the built SPA
│   ├── config.js        Env-driven config (ports, SCANS_DIR, image, python bin)
│   ├── lib/
│   │   ├── jobManager.js  Job registry + plan→docker run→postprocess + SSE
│   │   ├── pg.js          Postgres layer (api keys, users, reports, settings)
│   │   ├── python.js      Spawns the orchestrator brain, parses JSON stdout
│   │   ├── browse.js      Jailed server-side directory picker
│   │   └── ignore.js      Upload ignore filter + folder save
│   └── routes/          scans · tools · configs · misc · db
└── client/              React SPA (Vite) – see web/client/README.md
    └── src/
        ├── pages/       Dashboard, ScanForm, ScanLive, ScansList,
        │                ScanDetail, ScanReport, ToolsConfig
        ├── components/  Layout, Badges, BarChart, FindingModal
        └── lib/         api.js, format.js, theme.jsx, ignore.js
```

The Python orchestrator *brain* is reached only via CLI subcommands added to
`orchestrator/main.py`: `plan`, `postprocess`, `env-detect`, `auto-plan`.

### UI Layout

```
┌─────────────────────────────────────────────────────────────┐
│ 🔒 Security Orchestrator  Dashboard  New Scan  History   🌙 │  ← Navbar
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [Total Scans: 5]  [Running: 0]  [Findings: 42]  [Last: …] │  ← Stat cards
│                                                             │
│  ┌─ Risk Distribution ──────────────────────────────────┐  │
│  │  ██ CRITICAL  ████ HIGH  ██ MEDIUM  █ LOW  █ INFO    │  │  ← Bar chart
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─ Recent Scans ───────────────────────────────────────┐  │
│  │  Run ID   Status   Findings  Started       Actions   │  │
│  │  a1b2c3d  ✅ done  14        2024-01-15    Results   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

New Scan form:
  • Repository path text input
  • Config file dropdown (auto-populated from examples/ and configs/)
  • Plugin cards with enable/disable toggles and file upload per plugin
  • Network plugin card (orange border) with allowlist + nmap XML upload
  • LLM analysis toggle
  • Start Scan button → redirects to live view

Live Scan view:
  • Plugin progress list (⏳ waiting → ⚙️ running → ✅ done / ❌ error)
  • Scrolling log terminal (colour-coded INFO/WARN/ERROR/DEBUG)
  • Cancel button
  • Done panel with finding count + links to results

Findings Dashboard:
  • Executive summary (LLM, collapsible)
  • Severity bar chart + Source bar chart side by side
  • Findings table: sortable Score/Severity/Source columns
  • Filters: text search, severity dropdown, source dropdown, score ≥ N
  • Click any row → modal with full finding details, evidence, remediation,
    related finding chips (click to jump)
  • Export CSV button
```

### API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a new scan (multipart or JSON) |
| `GET`  | `/api/scans` | List all scan runs |
| `GET`  | `/api/scans/{run_id}` | Get scan metadata / status |
| `GET`  | `/api/scans/{run_id}/report` | Full `report.json` payload |
| `GET`  | `/api/scans/{run_id}/report.md` | `report.md` rendered as HTML |
| `GET`  | `/api/scans/{run_id}/logs` | SSE stream of live log lines |
| `POST` | `/api/scans/{run_id}/cancel` | Cancel a running scan |
| `DELETE` | `/api/scans/{run_id}` | Delete scan result from disk |
| `GET`  | `/api/configs` | List available config files |
| `GET`  | `/api/configs/{filename}` | Get raw config file content |
| `POST` | `/api/configs` | Save/update a config file |

### Scan results storage

Each scan run is stored under `scans/<run_id>/`:
```
scans/
└── c6a12efe/
    ├── meta.json      Job metadata (status, timing, finding count)
    ├── report.json    Full ScanResult with all findings
    ├── report.md      Human-readable Markdown report
    └── raw/           Raw plugin outputs (copied input files)
```

Results persist across server restarts and are listed in the scan history page.

