# Running with Docker

The orchestrator runs as **two images**:

| Image | Role | Lifetime |
|-------|------|----------|
| `security-orchestrator-web` | UI + brain: planning, LLM analysis, reporting. **No scanners.** | long-running service |
| `security-orchestrator` | Scanner-runner: all scanners installed, executes a plan. | ephemeral, one per scan |

The **web** container starts a **scanner-runner** container per scan, via the
host Docker daemon (it has the Docker socket mounted). They exchange data over
a shared `scans` directory: web writes `plan.json` → runner writes
`artifacts.json` → web reads it back and analyzes.

---

## Quick start (docker compose)

```bash
# 1. Build BOTH images (the `runner` profile pulls in the scanner-runner)
docker compose --profile runner build

# 2. Start only the web/brain service
docker compose up -d

# 3. Open the UI
#    http://localhost:5000
```

`docker compose up` deliberately starts **only** `web`. The scanner-runner is
not a service — compose just builds its image so the web container can launch
it on demand.

To stop: `docker compose down`.

### Configuration

Override these via a `.env` file next to `docker-compose.yml`, or your shell:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SCANS_DIR` | `/data/scans` | Where run dirs (plan/artifacts/reports) live. Bind-mounted at the **same path** on host and in-container. |
| `WORKSPACE_DIR` | `/data/workspace` | Root directory holding the repos you want to scan (mounted read-only). |
| `LLM_BASE_URL` | `http://host.docker.internal:1234` | Local LLM endpoint (e.g. LM Studio on the host). |
| `SCANNER_IMAGE` | `security-orchestrator` | Name of the runner image to launch. |
| `BROWSE_ROOT` | falls back to `WORKSPACE_DIR` | Root the directory picker may show, and the jail scan targets must stay inside. |
| `REQUIRE_AUTH` | on when `DATABASE_URL` is set | Force the `/api` login requirement on (`1`) or off (`0`). |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / `changeme` | Seed the first account. Applied **only** while the users table is empty. Change them. |
| `APP_SECRET_KEY` | *(unset)* | Session cookie signing key. Random per process when unset; **required** if `NODE_ENV=production`. |
| `MAX_CONCURRENT_SCANS` | `2` | Scans allowed to run at once; the rest queue. Each one launches a container. |
| `MAX_LOG_LINES` | `5000` | Log lines retained per scan in memory. Older lines are dropped, and the viewer is told how many. |
| `MAX_FINISHED_JOBS` | `50` | Finished scans kept in memory. Evicted ones are still listed from their `meta.json` on disk. |

Example `.env`:

```dotenv
SCANS_DIR=/srv/orchestrator/scans
WORKSPACE_DIR=/srv/orchestrator/repos
LLM_BASE_URL=http://host.docker.internal:1234
ADMIN_USERNAME=you
ADMIN_PASSWORD=<a real password>
APP_SECRET_KEY=<output of: openssl rand -hex 32>
```

### 🔐 Authentication

`compose` sets `DATABASE_URL`, so **the API requires a login by default**. Sign
in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`; the account is created on first
boot and only while no users exist, so changing those variables later will not
reset an existing password (edit the user in the UI instead).

Set `REQUIRE_AUTH=0` to disable the requirement. Only do that on a machine
where nothing else can reach the port: `/api/tools` and `/api/scan` between
them run commands, so an open instance is a remote code execution surface.

### ⚠️ Path rules (docker-out-of-docker)

The web container starts the runner on the **host** daemon, so any path it
passes to `docker run -v` is resolved by the **host**, not inside the web
container. Two consequences:

1. **`SCANS_DIR` and `WORKSPACE_DIR` are mounted at the same absolute path on
   host and in the container.** Don't change one side only.
2. **Scan targets must live under `WORKSPACE_DIR`.** The brain reads the repo
   from that path to plan, and the runner mounts the same host path read-only.
   A path outside the workspace won't be visible to both. This is now enforced,
   not just advised: the backend rejects a `repo_path` outside `BROWSE_ROOT`
   (which defaults to `WORKSPACE_DIR`) or the uploads directory, because that
   path is bind-mounted into the runner and passed to the scanner commands.

Make sure the host paths exist before starting:

```bash
mkdir -p /data/scans /data/workspace
# put (or clone) the repos you want to scan under /data/workspace
```

### Alternative: upload a folder (no mount, no path rules)

If you don't want to mount a workspace, the scan form has an **"upload a
project folder"** picker. The browser filters out heavy content
(`node_modules`, `.venv`, `.git`, build outputs, binaries, media…) **before**
uploading — manifests and lockfiles are kept — and the server unpacks what's
left onto the `scans` volume. Because it lands on the shared volume, the runner
can mount it with no docker-out-of-docker path matching needed. Good for one-off
scans; mounting is still better for large repos or repeated runs.

---

## Manual build & run (no compose)

```bash
# Build the scanner-runner (heavy: installs all scanners)
docker build -t security-orchestrator .

# Build the lightweight web/brain image
docker build -f web/Dockerfile -t security-orchestrator-web .

# Run the web container
docker run -d --name security-orchestrator-web \
  -p 5000:5000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /data/scans:/data/scans \
  -v /data/workspace:/data/workspace:ro \
  -e SCANS_DIR=/data/scans \
  -e SCANNER_IMAGE=security-orchestrator \
  -e LLM_BASE_URL=http://host.docker.internal:1234 \
  --add-host host.docker.internal:host-gateway \
  security-orchestrator-web
```

Then open <http://localhost:5000> and start a scan against a repo under
`/data/workspace`.

### Running the runner by hand (debugging)

The web app does this automatically, but you can invoke a plan directly:

```bash
docker run --rm \
  -v /data/workspace/myrepo:/scan/target:ro \
  -v /data/scans:/app/scans \
  security-orchestrator \
  python -m orchestrator.main run-plan \
    --plan /app/scans/<run_id>/plan.json --verbose
```

---

## Without Docker (single process)

For local development the all-in-one CLI still plans, runs, and analyzes in one
process (scanners must be installed locally — see `scripts/install_scanners.sh`):

```bash
python -m orchestrator.main scan --repo ./myrepo --out ./out --auto-scan --verbose
```