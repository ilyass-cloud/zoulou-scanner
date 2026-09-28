"""CLI entry point for the Security Orchestrator.

Usage:
    python -m orchestrator.main scan \\
        --repo PATH \\
        --config PATH \\
        --out OUTDIR \\
        [--network-allowlist allowlist.txt] \\
        [--network-input nmap.xml] \\
        [--no-llm] \\
        [--verbose]

⚠️  NETWORK SCANNING NOTICE ⚠️
The --network-allowlist flag enables the network inventory plugin.
Only targets explicitly listed in the allowlist file will be scanned.
You MUST have written authorization to scan every target.
Unauthorized scanning is illegal in most jurisdictions.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from pathlib import Path

from orchestrator.config import load_config
from orchestrator.correlate import dedup_and_correlate
from orchestrator.llm_analysis import run_llm_analysis
from orchestrator.llm_client import build_client_from_config
from orchestrator.models import ScanResult
from orchestrator.normalize import normalize_all
from orchestrator.planner import plan
from orchestrator.report import write_reports
from orchestrator.runner import run_all
from orchestrator.scoring import score_all

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _force_utf8_io() -> None:
    """Force stdout/stderr to UTF-8.

    Windows consoles default to cp1252, which cannot encode the dashes, arrows
    and warning signs used in the help text and log messages — argparse would
    otherwise abort with a UnicodeEncodeError before printing anything.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description=(
            "Security Orchestrator – plugin-based vulnerability scanning pipeline.\n\n"
            "⚠️  NETWORK SCANNING: Only targets in --network-allowlist are scanned.\n"
            "    Ensure you have written authorization for every target."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run the scanning pipeline")
    scan_p.add_argument(
        "--repo", required=True, metavar="PATH",
        help="Path to the repository / project root to scan",
    )
    scan_p.add_argument(
        "--config", required=False, default=None, metavar="PATH",
        help="Path to orchestrator config file (.yaml or .json)",
    )
    scan_p.add_argument(
        "--out", required=False, default="out", metavar="OUTDIR",
        help="Output directory for reports and raw plugin outputs (default: out/)",
    )
    scan_p.add_argument(
        "--network-allowlist", default=None, metavar="FILE",
        help=(
            "Path to allowlist file (one IP/hostname per line, # comments allowed). "
            "REQUIRED to enable the network inventory plugin. "
            "⚠️  Only scan targets you are authorized to scan."
        ),
    )
    scan_p.add_argument(
        "--network-input", default=None, metavar="FILE",
        help=(
            "Path to a pre-generated nmap XML file. "
            "If provided, the network plugin parses this file instead of executing a scan."
        ),
    )
    scan_p.add_argument(
        "--no-llm", action="store_true",
        help="Disable LLM analysis (useful for offline/CI runs)",
    )
    scan_p.add_argument(
        "--auto-scan", action="store_true",
        help=(
            "Enable auto-scan mode: detect repo environment, then use LLM "
            "(or rule-based fallback) to select appropriate scanning tools "
            "from the tools registry."
        ),
    )
    scan_p.add_argument(
        "--tools-registry", default=None, metavar="FILE",
        help="Path to tools_registry.yaml (default: auto-discover)",
    )
    scan_p.add_argument(
        "--tools", default=None, metavar="NAMES",
        help="Comma-separated list of tool names to run (e.g. semgrep,pip-audit)",
    )
    scan_p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    # ------------------------------------------------------------------
    # run-plan: runner-container entry point (execute a pre-built plan)
    # ------------------------------------------------------------------
    runplan_p = sub.add_parser(
        "run-plan",
        help=(
            "Execute a deterministic scan plan (plan.json) and write raw "
            "artifacts.json. This is the scanner-runner container entry point – "
            "it only executes tools, it does NOT plan or analyse."
        ),
    )
    runplan_p.add_argument(
        "--plan", required=True, metavar="FILE",
        help="Path to plan.json produced by the orchestrator brain",
    )
    runplan_p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    # ------------------------------------------------------------------
    # plan: brain step 1 – select tools + emit plan.json (no execution)
    # ------------------------------------------------------------------
    plan_p = sub.add_parser(
        "plan",
        help=(
            "Detect the repo environment, select tools, and write plan.json. "
            "Brain entry point used by the Node backend before launching the "
            "scanner-runner container. No scanners are executed."
        ),
    )
    plan_p.add_argument("--repo", required=True, metavar="PATH",
                        help="Repo path visible to the brain (used for tool selection)")
    plan_p.add_argument("--out", required=True, metavar="DIR",
                        help="Directory to write plan.json into (host-side)")
    plan_p.add_argument("--run-id", required=True, metavar="ID")
    plan_p.add_argument("--runner-repo", default="/scan/target", metavar="PATH",
                        help="Repo path the runner container will see")
    plan_p.add_argument("--runner-out", required=True, metavar="PATH",
                        help="Output dir the runner container will see")
    plan_p.add_argument("--config", default=None, metavar="PATH")
    plan_p.add_argument("--auto-scan", action="store_true")
    plan_p.add_argument("--families", default=None, metavar="NAMES",
                        help="Comma-separated families (sast,deps,secrets,container) "
                             "an automatic selection is restricted to")
    plan_p.add_argument("--tools", default=None, metavar="NAMES",
                        help="Comma-separated tool names to run")
    plan_p.add_argument("--tools-registry", default=None, metavar="FILE",
                        help="Path to tools_registry.yaml (default: from config)")
    plan_p.add_argument("--network-allowlist", default=None, metavar="PATH",
                        help="Allowlist path as seen by the runner container")
    plan_p.add_argument("--network-input", default=None, metavar="PATH",
                        help="nmap XML path as seen by the runner container")
    plan_p.add_argument("--no-llm", action="store_true",
                        help="Disable LLM-assisted tool selection")
    plan_p.add_argument("--verbose", "-v", action="store_true")

    # ------------------------------------------------------------------
    # postprocess: brain step 3 – analyse artifacts.json + write reports
    # ------------------------------------------------------------------
    post_p = sub.add_parser(
        "postprocess",
        help=(
            "Load artifacts.json produced by the runner and run "
            "normalize → correlate → score → LLM → report. Brain entry point "
            "used by the Node backend after the runner finishes."
        ),
    )
    post_p.add_argument("--out", required=True, metavar="DIR",
                        help="Run dir containing artifacts.json; reports written here")
    post_p.add_argument("--run-id", required=True, metavar="ID")
    post_p.add_argument("--repo", default="", metavar="PATH",
                        help="Original repo path (recorded in the report)")
    post_p.add_argument("--config", default=None, metavar="PATH")
    post_p.add_argument("--no-llm", action="store_true")
    post_p.add_argument("--verbose", "-v", action="store_true")

    # ------------------------------------------------------------------
    # env-detect / auto-plan: brain helpers that emit JSON to stdout
    # ------------------------------------------------------------------
    env_p = sub.add_parser("env-detect", help="Detect a repo's environment; print JSON")
    env_p.add_argument("--repo", required=True, metavar="PATH")
    env_p.add_argument("--verbose", "-v", action="store_true")

    auto_p = sub.add_parser("auto-plan", help="Detect env + suggest tools; print JSON")
    auto_p.add_argument("--repo", required=True, metavar="PATH")
    auto_p.add_argument("--config", default=None, metavar="PATH")
    auto_p.add_argument("--no-llm", action="store_true")
    auto_p.add_argument("--verbose", "-v", action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

#: Code de sortie du verdict de risque. Distinct de 1, qui signale une panne :
#: l'appelant doit pouvoir séparer « le scan a échoué » de « le scan a réussi et
#: son résultat est inacceptable ».
RISK_GATE_EXIT = 2


def risk_gate(cfg, findings) -> int:
    """Code de sortie selon la politique de risque : 0, ou RISK_GATE_EXIT.

    Deux politiques cumulables. `fail_on_critical` regarde la sévérité brute
    rapportée par l'outil ; `fail_on_score` regarde le score effectivement
    calculé, exposition et corrélation comprises. La seconde existe parce que la
    première ne voit pas ce que le pipeline prétend apporter : un résultat porté
    à 100 par son exposition ne déclenche pas une garde qui n'interroge que sa
    sévérité d'origine.

    Appelée depuis `scan` comme depuis `postprocess`. L'omettre du second, comme
    c'était le cas, rendait la garde inatteignable par le chemin conteneurisé —
    celui qu'emprunte le backend web, et donc toute intégration continue.
    """
    from orchestrator.models import Severity

    # Chaque commande de ce module tient son propre journal ; la garde étant
    # appelée depuis plusieurs d'entre elles, elle a le sien.
    log = logging.getLogger("orchestrator.risk_gate")

    tripped = False
    if cfg.fail_on_critical:
        critical = [f for f in findings if f.severity_raw == Severity.CRITICAL]
        if critical:
            log.error("fail_on_critical: %d critical finding(s) found", len(critical))
            tripped = True

    threshold = cfg.fail_on_score
    if threshold is not None:
        over = [f for f in findings if f.risk_score >= threshold]
        if over:
            log.error(
                "fail_on_score: %d finding(s) at or above %.1f (highest %.1f)",
                len(over), threshold, max(f.risk_score for f in over),
            )
            tripped = True

    return RISK_GATE_EXIT if tripped else 0


def cmd_scan(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    log = logging.getLogger("orchestrator.main")

    repo_path = str(Path(args.repo).resolve())
    out_dir = str(Path(args.out).resolve())
    run_id = str(uuid.uuid4())[:8]

    log.info("=== Security Orchestrator – run %s ===", run_id)
    log.info("repo: %s", repo_path)
    log.info("output: %s", out_dir)

    # 1. Load config
    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        log.error("Config error: %s", exc)
        return 1

    # 1b. Load tools registry if needed
    from orchestrator.config import load_tools_registry
    auto_scan = getattr(args, 'auto_scan', False)
    tools_arg = getattr(args, 'tools', None)
    selected_tools = [t.strip() for t in tools_arg.split(",")] if tools_arg else None
    registry_path = getattr(args, 'tools_registry', None) or cfg.tools_registry_path
    tools_registry = load_tools_registry(registry_path) if (auto_scan or selected_tools) else None

    # 2. Plan
    plan_items = plan(
        repo_path=repo_path,
        cfg=cfg,
        output_dir=out_dir,
        network_allowlist=args.network_allowlist,
        network_input=args.network_input,
        auto_scan=auto_scan,
        tools_registry=tools_registry,
        selected_tools=selected_tools,
    )
    if not plan_items:
        log.warning("No plugins were selected. Check your config and plugin input files.")

    # 3. Run plugins
    artifacts = run_all(plan_items)

    # 4. Normalize
    default_exposure = cfg.network.default_exposure
    findings = normalize_all(artifacts, default_exposure=default_exposure)

    # 5. Deduplicate + correlate
    findings = dedup_and_correlate(findings)

    # 6. Score
    findings = score_all(
        findings,
        external_exposure_boost=cfg.external_exposure_boost,
        low_confidence_penalty=cfg.low_confidence_penalty,
    )

    # 7. LLM analysis
    llm_enabled = cfg.llm.enabled and not args.no_llm
    client = build_client_from_config(cfg)
    executive_summary, top_findings_text = run_llm_analysis(
        client,
        findings,
        enabled=llm_enabled,
        top_n=cfg.llm.top_findings_count,
        max_workers=cfg.llm.analysis_workers,
    )

    # 8. Collect errors
    errors = [
        f"[{a.plugin_name}] {a.stderr.strip()}"
        for a in artifacts
        if a.exit_code != 0 and a.stderr
    ]

    # 9. Build result
    result = ScanResult(
        run_id=run_id,
        repo_path=repo_path,
        config_path=args.config or "(defaults)",
        artifacts=artifacts,
        findings=findings,
        executive_summary=executive_summary,
        top_findings_analysis=top_findings_text,
        errors=errors,
    )

    # 10. Write reports
    json_path, md_path = write_reports(result, out_dir)

    log.info("=== Scan complete ===")
    log.info("Findings: %d", len(findings))
    log.info("JSON report: %s", json_path)
    log.info("Markdown report: %s", md_path)

    return risk_gate(cfg, findings)


# ---------------------------------------------------------------------------
# run-plan command  (scanner-runner container)
# ---------------------------------------------------------------------------

def cmd_run_plan(args: argparse.Namespace) -> int:
    """Execute a pre-built plan.json and write artifacts.json.

    This runs inside the ephemeral scanner-runner container. It performs no
    planning, normalisation, scoring or LLM analysis – only tool execution.
    """
    _setup_logging(args.verbose)
    log = logging.getLogger("orchestrator.run_plan")

    from orchestrator.ipc import load_scan_plan, write_artifacts
    from orchestrator.planner import plan_items_from_scan_plan

    plan_path = str(Path(args.plan).resolve())
    log.info("=== Scanner runner – executing plan %s ===", plan_path)

    try:
        scan_plan = load_scan_plan(plan_path)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load plan: %s", exc)
        return 1

    log.info("run %s: target=%s tools=%s network=%s",
             scan_plan.run_id, scan_plan.repo_path,
             [t.name for t in scan_plan.tools], scan_plan.include_network)

    plan_items = plan_items_from_scan_plan(scan_plan)
    if not plan_items:
        log.warning("Plan contains no executable tools.")

    artifacts = run_all(plan_items)
    artifacts_path = write_artifacts(artifacts, scan_plan.output_dir)

    failures = sum(1 for a in artifacts if a.exit_code != 0)
    log.info("=== Runner complete: %d artifact(s), %d non-zero exit(s) ===",
             len(artifacts), failures)
    log.info("Artifacts: %s", artifacts_path)
    return 0


# ---------------------------------------------------------------------------
# Brain steps invoked by the Node backend (plan / postprocess / detect)
# ---------------------------------------------------------------------------

def _load_cfg_with_llm(config_path, no_llm: bool):
    """Load config and apply the LLM toggle (mirrors web behaviour)."""
    cfg = load_config(config_path)
    cfg.llm.enabled = (not no_llm) and cfg.llm.enabled
    return cfg


def cmd_plan(args: argparse.Namespace) -> int:
    """Select tools and write plan.json. No scanners are executed."""
    _setup_logging(args.verbose)
    log = logging.getLogger("orchestrator.plan")

    from orchestrator.config import load_tools_registry
    from orchestrator.ipc import write_scan_plan
    from orchestrator.planner import build_scan_plan

    cfg = _load_cfg_with_llm(args.config, args.no_llm)

    selected_tools = (
        [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else None
    )
    registry = None
    if args.auto_scan or selected_tools:
        registry = load_tools_registry(args.tools_registry or cfg.tools_registry_path or "tools_registry.yaml")

    scan_plan = build_scan_plan(
        args.run_id, cfg,
        plan_repo_path=str(Path(args.repo).resolve()),
        runner_repo_path=args.runner_repo,
        runner_output_dir=args.runner_out,
        auto_scan=args.auto_scan,
        tools_registry=registry,
        selected_tools=selected_tools,
        families=([f.strip() for f in args.families.split(",") if f.strip()]
                  if args.families is not None else None),
        network_allowlist=args.network_allowlist,
        network_input=args.network_input,
    )
    path = write_scan_plan(scan_plan, args.out)

    tool_names = [t.name for t in scan_plan.tools]
    log.info("Planned %d tool(s): %s%s",
             len(tool_names), ", ".join(tool_names) or "(none)",
             " + network" if scan_plan.include_network else "")
    log.info("Wrote plan: %s", path)
    return 0


def cmd_postprocess(args: argparse.Namespace) -> int:
    """Load artifacts.json and run normalize → correlate → score → LLM → report."""
    _setup_logging(args.verbose)
    log = logging.getLogger("orchestrator.postprocess")

    from orchestrator.ipc import ARTIFACTS_FILENAME, load_artifacts

    out_dir = Path(args.out).resolve()
    cfg = _load_cfg_with_llm(args.config, args.no_llm)

    artifacts = load_artifacts(out_dir / ARTIFACTS_FILENAME)
    log.info("Loaded %d raw artifact(s); analysing…", len(artifacts))

    findings = normalize_all(artifacts, default_exposure=cfg.network.default_exposure)
    findings = dedup_and_correlate(findings)
    findings = score_all(
        findings,
        external_exposure_boost=cfg.external_exposure_boost,
        low_confidence_penalty=cfg.low_confidence_penalty,
    )

    executive_summary = top_findings_text = None
    if cfg.llm.enabled:
        client = build_client_from_config(cfg)
        executive_summary, top_findings_text = run_llm_analysis(
            client, findings, enabled=True,
            top_n=cfg.llm.top_findings_count,
            max_workers=cfg.llm.analysis_workers,
        )

    errors = [
        f"[{a.plugin_name}] {a.stderr.strip()}"
        for a in artifacts
        if a.exit_code != 0 and a.stderr
    ]

    result = ScanResult(
        run_id=args.run_id,
        repo_path=args.repo,
        config_path=args.config or "(defaults)",
        artifacts=artifacts,
        findings=findings,
        executive_summary=executive_summary,
        top_findings_analysis=top_findings_text,
        errors=errors,
    )
    json_path, md_path = write_reports(result, str(out_dir))
    log.info("=== Post-processing complete: %d finding(s) ===", len(findings))
    log.info("JSON report: %s", json_path)
    log.info("Markdown report: %s", md_path)
    # Le récapitulatif lisible par la machine est écrit avant la garde : un
    # verdict de risque n'est pas une panne, et l'appelant doit recevoir son
    # décompte dans les deux cas.
    print(json.dumps({"finding_count": len(findings)}))
    return risk_gate(cfg, findings)


def cmd_env_detect(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    from orchestrator.env_detect import detect_environment
    profile = detect_environment(str(Path(args.repo).resolve()))
    print(json.dumps(profile.model_dump()))
    return 0


def cmd_auto_plan(args: argparse.Namespace) -> int:
    _setup_logging(args.verbose)
    from orchestrator.auto_planner import auto_plan
    from orchestrator.config import load_tools_registry

    cfg = _load_cfg_with_llm(args.config, args.no_llm)
    registry = load_tools_registry(cfg.tools_registry_path or "tools_registry.yaml")

    llm_client = build_client_from_config(cfg) if cfg.llm.enabled else None
    profile, selected = auto_plan(
        str(Path(args.repo).resolve()), registry,
        llm_client=llm_client, use_llm=cfg.llm.enabled,
    )
    print(json.dumps({
        "profile": profile.model_dump(),
        "selected_tools": [t.model_dump() for t in selected],
    }))
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    _force_utf8_io()
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {
        "scan": cmd_scan,
        "run-plan": cmd_run_plan,
        "plan": cmd_plan,
        "postprocess": cmd_postprocess,
        "env-detect": cmd_env_detect,
        "auto-plan": cmd_auto_plan,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.error(f"unknown command: {args.command}")
    sys.exit(handler(args))


if __name__ == "__main__":
    main()

