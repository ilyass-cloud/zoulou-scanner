"""Authorized network inventory plugin.

⚠️  SECURITY NOTICE ⚠️
This plugin performs PASSIVE INVENTORY ONLY (service version detection).
It will ONLY scan targets explicitly listed in a user-provided allowlist file.
It does NOT perform exploit attempts, brute-force attacks, or vulnerability
exploitation of any kind.  Scanning targets without authorization is illegal
in most jurisdictions.  You are solely responsible for obtaining written
authorization before scanning any target.

Modes:
  Parse-only  – pass --network-input <nmap.xml>; no subprocess is spawned.
  Execute     – no --network-input; calls the configured scanner binary with
                conservative inventory flags from config.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Sequence, Union

from orchestrator.models import RawScanArtifact, ScanType
from orchestrator.plugins.base import BasePlugin, PluginContext

log = logging.getLogger(__name__)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

_CIDR_RE = re.compile(r"[/\\]")  # crude CIDR detector

# A DNS name, or an nmap octet-range target such as '192.168.1.1-20'. Labels are
# alphanumeric with interior hyphens, 1-63 chars each, 253 chars total.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.?$"
)


def _validate_target(line: str, lineno: int, allow_cidr: bool) -> Optional[str]:
    """Validate one allowlist entry. Returns an error message, or None if valid.

    Every entry becomes an argv element of the scanner invocation, so an entry
    that is not a target is an argument-injection vector: an allowlist line of
    '--script=vuln' previously turned this passive inventory plugin into an
    active exploitation scan, and '-T5 --min-rate=100000' turned a throttled
    scan into a flood. Anything that is not recognisably an address, a network,
    or a hostname is refused.
    """
    # Checked first, and explicitly, so the error names the real problem.
    if line.startswith("-"):
        return (
            f"Line {lineno}: '{line}' looks like a command-line flag, not a target. "
            "Allowlist entries are passed to the scanner as arguments and must be "
            "an IP address, a CIDR range, or a hostname."
        )

    if "\\" in line:
        return f"Line {lineno}: '{line}' contains a backslash and is not a valid target."

    if "/" in line:
        if not allow_cidr:
            return (
                f"Line {lineno}: CIDR range '{line}' rejected. "
                "Set network.allow_cidr=true in config to permit CIDR ranges."
            )
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            return f"Line {lineno}: invalid CIDR '{line}'"
        return None

    try:
        ipaddress.ip_address(line)
        return None
    except ValueError:
        pass

    # A purely numeric entry that is not an address is a malformed address or an
    # nmap-style range ('10.0.0.1-20'). Ranges are refused rather than passed
    # through: authorization is resolved to a concrete address set before
    # scanning, and a range this code cannot expand is a range it cannot verify.
    # CIDR expresses the same intent and is verifiable.
    if not any(char.isalpha() for char in line):
        return (
            f"Line {lineno}: '{line}' is not a valid IP address. "
            "Write address ranges as CIDR (e.g. 10.0.0.0/24) and enable "
            "network.allow_cidr."
        )

    if _HOSTNAME_RE.match(line):
        return None

    return (
        f"Line {lineno}: '{line}' is not a valid IP address, CIDR range, or hostname."
    )


def parse_allowlist(path: str, allow_cidr: bool = False) -> List[str]:
    """Parse allowlist file; return validated list of targets.

    Rules:
    - Lines starting with # are comments.
    - Empty lines are ignored.
    - Each entry must be an IP address, a CIDR range, or a hostname; anything
      else — in particular anything beginning with '-' — is rejected, because
      entries are passed straight to the scanner as arguments.
    - CIDR ranges are rejected unless allow_cidr=True.
    - Each entry is stripped of whitespace.
    """
    targets: List[str] = []
    errors: List[str] = []

    with open(path, encoding="utf-8") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            error = _validate_target(line, lineno, allow_cidr)
            if error:
                errors.append(error)
                continue

            targets.append(line)

    if errors:
        raise ValueError(
            "Allowlist validation failed:\n" + "\n".join(errors)
        )

    if not targets:
        raise ValueError(
            f"Allowlist file '{path}' contains no valid targets after parsing."
        )

    return targets


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

class AuthorizedTargets:
    """The addresses the operator authorized, resolved once, before any scan.

    The allowlist used to be enforced by filtering the scanner's *output*, which
    cannot prevent anything — by the time a result is discarded the packets have
    already been sent. Worse, a hostname entry was authorized by name but
    scanned by address, so what got probed was whatever DNS happened to return
    at that moment.

    Resolving up front and handing the scanner literal addresses closes that
    gap: the thing that was checked is the thing that is scanned. DNS can still
    change afterwards, but it no longer changes what this run touches.
    """

    def __init__(self, networks: List[IPNetwork], scan_targets: List[str]) -> None:
        self.networks = networks
        self.scan_targets = scan_targets

    @classmethod
    def resolve(
        cls,
        entries: Sequence[str],
        resolver=socket.getaddrinfo,
    ) -> "AuthorizedTargets":
        """Turn validated allowlist entries into addresses and networks.

        Args:
            entries: output of parse_allowlist().
            resolver: injectable for testing; defaults to socket.getaddrinfo.

        Raises:
            ValueError: a hostname could not be resolved. Fail closed — an
                unresolvable entry means we cannot say what would be scanned.
        """
        networks: List[IPNetwork] = []
        scan_targets: List[str] = []
        errors: List[str] = []

        for entry in entries:
            if "/" in entry:
                networks.append(ipaddress.ip_network(entry, strict=False))
                scan_targets.append(entry)
                continue

            try:
                address = ipaddress.ip_address(entry)
            except ValueError:
                address = None

            if address is not None:
                networks.append(ipaddress.ip_network(address))
                scan_targets.append(str(address))
                continue

            # A hostname: authorize and scan the addresses it resolves to now,
            # not the name, so the check and the scan cannot disagree.
            try:
                resolved = resolver(entry, None)
            except (OSError, socket.gaierror) as exc:
                errors.append(f"'{entry}' could not be resolved: {exc}")
                continue

            addresses = {info[4][0] for info in resolved}
            if not addresses:
                errors.append(f"'{entry}' resolved to no addresses")
                continue

            for raw in sorted(addresses):
                try:
                    resolved_address = ipaddress.ip_address(raw)
                except ValueError:
                    continue
                networks.append(ipaddress.ip_network(resolved_address))
                scan_targets.append(str(resolved_address))
                log.info("network: '%s' authorized as %s", entry, resolved_address)

        if errors:
            raise ValueError(
                "Allowlist could not be resolved to addresses:\n" + "\n".join(errors)
            )

        return cls(networks, scan_targets)

    def contains(self, address: str) -> bool:
        """Whether an address reported by the scanner was actually authorized."""
        try:
            parsed = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            return False
        return any(parsed in network for network in self.networks)


# ---------------------------------------------------------------------------
# Nmap XML parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_path: str) -> List[dict]:
    """Parse an nmap XML output file into a list of exposure dicts."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    findings: List[dict] = []

    for host_el in root.findall("host"):
        # Resolve address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        host = addr_el.get("addr", "unknown")

        # Hostname (optional)
        hostname_el = host_el.find(".//hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        # Ports
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            # Callers catch only ET.ParseError, so a non-numeric portid in an
            # uploaded XML used to escape the plugin's error handling entirely.
            # A malformed port is skipped rather than aborting the whole parse.
            raw_portid = port_el.get("portid")
            try:
                portid = int(raw_portid)
            except (TypeError, ValueError):
                log.warning("network: skipping port with non-numeric portid %r", raw_portid)
                continue
            if not 0 <= portid <= 65535:
                log.warning("network: skipping out-of-range portid %d", portid)
                continue

            protocol = port_el.get("protocol", "tcp")

            service_el = port_el.find("service")
            service_name = ""
            product = ""
            version = ""
            if service_el is not None:
                service_name = service_el.get("name", "")
                product = service_el.get("product", "")
                version = service_el.get("version", "")

            findings.append({
                "host": host,
                "hostname": hostname,
                "port": portid,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "product_version": version,
            })

    return findings


# ---------------------------------------------------------------------------
# Network plugin
# ---------------------------------------------------------------------------

class NetworkPlugin(BasePlugin):
    """Authorized network inventory plugin (parse-only or execute mode)."""

    name = "network"
    scan_type = ScanType.NETWORK

    # Warning printed to stderr whenever the plugin runs in execute mode
    _EXECUTE_WARNING = (
        "\n[NETWORK PLUGIN] ⚠️  Execute mode active.\n"
        "Scanning will be performed ONLY against targets in the allowlist.\n"
        "Ensure you have WRITTEN AUTHORIZATION for every target before proceeding.\n"
        "This tool performs inventory scanning only – no exploits, no brute-force.\n"
    )

    def run(self, context: PluginContext) -> RawScanArtifact:
        # ------------------------------------------------------------------
        # Guard: allowlist is mandatory
        # ------------------------------------------------------------------
        if not context.network_allowlist_path:
            return self._make_artifact(
                stderr=(
                    "network: plugin disabled – no --network-allowlist provided.\n"
                    "Network scanning requires an explicit allowlist of authorized targets."
                ),
                exit_code=0,
            )

        # ------------------------------------------------------------------
        # Parse allowlist
        # ------------------------------------------------------------------
        global_cfg = context.global_cfg
        allow_cidr: bool = (
            global_cfg.network.allow_cidr if global_cfg else False
        )

        try:
            targets = parse_allowlist(context.network_allowlist_path, allow_cidr=allow_cidr)
            # Resolved before either mode runs: authorization must be settled
            # before a single packet is sent, not applied to the results after.
            authorized = AuthorizedTargets.resolve(targets)
        except (ValueError, OSError) as exc:
            return self._make_artifact(
                stderr=f"network: allowlist error – {exc}",
                exit_code=2,
            )

        raw_dir = Path(context.output_dir) / "raw" / self.name
        raw_dir.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------
        # Parse-only mode
        # ------------------------------------------------------------------
        if context.network_input_file:
            return self._parse_mode(context, authorized, raw_dir)

        # ------------------------------------------------------------------
        # Execute mode
        # ------------------------------------------------------------------
        return self._execute_mode(context, authorized, raw_dir, global_cfg)

    # ------------------------------------------------------------------
    # Parse-only
    # ------------------------------------------------------------------

    def _parse_mode(
        self,
        context: PluginContext,
        authorized: AuthorizedTargets,
        raw_dir: Path,
    ) -> RawScanArtifact:
        src = Path(context.network_input_file)  # type: ignore[arg-type]
        if not src.exists():
            return self._make_artifact(
                stderr=f"network: --network-input file not found: {context.network_input_file}",
                exit_code=1,
            )

        dest = raw_dir / src.name
        shutil.copy2(src, dest)

        try:
            findings = parse_nmap_xml(str(src))
        except ET.ParseError as exc:
            return self._make_artifact(
                raw_file_path=str(dest),
                stderr=f"network: XML parse error – {exc}",
                exit_code=1,
            )

        # Filter findings to only allowlisted hosts
        findings = _filter_to_allowlist(findings, authorized)

        stdout = json.dumps(findings, indent=2)
        return self._make_artifact(
            raw_file_path=str(dest),
            stdout=stdout,
            exit_code=0,
            extra={"mode": "parse-only", "targets_in_allowlist": authorized.scan_targets},
        )

    # ------------------------------------------------------------------
    # Execute mode
    # ------------------------------------------------------------------

    def _execute_mode(
        self,
        context: PluginContext,
        authorized: AuthorizedTargets,
        raw_dir: Path,
        global_cfg,
    ) -> RawScanArtifact:
        net_cfg = global_cfg.network if global_cfg else None
        binary = (net_cfg.scanner_binary if net_cfg else "nmap")
        flags = list(net_cfg.default_flags if net_cfg else ["-sV", "--open", "-T2"])

        if not shutil.which(binary):
            return self._make_artifact(
                stderr=(
                    f"network: scanner binary '{binary}' not found in PATH.\n"
                    "Install nmap or configure network.scanner_binary in config."
                ),
                exit_code=127,
            )

        output_xml = raw_dir / "nmap_output.xml"
        # Literal addresses and networks only — never a hostname, so the scanner
        # cannot resolve a name to something other than what was authorized.
        cmd = [binary, "-oX", str(output_xml)] + flags + authorized.scan_targets

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute hard cap
            )
        except subprocess.TimeoutExpired:
            return self._make_artifact(
                stderr="network: scanner timed out after 300 seconds",
                exit_code=124,
                duration_seconds=300.0,
            )
        except OSError as exc:
            return self._make_artifact(
                stderr=f"network: failed to launch scanner – {exc}",
                exit_code=1,
            )

        duration = time.monotonic() - start

        if not output_xml.exists():
            return self._make_artifact(
                stdout=proc.stdout,
                stderr=self._EXECUTE_WARNING + proc.stderr,
                exit_code=proc.returncode,
                duration_seconds=duration,
            )

        try:
            findings = parse_nmap_xml(str(output_xml))
        except ET.ParseError as exc:
            return self._make_artifact(
                raw_file_path=str(output_xml),
                stdout=proc.stdout,
                stderr=f"network: XML parse error – {exc}\n" + proc.stderr,
                exit_code=1,
                duration_seconds=duration,
            )

        findings = _filter_to_allowlist(findings, authorized)
        stdout = json.dumps(findings, indent=2)

        return self._make_artifact(
            raw_file_path=str(output_xml),
            stdout=stdout,
            stderr=self._EXECUTE_WARNING + proc.stderr,
            exit_code=proc.returncode,
            duration_seconds=duration,
            extra={"mode": "execute", "targets": authorized.scan_targets, "cmd": cmd},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _filter_to_allowlist(
    findings: List[dict],
    authorized: AuthorizedTargets,
) -> List[dict]:
    """Keep only findings whose host address was authorized.

    Matching is on the address alone, by membership in the authorized networks.
    The previous implementation compared strings and also accepted a match on
    the ``hostname`` field — which, in parse-only mode, comes from the uploaded
    XML, so a crafted file could claim an allowlisted name and smuggle arbitrary
    hosts into the report. Exact string matching also silently discarded every
    result from a CIDR entry, since '10.0.0.5' is never equal to '10.0.0.0/24'.
    """
    return [f for f in findings if authorized.contains(f.get("host", ""))]

