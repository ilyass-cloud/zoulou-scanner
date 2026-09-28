"""Environment detector – scans a repository to identify languages,
frameworks, package managers, container usage, and other characteristics
that inform which scanning tools should be applied.

Returns a structured ``EnvProfile`` that can be serialised to JSON and
fed to the LLM-aided auto-planner.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Set

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class EnvProfile(BaseModel):
    """Detected environment profile for a repository."""
    repo_path: str = ""
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    has_dockerfile: bool = False
    has_docker_compose: bool = False
    has_kubernetes: bool = False
    has_terraform: bool = False
    has_ci_cd: bool = False
    manifest_files: List[str] = Field(default_factory=list)
    iac_files: List[str] = Field(default_factory=list)
    file_count: int = 0
    dir_count: int = 0
    summary: str = ""


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# Extension → language mapping
_EXT_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".scala": "Scala",
    ".r": "R",
    ".pl": "Perl",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".tf": "Terraform/HCL",
    ".hcl": "Terraform/HCL",
}

# Filename → package manager / manifest
_MANIFEST_MAP = {
    "requirements.txt": "pip",
    "setup.py": "pip",
    "setup.cfg": "pip",
    "pyproject.toml": "pip/poetry",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "go.mod": "go modules",
    "go.sum": "go modules",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "composer.json": "composer",
    "composer.lock": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "*.csproj": "nuget",
    "*.sln": "nuget",
    "mix.exs": "mix",
    "pubspec.yaml": "pub",
}

# Filename patterns → framework
_FRAMEWORK_INDICATORS = {
    "manage.py": "Django",
    "wsgi.py": "Django",
    "asgi.py": "Django",
    "app.py": "Flask",
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "nuxt.config.js": "Nuxt.js",
    "angular.json": "Angular",
    "vue.config.js": "Vue.js",
    "svelte.config.js": "Svelte",
    "fastapi": "FastAPI",
    "spring": "Spring",
    "rails": "Ruby on Rails",
    "express": "Express.js",
}

# Directories to skip
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "target", "bin", "obj", ".idea", ".vscode",
}

# Max files to scan (safety limit)
_MAX_FILES = 50_000


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def detect_environment(repo_path: str) -> EnvProfile:
    """Walk the repository and build an environment profile."""
    root = Path(repo_path).resolve()
    if not root.exists():
        return EnvProfile(repo_path=str(root), summary="Repository path does not exist.")

    languages: Set[str] = set()
    frameworks: Set[str] = set()
    pkg_managers: Set[str] = set()
    manifests: List[str] = []
    iac_files: List[str] = []
    has_dockerfile = False
    has_docker_compose = False
    has_k8s = False
    has_terraform = False
    has_ci = False
    file_count = 0
    dir_count = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        dir_count += 1

        rel_dir = Path(dirpath).relative_to(root)

        for fname in filenames:
            file_count += 1
            if file_count > _MAX_FILES:
                break

            fpath = Path(dirpath) / fname
            rel_path = str(rel_dir / fname)
            ext = fpath.suffix.lower()
            name_lower = fname.lower()

            # Language detection
            if ext in _EXT_LANG:
                languages.add(_EXT_LANG[ext])

            # Manifest / package manager detection
            if fname in _MANIFEST_MAP:
                pkg_managers.add(_MANIFEST_MAP[fname])
                manifests.append(rel_path)

            # .csproj / .sln detection
            if ext in (".csproj", ".sln"):
                pkg_managers.add("nuget")
                manifests.append(rel_path)

            # Framework indicators
            if fname in _FRAMEWORK_INDICATORS:
                frameworks.add(_FRAMEWORK_INDICATORS[fname])

            # Docker
            # Dockerfile, Dockerfile.<variant> (Dockerfile.app, Dockerfile.db…)
            # and <name>.dockerfile. Only .dev and .prod were recognised, so a
            # project splitting its images into named variants had none.
            if name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
                has_dockerfile = True
            if name_lower.startswith("docker-compose"):
                has_docker_compose = True
            if ext == ".dockerfile":
                has_dockerfile = True

            # Kubernetes
            if name_lower in ("kustomization.yaml", "kustomization.yml"):
                has_k8s = True
            # Heuristic: YAML files in k8s-like dirs
            if ext in (".yaml", ".yml") and any(
                k in str(rel_dir).lower()
                for k in ("k8s", "kubernetes", "helm", "charts", "deploy")
            ):
                has_k8s = True

            # Terraform / IaC
            if ext in (".tf", ".hcl"):
                has_terraform = True
                iac_files.append(rel_path)

            # CI/CD
            if name_lower in (
                ".github", ".gitlab-ci.yml", "jenkinsfile",
                ".circleci", "azure-pipelines.yml", "bitbucket-pipelines.yml",
            ):
                has_ci = True

        if file_count > _MAX_FILES:
            break

    # Check for CI dirs at root level
    for ci_dir in (".github", ".circleci", ".gitlab"):
        if (root / ci_dir).is_dir():
            has_ci = True

    # Check for framework hints in package.json
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            import json
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for dep_name in all_deps:
                if dep_name == "react":
                    frameworks.add("React")
                elif dep_name == "vue":
                    frameworks.add("Vue.js")
                elif dep_name == "@angular/core":
                    frameworks.add("Angular")
                elif dep_name == "express":
                    frameworks.add("Express.js")
                elif dep_name == "next":
                    frameworks.add("Next.js")
                elif dep_name == "fastify":
                    frameworks.add("Fastify")
                elif dep_name == "svelte":
                    frameworks.add("Svelte")
        except Exception:
            pass

    # Build summary
    parts = []
    if languages:
        parts.append(f"Languages: {', '.join(sorted(languages))}")
    if frameworks:
        parts.append(f"Frameworks: {', '.join(sorted(frameworks))}")
    if pkg_managers:
        parts.append(f"Package managers: {', '.join(sorted(pkg_managers))}")
    if has_dockerfile:
        parts.append("Docker: yes")
    if has_k8s:
        parts.append("Kubernetes: yes")
    if has_terraform:
        parts.append("Terraform/IaC: yes")
    if has_ci:
        parts.append("CI/CD: yes")
    parts.append(f"Files: {file_count}, Dirs: {dir_count}")

    profile = EnvProfile(
        repo_path=str(root),
        languages=sorted(languages),
        frameworks=sorted(frameworks),
        package_managers=sorted(pkg_managers),
        has_dockerfile=has_dockerfile,
        has_docker_compose=has_docker_compose,
        has_kubernetes=has_k8s,
        has_terraform=has_terraform,
        has_ci_cd=has_ci,
        manifest_files=manifests[:50],  # cap for sanity
        iac_files=iac_files[:50],
        file_count=file_count,
        dir_count=dir_count,
        summary=" | ".join(parts),
    )

    log.info("env_detect: %s", profile.summary)
    return profile

