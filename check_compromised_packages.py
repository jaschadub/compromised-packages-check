#!/usr/bin/env python3
"""
check_compromised_packages.py

Scan a repository for known-malicious package versions from recent npm and
PyPI supply-chain incidents (Mini Shai-Hulud / TanStack May 2026, the April
2026 @cap-js / mbt wave, axios DPRK takeover March 2026, @bitwarden/cli
April 2026, node-ipc May 2026, the @antv / atool May 19 mass wave, the
TrapDoor crypto-stealer typosquats from May 22 2026, the 25-package
multi-cluster npm typosquat wave from May 25 2026, intercom-client April 2026,
and related Mistral / Guardrails / durabletask / pytorch-lightning poisonings,
plus the dYdX supply-chain attack January 2026, TeamPCP Trivy-cascade litellm
and telnyx (March 2026), and elementary-data April 2026).

Author:    Jascha Wanger / Tarnover, LLC
Date:      2026-05-26
License:   MIT
Usage:     check_compromised_packages.py [path]   (defaults to cwd)
Exit code: 0 clean, 1 hit(s) found, 2 error
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Known-malicious version data. Update as advisories evolve.
#
# Data model: package name -> set of malicious version strings. An *empty
# set* is the wildcard convention: any installed version of that package is
# treated as malicious. Use it for pure-malware typosquats (where OSV's
# `affected.ranges` is `>=0`) so we still catch republished versions after
# npm/PyPI takedowns leave only a `0.0.1-security` placeholder.
# ---------------------------------------------------------------------------

# PyPI: package name (lowercased) -> set of malicious versions
PYPI_BAD: dict[str, set[str]] = {
    "durabletask": {"1.4.1", "1.4.2", "1.4.3"},
    "mistralai": {"2.4.6"},
    "guardrails-ai": {"0.10.1"},
    # PyTorch Lightning maintainer compromise (April 30 2026)
    # GHSA-w37p-236h-pfx3 / CVE-2026-44484
    "pytorch-lightning": {"2.6.2", "2.6.3"},
    # dYdX supply-chain attack (January 27 2026) — maintainer credential compromise
    # PYSEC-2026-1; Socket + TheHackerNews + Rescana + CyberPress
    "dydx-v4-client": {"1.1.5.post1"},
    # TeamPCP / Trivy CI credential-steal cascade (March 2026)
    # litellm: GHSA-5mg7-485q-xm76 (Datadog, Snyk, Sonatype, Wiz, Endor Labs, Truesec)
    "litellm": {"1.82.7", "1.82.8"},
    # telnyx: GHSA-955r-262c-33jc (Akamai, Help Net Security, Mend, Hexastrike)
    "telnyx": {"4.87.1", "4.87.2"},
    # elementary-data GitHub Actions script-injection (April 24 2026)
    # StepSecurity, Snyk, Bleeping Computer, CyberSecurityNews, Chainguard
    "elementary-data": {"0.23.3"},
    # TrapDoor crypto-stealer campaign (May 22 2026) — fully malicious typosquats
    # OSV MAL-2026-4259, 4260, 4261, 4262, 4271, 4272, 4273
    "cryptowallet-safety": {"0.1.0"},
    "defi-risk-scanner": {"0.1.0"},
    "eth-security-auditor": {"0.1.0"},
    "solidity-build-guard": {"0.1.0"},
    "data-pipeline-check": {"0.1.0", "0.1.1"},
    "env-loader-cli": {"0.1.0", "0.1.1"},
    "git-config-sync": {"0.1.0", "0.1.1"},
}

# npm: exact package name -> set of malicious versions.
# @tanstack/* list per GHSA-g7cv-rxg3-hmpx (TanStack supply-chain compromise).
NPM_BAD: dict[str, set[str]] = {
    "@tanstack/arktype-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/eslint-plugin-router": {"1.161.9", "1.161.12"},
    "@tanstack/eslint-plugin-start": {"0.0.4", "0.0.7"},
    "@tanstack/history": {"1.161.9", "1.161.12"},
    "@tanstack/nitro-v2-vite-plugin": {"1.154.12", "1.154.15"},
    "@tanstack/react-router": {"1.169.5", "1.169.8"},
    "@tanstack/react-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/react-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/react-start": {"1.167.68", "1.167.71"},
    "@tanstack/react-start-client": {"1.166.51", "1.166.54"},
    "@tanstack/react-start-rsc": {"0.0.47", "0.0.50"},
    "@tanstack/react-start-server": {"1.166.55", "1.166.58"},
    "@tanstack/router-cli": {"1.166.46", "1.166.49"},
    "@tanstack/router-core": {"1.169.5", "1.169.8"},
    "@tanstack/router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/router-devtools-core": {"1.167.6", "1.167.9"},
    "@tanstack/router-generator": {"1.166.45", "1.166.48"},
    "@tanstack/router-plugin": {"1.167.38", "1.167.41"},
    "@tanstack/router-ssr-query-core": {"1.168.3", "1.168.6"},
    "@tanstack/router-utils": {"1.161.11", "1.161.14"},
    "@tanstack/router-vite-plugin": {"1.166.53", "1.166.56"},
    "@tanstack/solid-router": {"1.169.5", "1.169.8"},
    "@tanstack/solid-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/solid-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/solid-start": {"1.167.65", "1.167.68"},
    "@tanstack/solid-start-client": {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server": {"1.166.54", "1.166.57"},
    "@tanstack/start-client-core": {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs": {"1.161.9", "1.161.12"},
    "@tanstack/start-plugin-core": {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core": {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context": {"1.166.38", "1.166.41"},
    "@tanstack/valibot-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/virtual-file-routes": {"1.161.10", "1.161.13"},
    "@tanstack/vue-router": {"1.169.5", "1.169.8"},
    "@tanstack/vue-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/vue-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/vue-start": {"1.167.61", "1.167.64"},
    "@tanstack/vue-start-client": {"1.166.46", "1.166.49"},
    "@tanstack/vue-start-server": {"1.166.50", "1.166.53"},
    "@tanstack/zod-adapter": {"1.166.12", "1.166.15"},
    # April 2026 @cap-js / mbt wave
    "@cap-js/sqlite": {"2.2.2"},
    "@cap-js/postgres": {"2.2.2"},
    "@cap-js/db-service": {"2.10.1"},
    "mbt": {"1.2.48"},
    # @mistralai (May 2026 wave)
    # Caveat: per Corgea research, the @mistralai/* and @uipath/* payloads
    # contain a bug that renders the malware non-functional. These versions
    # should still be treated as compromised (remove and rotate credentials),
    # but the realised impact differs from the working @tanstack/* payloads.
    "@mistralai/mistralai": {"2.2.2", "2.2.3", "2.2.4"},
    "@mistralai/mistralai-gcp": {"1.7.1", "1.7.2", "1.7.3"},
    "@mistralai/mistralai-azure": {"1.7.1", "1.7.2", "1.7.3"},
    # @opensearch-project (May 2026 wave)
    "@opensearch-project/opensearch": {"3.5.3", "3.6.2", "3.7.0", "3.8.0"},
    # @uipath (May 2026 wave, 66 packages)
    "@uipath/access-policy-sdk": {"0.3.1"},
    "@uipath/access-policy-tool": {"0.3.1"},
    "@uipath/admin-tool": {"0.1.1"},
    "@uipath/agent-sdk": {"1.0.2"},
    "@uipath/agent-tool": {"1.0.1"},
    "@uipath/agent.sdk": {"0.0.18"},
    "@uipath/aops-policy-tool": {"0.3.1"},
    "@uipath/ap-chat": {"1.5.7"},
    "@uipath/api-workflow-tool": {"1.0.1"},
    "@uipath/apollo-core": {"5.9.2"},
    "@uipath/apollo-react": {"4.24.5"},
    "@uipath/apollo-wind": {"2.16.2"},
    "@uipath/auth": {"1.0.1"},
    "@uipath/case-tool": {"1.0.1"},
    "@uipath/cli": {"1.0.1"},
    "@uipath/codedagent-tool": {"1.0.1"},
    "@uipath/codedagents-tool": {"0.1.12"},
    "@uipath/codedapp-tool": {"1.0.1"},
    "@uipath/common": {"1.0.1"},
    "@uipath/context-grounding-tool": {"0.1.1"},
    "@uipath/data-fabric-tool": {"1.0.2"},
    "@uipath/docsai-tool": {"1.0.1"},
    "@uipath/filesystem": {"1.0.1"},
    "@uipath/flow-tool": {"1.0.2"},
    "@uipath/functions-tool": {"1.0.1"},
    "@uipath/gov-tool": {"0.3.1"},
    "@uipath/identity-tool": {"0.1.1"},
    "@uipath/insights-sdk": {"1.0.1"},
    "@uipath/insights-tool": {"1.0.1"},
    "@uipath/integrationservice-sdk": {"1.0.2"},
    "@uipath/integrationservice-tool": {"1.0.2"},
    "@uipath/llmgw-tool": {"1.0.1"},
    "@uipath/maestro-sdk": {"1.0.1"},
    "@uipath/maestro-tool": {"1.0.1"},
    "@uipath/orchestrator-tool": {"1.0.1"},
    "@uipath/packager-tool-apiworkflow": {"0.0.19"},
    "@uipath/packager-tool-bpmn": {"0.0.9"},
    "@uipath/packager-tool-case": {"0.0.9"},
    "@uipath/packager-tool-connector": {"0.0.19"},
    "@uipath/packager-tool-flow": {"0.0.19"},
    "@uipath/packager-tool-functions": {"0.1.1"},
    "@uipath/packager-tool-webapp": {"1.0.6"},
    "@uipath/packager-tool-workflowcompiler": {"0.0.16"},
    "@uipath/packager-tool-workflowcompiler-browser": {"0.0.34"},
    "@uipath/platform-tool": {"1.0.1"},
    "@uipath/project-packager": {"1.1.16"},
    "@uipath/resource-tool": {"1.0.1"},
    "@uipath/resourcecatalog-tool": {"0.1.1"},
    "@uipath/resources-tool": {"0.1.11"},
    "@uipath/robot": {"1.3.4"},
    "@uipath/rpa-legacy-tool": {"1.0.1"},
    "@uipath/rpa-tool": {"0.9.5"},
    "@uipath/solution-packager": {"0.0.35"},
    "@uipath/solution-tool": {"1.0.1"},
    "@uipath/solutionpackager-sdk": {"1.0.11"},
    "@uipath/solutionpackager-tool-core": {"0.0.34"},
    "@uipath/tasks-tool": {"1.0.1"},
    "@uipath/telemetry": {"0.0.7"},
    "@uipath/test-manager-tool": {"1.0.2"},
    "@uipath/tool-workflowcompiler": {"0.0.12"},
    "@uipath/traces-tool": {"1.0.1"},
    "@uipath/ui-widgets-multi-file-upload": {"1.0.1"},
    "@uipath/uipath-python-bridge": {"1.0.1"},
    "@uipath/vertical-solutions-tool": {"1.0.1"},
    "@uipath/vss": {"0.1.6"},
    "@uipath/widget.sdk": {"1.2.3"},
    # dYdX supply-chain attack (January 27 2026) — maintainer credential compromise
    # Socket + TheHackerNews + Rescana + CyberPress agree on all four versions
    "@dydxprotocol/v4-client-js": {"3.4.1", "1.22.1", "1.15.2", "1.0.31"},
    # axios maintainer-account takeover (March 31 2026) — Sapphire Sleet / DPRK
    # OSV MAL-2026-2307 / GHSA-fw8c-xr5c-95f9 (axios)
    # OSV MAL-2026-2306 / GHSA-2x9r-6wxq-hrr7 (plain-crypto-js phantom dep)
    "axios": {"0.30.4", "1.14.1"},
    "plain-crypto-js": {"4.2.0", "4.2.1"},
    # @bitwarden/cli typosquat (April 22 2026) — TeamPCP / Checkmarx breach
    # OSV MAL-2026-3020 / GHSA-g98r-qjhg-4fmr
    "@bitwarden/cli": {"2026.4.0"},
    # node-ipc maintainer-account takeover (May 14 2026)
    # OSV MAL-2026-3744 / GHSA-g7cv-rxg3-hmpx / CVE-2026-45321
    "node-ipc": {"9.1.6", "9.2.3", "12.0.1"},
    # Additional Mini Shai-Hulud packages (May 2026 wave)
    # OSV MAL-2026-3448, MAL-2026-3456, MAL-2026-3444, MAL-2026-3515, MAL-2026-3458
    "@squawk/mcp": {"0.9.1", "0.9.2", "0.9.3", "0.9.4", "0.9.5"},
    "@squawk/weather": {"0.5.6", "0.5.7", "0.5.8", "0.5.9", "0.5.10"},
    "@squawk/flightplan": {"0.5.2", "0.5.3", "0.5.4", "0.5.5", "0.5.6"},
    "@tallyui/connector-medusa": {"1.0.1", "1.0.2", "1.0.3"},
    "@tallyui/connector-vendure": {"1.0.1", "1.0.2", "1.0.3"},
    # intercom-client maintainer-credential compromise (April 30 2026) — Shai-Hulud campaign
    # GHSA-54pg-9963-v8vg; confirmed by StepSecurity, Socket, Netskope, OX Security, Upwind
    "intercom-client": {"7.0.4"},
    # @antv / atool mass wave (May 19 2026) — 317 npm packages, 631 versions
    # Per safedep.io and ossf/malicious-packages. High-impact subset only;
    # the rest of the @antv/ scope is covered by NPM_SUSPECT_SCOPES below.
    # OSV MAL-2026-3973, MAL-2026-3982, MAL-2026-4033, MAL-2026-4077,
    # MAL-2026-3839, MAL-2026-4083, MAL-2026-4153, MAL-2026-4132, MAL-2026-4156
    "@antv/g2": {"5.5.8", "5.6.8"},
    "@antv/g6": {"5.2.1", "5.3.1"},
    "@antv/l7": {"2.26.10", "2.27.10"},
    "@antv/s2": {"2.8.1", "2.9.1"},
    "@antv/x6": {"3.2.7", "3.3.7"},
    "@antv/scale": {"0.6.2", "0.7.2"},
    "size-sensor": {"1.0.4", "1.1.4", "1.2.4"},
    "echarts-for-react": {"3.0.7", "3.1.7", "3.2.7"},
    "timeago.js": {"4.1.2", "4.2.2"},
    # TrapDoor crypto-stealer campaign (May 22 2026) — pure-malware typosquats
    # OSV records flag the entire package (`affected.ranges` is `>=0`); use
    # the empty-set wildcard so we catch any republished versions.
    # OSV MAL-2026-4202..4208, 4218..4220, 4250, 4275..4284
    "async-pipeline-builder": set(),
    "build-scripts-utils": set(),
    "chain-key-validator": set(),
    "crypto-credential-scanner": set(),
    "defi-env-auditor": set(),
    "defi-threat-scanner": set(),
    "deployment-key-auditor": set(),
    "dev-env-bootstrapper": set(),
    "eth-wallet-sentinel": set(),
    "llm-context-compressor": set(),
    "mnemonic-safety-check": set(),
    "model-switch-router": set(),
    "node-setup-helpers": set(),
    "project-init-tools": set(),
    "prompt-engineering-toolkit": set(),
    "solidity-deploy-guard": set(),
    "token-usage-tracker": set(),
    "wallet-backup-verifier": set(),
    "wallet-security-checker": set(),
    "web3-secrets-detector": set(),
    "workspace-config-loader": set(),
    # Multi-cluster npm typosquat wave (May 25 2026) — 25 packages, all fully malicious.
    # GitHub Advisory Database confirmed affected.ranges >=0 for every entry; use the
    # empty-set wildcard. The batch breaks into five sub-clusters published the same day:
    #   ts-* family:        GHSA-jp5r-76w9-2rvh, GHSA-66j8-7w8q-vvf5, GHSA-xqpr-hv2v-6pfj,
    #                       GHSA-qgfv-9wmq-m4f7, GHSA-f6hr-rvf9-ch6p, GHSA-vxrv-934h-xj6q
    #   @gbrlxvii/* scope:  GHSA-pvrm-mpcj-2mcp, GHSA-362c-qm74-42gg, GHSA-59j3-wvx3-w9hx
    #   auth0-* cluster:    GHSA-4xqv-4874-rxx6, GHSA-g8jx-g4j9-hh3w, GHSA-cwjp-2mq2-6xp6,
    #                       GHSA-xm89-4mqj-hfrq, GHSA-c8ph-73mc-f5p8, GHSA-jfp3-8vwj-7g9v
    #   webservices.rest*:  GHSA-2qjx-pgq9-vx24, GHSA-v62r-4vqp-f32g
    #   vite-plugin-env-*:  GHSA-7v58-43rg-wjwq, GHSA-2rh6-x7fc-2fr4
    #   miscellaneous:      GHSA-fc78-r45j-m7f5, GHSA-6pxr-857g-mr97, GHSA-qcrh-87jf-mm39,
    #                       GHSA-w6gc-fhv9-53hq, GHSA-rj44-v8w3-c5q5, GHSA-gqvh-j8hx-425w
    "ts-stream-compose": set(),
    "ts-result-pipe": set(),
    "ts-typeguard-utils": set(),
    "ts-config-mapper": set(),
    "ts-iter-utils": set(),
    "ts-schema-config": set(),
    "@gbrlxvii/ts-project-lint": set(),
    "@gbrlxvii/ts-form-utils": set(),
    "@gbrlxvii/ts-env-validator": set(),
    "auth0-aspnetcore-utils": set(),
    "auth0-internal-collector": set(),
    "auth0-android-helper-utils": set(),
    "auth0-net-sdk-utils": set(),
    "auth0-sample-dus-utils": set(),
    "auth0-common-telemetry": set(),
    "webservices.rest": set(),
    "webservices.rest-utils": set(),
    "vite-plugin-env-compat-1.5": set(),
    "vite-plugin-env-compat-plus": set(),
    "fivem-monitor": set(),
    "jules-standard": set(),
    "internallib_v95": set(),
    "chai-as-redeploy": set(),
    "expo-config-plugin-typescript": set(),
    "unique-string-64": set(),
}

# npm scopes hit in this campaign. Exact versions are pinned above; any
# additional package in these scopes still triggers a manual-review warning
# in case the advisory expands.
NPM_SUSPECT_SCOPES = ("@mistralai/", "@uipath/", "@opensearch-project/", "@antv/")

SKIP_DIRS = {"node_modules", ".venv", "venv", ".git",
             "dist", "build", "__pycache__", ".tox", ".mypy_cache"}

PYPI_FILENAMES = {"Pipfile", "Pipfile.lock", "poetry.lock",
                  "pyproject.toml", "setup.py"}
NPM_FILENAMES = {"package.json", "package-lock.json",
                 "yarn.lock", "pnpm-lock.yaml"}

REQ_TXT_RE = re.compile(r"^requirements.*\.txt$")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_requirements_txt(path: Path) -> Iterable[tuple[str, str | None]]:
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*={2,3}\s*([A-Za-z0-9_.\-+]+)", line)
        if m:
            yield m.group(1).lower(), m.group(2)
        else:
            m = re.match(r"([A-Za-z0-9_.\-]+)", line)
            if m:
                yield m.group(1).lower(), None


def parse_pyproject_toml(path: Path) -> Iterable[tuple[str, str | None]]:
    text = path.read_text(errors="ignore")
    # poetry-style:  pkg = "==1.2.3"  or  pkg = "1.2.3"
    for m in re.finditer(
        r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"={0,2}\s*([A-Za-z0-9_.\-+]+)"',
        text, re.MULTILINE,
    ):
        yield m.group(1).lower(), m.group(2)
    # PEP 621 dependency strings:  "pkg==1.2.3"
    for m in re.finditer(
        r'"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)"',
        text,
    ):
        yield m.group(1).lower(), m.group(2)


def parse_package_json(path: Path) -> Iterable[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return
    for section in ("dependencies", "devDependencies",
                    "peerDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            # Strip leading range operators; bare version stays intact.
            ver = re.sub(r"^[\^~>=<]*\s*", "", str(spec)).strip()
            ver = ver.split(" ")[0]
            yield name, ver


def parse_package_lock(path: Path) -> Iterable[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return
    # npm v2/v3 lockfile: flat "packages" map keyed by node_modules path.
    for key, entry in (data.get("packages") or {}).items():
        if not key:
            continue
        idx = key.rfind("node_modules/")
        if idx == -1:
            continue
        name = key[idx + len("node_modules/"):]
        version = entry.get("version")
        if name and version:
            yield name, version
    # npm v1 fallback.
    def walk(deps):
        for name, entry in (deps or {}).items():
            v = entry.get("version")
            if v:
                yield name, v
            yield from walk(entry.get("dependencies"))
    yield from walk(data.get("dependencies"))


YARN_BLOCK_RE = re.compile(
    r'^"?((?:@[^/\s"]+/)?[^@\s",]+)@[^\n]*?:\n'
    r'(?:[^\n]*\n)*?\s+version\s+"([^"]+)"',
    re.MULTILINE,
)


def parse_yarn_lock(path: Path) -> Iterable[tuple[str, str]]:
    for m in YARN_BLOCK_RE.finditer(path.read_text(errors="ignore")):
        yield m.group(1), m.group(2)


PNPM_ENTRY_RE = re.compile(
    r"(?:^|\s)'?/?((?:@[^/@\s']+/)?[A-Za-z0-9._\-]+)@(\d[^\s'():]*)"
)


def parse_pnpm_lock(path: Path) -> Iterable[tuple[str, str]]:
    for m in PNPM_ENTRY_RE.finditer(path.read_text(errors="ignore")):
        yield m.group(1), m.group(2)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def find_manifests(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        name = path.name
        if name in PYPI_FILENAMES or name in NPM_FILENAMES or REQ_TXT_RE.match(name):
            out.append(path)
    return out


def parse_manifest(path: Path) -> tuple[list[tuple[str, str | None]], bool]:
    """Return (pairs, is_npm) for the given manifest path."""
    name = path.name
    if name == "package.json":
        return list(parse_package_json(path)), True
    if name == "package-lock.json":
        return list(parse_package_lock(path)), True
    if name == "yarn.lock":
        return list(parse_yarn_lock(path)), True
    if name == "pnpm-lock.yaml":
        return list(parse_pnpm_lock(path)), True
    if name == "pyproject.toml":
        return list(parse_pyproject_toml(path)), False
    if name in {"Pipfile", "Pipfile.lock", "poetry.lock", "setup.py"} or REQ_TXT_RE.match(name):
        return list(parse_requirements_txt(path)), False
    return [], False


def scan(root: Path):
    hits: list[tuple[Path, str, str, str]] = []
    suspects: list[tuple[Path, str, str, str]] = []

    for path in find_manifests(root):
        try:
            pairs, is_npm = parse_manifest(path)
        except Exception as exc:
            print(f"warn: failed to parse {path}: {exc}", file=sys.stderr)
            continue

        for pkg, version in pairs:
            if is_npm:
                bad = NPM_BAD.get(pkg)
                # Empty set is the wildcard: any version of this package is
                # malicious (pure-malware typosquats; see PYPI_BAD docstring).
                if bad is not None and (not bad or version in bad):
                    hits.append((path, pkg, version or "?", "npm"))
                elif any(pkg.startswith(s) for s in NPM_SUSPECT_SCOPES):
                    suspects.append((path, pkg, version or "?", "npm-scope"))
            else:
                bad = PYPI_BAD.get(pkg.lower())
                if bad is not None and (not bad or (version and version in bad)):
                    hits.append((path, pkg, version or "?", "pypi"))

    return hits, suspects


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a repo for known-malicious npm/PyPI package versions.",
        epilog="Author: Jascha Wanger / Tarnover, LLC",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="repo root to scan (default: current dir)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    hits, suspects = scan(root)

    if hits:
        print(f"FOUND {len(hits)} MALICIOUS PACKAGE VERSION(S):")
        for path, pkg, ver, eco in hits:
            print(f"  [{eco}] {pkg}@{ver}  ({path.relative_to(root)})")

    if suspects:
        if hits:
            print()
        print(f"{len(suspects)} package(s) in advisory-affected scopes "
              "(verify versions manually):")
        # Dedupe by (pkg, version, file).
        seen = set()
        for path, pkg, ver, _ in suspects:
            key = (str(path), pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {pkg}@{ver}  ({path.relative_to(root)})")

    if not hits and not suspects:
        print("No known-malicious packages detected.")

    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
