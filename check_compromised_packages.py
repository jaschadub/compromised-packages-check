#!/usr/bin/env python3
"""
check_compromised_packages.py

Scan a repository for known-malicious package versions from recent npm,
PyPI, and crates.io supply-chain incidents (Mini Shai-Hulud / TanStack
May 2026, the April 2026 @cap-js / mbt wave, axios DPRK takeover March
2026, @bitwarden/cli April 2026, node-ipc May 2026, the @antv / atool
May 19 mass wave, the TrapDoor crypto-stealer typosquats from May 22
2026, the 25-package multi-cluster npm typosquat wave from May 25 2026,
the toskypi npm RAT/infostealer campaign May 25 2026, the CLOB IPFS
dropper campaign May 26 2026, the DPRK js-logger-pack / terminal-logger
npm stealer cluster April–May 2026, the leaked Shai-Hulud
deadcode09284814 npm infostealer/DDoS cluster May 26 2026, the TrapDoor
crates.io Sui/Move build.rs dropper cluster May 2026, intercom-client
April 2026, the dYdX supply-chain attack January 2026, TeamPCP
Trivy-cascade litellm and telnyx March 2026, elementary-data April 2026,
the Polymarket / Mysten / timeapi crates.io campaigns, the 2023 amaperf
crates typosquat cluster, the Nx build-system supply-chain compromise
May 27 2026, the @limebike dependency-confusion campaign May 27 2026,
the @tailwind-core Tailwind typosquat cluster May 27 2026, the
fastapi / strawberry-graphql PyPI poisonings May 27 2026, the
CanisterSprawl TeamPCP npm worm / Namastex Labs packages April 2026,
the @velora-dex/sdk registry-only macOS backdoor April 2026, the DevTap
user0001 typosquat cluster April–May 2026, the xinference PyPI TeamPCP
compromise April 2026, the Baileys/WhatsApp bot malware campaign May 27
2026, the @onerjs BabylonJS typosquat cluster May 27 2026, the Claude
Code/openclaw impersonation cluster May 27 2026, the local-mcp/lokal-mcp
MCP malware campaign May 27 2026, the dependency-confusion 99.x batch May
27 2026, bulk OSV-disclosed npm/PyPI malware May 27 2026, and related
Mistral / Guardrails / durabletask / pytorch-lightning poisonings, the
May 26 2026 17-package pure-malware batch covering Web3/DeFi, JSON-utility,
Solidity/Hardhat, and document-library typosquats, the September 8 2025
Qix phishing attack on the chalk/debug/color/ansi npm ecosystem (19
packages, >2B weekly downloads, crypto-wallet interceptor), and the
September 15 2025 Shai-Hulud worm wave via @ctrl/tinycolor and
ngx-bootstrap account takeovers, and the Moika Tech out-of-band dependency
confusion campaign May 28 2026 (five private scopes, 164 npm packages:
@car-loans, @cloudplatform-single-spa, @debit-ib, @fb-deposit, @mlspace)).

Author:    Jascha Wanger / Tarnover, LLC
Date:      2026-05-28
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
    # xinference maintainer-account compromise (April 22 2026) — 600k-download PyPI AI-inference framework
    # Three consecutive malicious versions published after account takeover; heavily obfuscated
    # base64 payload steals AWS/GCP/K8s/SSH/env credentials on import.
    # JFrog research.jfrog.com/post/xinference-compromise/
    # Mend.io mend.io/blog/malicious-xinference-pypi-teampcp-part-4/
    # OX Security ox.security/blog/xinference-allegedly-hacked-by-teampcp-malicious-package-in-pypi/
    "xinference": {"2.6.0", "2.6.1", "2.6.2"},
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
    # fastapi maintainer-account compromise (May 27 2026)
    # A single malicious version of the ubiquitous Python web framework
    # (400M+ monthly PyPI downloads). Specific version only; do not wildcard.
    # OSV MAL-2026-4750.
    "fastapi": {"0.136.3"},
    # strawberry-graphql compromise (May 27 2026)
    # Malicious version of the popular Python GraphQL library.
    # OSV MAL-2026-4771.
    "strawberry-graphql": {"0.315.6"},
    # notebook-intelligence compromise (May 27 2026)
    # Malicious versions of the Jupyter AI assistant extension.
    # OSV MAL-2026-4759.
    "notebook-intelligence": {"5.0.0a1", "5.0.0", "5.0.1"},
    # libhmac crypto-stealer typosquat (May 26 2026)
    # Impersonates a legitimate HMAC library; exfiltrates credentials.
    # OSV MAL-2026-4194.
    "libhmac": {"0.3.0", "0.8.28.0", "0.8.28.1", "1.1.0"},
    # TrapDoor crypto-stealer campaign (May 22 2026) — fully malicious typosquats
    # OSV MAL-2026-4259, 4260, 4261, 4262, 4271, 4272, 4273
    "cryptowallet-safety": {"0.1.0"},
    "defi-risk-scanner": {"0.1.0"},
    "eth-security-auditor": {"0.1.0"},
    "solidity-build-guard": {"0.1.0"},
    "data-pipeline-check": {"0.1.0", "0.1.1"},
    "env-loader-cli": {"0.1.0", "0.1.1"},
    "git-config-sync": {"0.1.0", "0.1.1"},
    # Various PyPI malware — May 27 2026 bulk OSV disclosures
    # All entries confirmed by individual OSV MAL-2026-* records; versions
    # as recorded in affected.versions (no >=0 ranges → exact-version pins).
    # qontract-reconcile is a legitimate Red Hat/AppSRE reconciliation tool;
    # only the four dev-build versions listed are malicious.
    # MAL-2026-4747 (edison-tools), MAL-2026-4754 (heims), MAL-2026-4761 (openirf),
    # MAL-2026-4762 (pgrayy-wasmtime), MAL-2026-4763 (pulumi-vcd),
    # MAL-2026-4765 (qontract-reconcile), MAL-2026-4786 (ranno),
    # MAL-2026-4794 (indextts-cli), MAL-2026-4795 (massive),
    # MAL-2026-4813 (noteparse), MAL-2026-4824 (cdktn-provider-datadog),
    # MAL-2026-4825 (cdktn-provider-newrelic), MAL-2026-4829 (quatres)
    "cdktn-provider-datadog": {"15.1.1"},
    "cdktn-provider-newrelic": {"15.0.5"},
    "edison-tools": {"0.1.13", "0.1.15", "0.1.16", "0.1.17", "0.1.22"},
    "heims": {"1.1.16"},
    "indextts-cli": {"0.1.1", "0.1.3", "0.1.4", "0.1.5"},
    "massive": {"2.8.0"},
    "noteparse": {"1.1.27"},
    "openirf": {"0.1.4a1"},
    "pgrayy-wasmtime": {"0.0.0", "44.0.3"},
    "pulumi-vcd": {"3.0.0a1779455998", "3.0.0a1779710724"},
    "qontract-reconcile": {
        "0.10.2.dev649", "0.10.2.dev653", "0.10.2.dev658", "0.10.2.dev663",
    },
    "quatres": {"3.0.1"},
    "ranno": {"0.3.0"},
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
    "@tanstack/solid-router-devtools": {"1.166.16", "1.166.19", "1.167.0"},
    "@tanstack/solid-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/solid-start": {"1.167.65", "1.167.68"},
    "@tanstack/solid-start-client": {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server": {"1.166.54", "1.166.57"},
    "@tanstack/start-client-core": {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs": {"1.161.9", "1.161.12"},
    "@tanstack/start-plugin-core": {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core": {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context": {"1.166.38", "1.166.41", "1.167.4"},
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
    # September 8 2025 Qix phishing attack — chalk / debug / color ecosystem
    # A single npm maintainer (Qix-) was phished via a fake npmjs.help 2FA-reset
    # email; attacker published malicious versions of 19 widely-used packages
    # within 16 minutes of account takeover. Malicious code is a browser-based
    # interceptor that silently rewrites crypto-wallet addresses in fetch/XHR
    # and window.ethereum payloads. Versions were live for ~2.5 hours before
    # the maintainer revoked access and re-published clean versions.
    # Collectively these packages see >2 billion weekly npm downloads.
    # Each entry has an individual GHSA/CVE record; versions confirmed as exact
    # pins by maintainer postmortems and multiple independent vendor writeups
    # (StepSecurity, Upwind, Wiz, Bleeping Computer, Checkmarx, OX Security).
    "chalk": {"5.6.1"},            # GHSA-2v46-p5h4-248w
    "debug": {"4.4.2"},            # GHSA-4x49-vf9v-38px / CVE-2025-59144
    "color": {"5.0.1"},            # GHSA-qrmh-qg46-72pp / CVE-2025-59143
    "color-name": {"2.0.1"},       # GHSA-5fvm-p68v-5wmh / CVE-2025-59145
    "color-convert": {"3.1.1"},    # GHSA-pxx3-g568-hxr4 / CVE-2025-59162
    "color-string": {"2.1.1"},     # GHSA-286p-vc9p-p5qv
    "error-ex": {"1.3.3"},         # GHSA-6jp5-hh4c-8c5h / CVE-2025-59330
    "ansi-regex": {"6.2.1"},       # GHSA-jvhh-2m83-6w29
    "strip-ansi": {"7.1.1"},       # GHSA-vfjc-p7x3-q864
    "ansi-styles": {"6.2.2"},      # GHSA-p5rr-crjh-x7gr
    "wrap-ansi": {"9.0.1"},        # GHSA-2rv4-jp6r-xgq7
    "backslash": {"0.2.1"},        # GHSA-53mq-f4w3-f7qv
    "is-arrayish": {"0.3.3"},      # GHSA-frh7-2f84-v9mw / CVE-2025-59331
    "simple-swizzle": {"0.2.3"},   # GHSA-9g9j-rggx-7fmg / CVE-2025-59141
    "supports-color": {"10.2.1"},  # GHSA-pj3j-3w3f-j752
    "slice-ansi": {"7.1.1"},       # GHSA-9xjj-cmqc-578p
    # StepSecurity + Bleeping Computer + Checkmarx + OX Security all confirm
    # the same version list for has-ansi, chalk-template, and supports-hyperlinks:
    "has-ansi": {"6.0.1"},
    "chalk-template": {"1.1.1"},
    "supports-hyperlinks": {"4.1.1"},
    # September 15 2025 Shai-Hulud worm — @ctrl/tinycolor and ngx-bootstrap wave
    # A separate account takeover (different maintainer) using an identical
    # postinstall bundle.js that harvests npm/GitHub tokens and cloud credentials,
    # then self-propagates by republishing infected versions using stolen credentials.
    # The campaign ultimately spread to 194 packages (582 compromised versions),
    # though only the original entry points are pinned here.
    # @ctrl/tinycolor: OSV MAL-2025-47141; Snyk + Endor Labs (independent sources)
    # ngx-bootstrap: GHSA-6m4g-vm7c-f8w6 / OSV MAL-2025-47197;
    #               Snyk blog + valor-software/ngx-bootstrap#6776 (maintainer issue)
    "@ctrl/tinycolor": {"4.1.1", "4.1.2"},
    "ngx-bootstrap": {"18.1.4", "19.0.3", "19.0.4",
                       "20.0.3", "20.0.4", "20.0.5", "20.0.6"},
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
    # CanisterSprawl / TeamPCP npm self-propagating worm (April 8–22 2026)
    # Self-spreading credential stealer using ICP-canister exfiltration; compromised Namastex Labs
    # developer tools. Postinstall hook harvests cloud creds, SSH keys, npm tokens, then republishes
    # infected versions using stolen tokens. Covers @fairwords scope (April 8) and Namastex packages
    # (April 21–22). All version ranges confirmed by two+ independent vendors.
    # pgserve: StepSecurity stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials
    #          Socket socket.dev/blog/namastex-npm-packages-compromised-canisterworm
    #          Maintainer issue github.com/namastexlabs/pgserve/issues/25
    # @automagik/genie: Socket; THN thehackernews.com/2026/04/self-propagating-supply-chain-worm.html
    #                   InfoWorld infoworld.com/article/4162198/malicious-pgserve-automagik-developer-tools-found-in-npm-registry.html
    # @fairwords/*: SafeDep safedep.io/malicious-fairwords-npm-credential-worm/; Socket (same campaign)
    # @openwebconcept/*: Socket (same campaign); THN; The Register
    "pgserve": {"1.1.11", "1.1.12", "1.1.13"},
    "@automagik/genie": {
        "4.260421.33", "4.260421.34", "4.260421.35", "4.260421.36",
        "4.260421.37", "4.260421.38", "4.260421.39", "4.260421.40",
    },
    "@fairwords/websocket": {"1.0.38", "1.0.39"},
    "@fairwords/loopback-connector-es": {"1.4.3", "1.4.4"},
    "@openwebconcept/theme-owc": {"1.0.1", "1.0.2", "1.0.3"},
    "@openwebconcept/design-tokens": {"1.0.1", "1.0.2", "1.0.3"},
    # @velora-dex/sdk registry-only supply-chain compromise (April 7 2026)
    # Malicious build published directly to npm without matching GitHub commit; injects a Go RAT
    # (minirat) + macOS launchctl persistence into dist/index.js on import (no postinstall hook).
    # Legitimate SDK; pin to <=9.4.0 and rotate all credentials.
    # StepSecurity stepsecurity.io/blog/velora-dex-sdk-compromised-on-npm-malicious-version-drops-macos-backdoor-via-launchctl-persistence
    # SafeDep safedep.io/malicious-velora-dex-sdk-npm-compromised-rat/
    "@velora-dex/sdk": {"9.4.1"},
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
    # toskypi npm RAT/infostealer campaign (May 25 2026)
    # Multi-platform infostealer + RAT disguised as terminal/logger utilities.
    # Postinstall hook establishes persistence on Windows/macOS/Linux;
    # steals crypto wallets, browsers, SSH keys, cloud creds. Second-stage
    # payload fetched from HuggingFace repo; C2: ws://195.201.194.107:8010.
    # OSV MAL-2026-4345 (eo-terminal), MAL-2026-4346 (logger-draft)
    # ossf/malicious-packages PR #1270 (merged 2026-05-26); SafeDep discovery
    "eo-terminal": set(),
    "logger-draft": set(),
    # CLOB IPFS dropper campaign (May 26 2026)
    # Four typosquats targeting DeFi / Central-Limit-Order-Book API developers.
    # Postinstall hook fetches a Windows executable via IPFS CID, installs it
    # with registry persistence, and beacons to C2 at 45.8.22.112:2026.
    # OSV MAL-2026-4347 (@devcarron/clob), MAL-2026-4348 (api-rs-node),
    # MAL-2026-4349 (clob.api), MAL-2026-4350 (clobprice.api)
    # ossf/malicious-packages PR #1271 (merged 2026-05-26); SafeDep discovery
    "@devcarron/clob": set(),
    "api-rs-node": set(),
    "clob.api": set(),
    "clobprice.api": set(),
    # DPRK-linked js-logger-pack / terminal-logger-utils cluster (April–May 2026)
    # js-logger-pack: fake npm logger with 23 malicious versions (2026-04-01 to
    # 2026-04-15); downloads MicrosoftSystem64 binary from HuggingFace Lordplay/
    # system-releases and exfiltrates via WebSocket; OSV MAL-2026-2827.
    # terminal-logger-utils: multi-stage dropper + RAT targeting Telegram sessions,
    # SSH keys, crypto wallets, cloud credentials; postinstall hook, HuggingFace
    # second-stage; three dependent packages trigger it on install.
    # Sources: OSV MAL-2026-2827; JFrog research.jfrog.com/post/hugging-face-exfil/;
    #          OX Security ox.security/blog/north-korean-npm-infostealer-rat/;
    #          SafeDep safedep.io/malicious-js-logger-pack-npm-stealer/;
    #          CybersecurityNews cybersecuritynews.com/malicious-npm-package-turns-hugging-face/
    "js-logger-pack": set(),
    "terminal-logger-utils": set(),
    "pretty-logger-utils": set(),
    "ts-logger-pack": set(),
    "pinno-loggers": set(),
    # DevTap user0001 typosquat cluster (April–May 2026) — six pure-malware packages
    # Single throwaway publisher (user0001 / tanvisoul9@gmail.com); all six share identical
    # postinstall payloads. Payloads include: SSH-key backdoor via Supabase bucket, Windows
    # HKCU persistence + Node.js RAT with microphone/screenshot/browser-history theft,
    # and full remote-access shell. OSV confirmed affected.ranges >=0 for all; use empty-set
    # wildcard.
    # SafeDep (per-package blogs: safedep.io/malicious-npm-node-env-resolve-rat/,
    #          safedep.io/malicious-dom-utils-lite-npm-ssh-backdoor/)
    # Xygeni xygeni.io/blog/devtap-npm-typosquatting-attack-2/ (covers all six packages)
    "centralogger": set(),
    "connector-agent": set(),
    "dom-utils-lite": set(),
    "node-env-resolve": set(),
    "node-fetch-lite": set(),
    "node-gyp-runtime": set(),
    # Leaked Shai-Hulud / deadcode09284814 npm cluster (May 26 2026)
    # Four packages published by npm user deadcode09284814 containing different
    # payloads: chalk-tempalte carries a working Shai-Hulud worm clone with its
    # own C2; axois-utils delivers Phantom Bot (Golang DDoS botnet with HTTP/TCP/
    # UDP flood and persistence on Windows + Linux); @deadcode09284814/axios-util
    # and color-style-utils siphon SSH keys, env vars, cloud credentials, and
    # crypto wallet data. "Any version" confirmed for all four.
    # Sources: Bleeping Computer bleepingcomputer.com/news/security/leaked-shai-hulud-malware-fuels-new-npm-infostealer-campaign/ (2026-05-26);
    #          OX Security ox.security/blog/new-actors-deploy-shai-hulud-clones-teampcp-copycats-are-here/;
    #          SecurityWeek securityweek.com/first-shai-hulud-worm-clones-emerge/;
    #          The Hacker News thehackernews.com/2026/05/four-malicious-npm-packages-deliver.html
    "chalk-tempalte": set(),
    "@deadcode09284814/axios-util": set(),
    "axois-utils": set(),
    "color-style-utils": set(),
    # Nx build-system supply-chain compromise (May 27 2026)
    # Malicious versions injected into the @nx/* monorepo-build ecosystem.
    # OSV MAL-2025-41436 (@nx/devkit), MAL-2025-41437 (@nx/enterprise-cloud),
    # MAL-2025-41438 (@nx/eslint), MAL-2025-41439 (@nx/js),
    # MAL-2025-41440 (@nx/key), MAL-2025-41441 (@nx/node),
    # MAL-2025-41442 (@nx/workspace), MAL-2025-41443 (nx)
    "@nx/devkit": {"20.9.0", "21.5.0"},
    "@nx/enterprise-cloud": {"3.2.0"},
    "@nx/eslint": {"21.5.0"},
    "@nx/js": {"20.9.0", "21.5.0"},
    "@nx/key": {"3.2.0", "5.0.7"},
    "@nx/node": {"20.9.0", "21.5.0"},
    "@nx/workspace": {"20.9.0", "21.5.0"},
    "nx": {"20.9.0", "20.10.0", "20.11.0", "20.12.0",
            "21.5.0", "21.6.0", "21.7.0", "21.8.0"},
    # @limebike/* dependency-confusion campaign (May 27 2026)
    # High-version (85.x) packages published to the @limebike scope to
    # override Lime's internal packages in CI. OSV affected.ranges is >=0
    # for every entry — use the empty-set wildcard.
    # OSV MAL-2026-4187 (@limebike/frontend-core-api),
    # MAL-2026-4188 (@limebike/supreme),
    # MAL-2026-4189 (@limebike/supreme-data-grid),
    # MAL-2026-4190 (@limebike/supreme-date-pickers)
    "@limebike/frontend-core-api": set(),
    "@limebike/supreme": set(),
    "@limebike/supreme-data-grid": set(),
    "@limebike/supreme-date-pickers": set(),
    # art-template maintainer-account compromise (May 27 2026)
    # Popular npm template engine (10M+ weekly downloads); specific malicious
    # versions injected. OSV MAL-2026-4200.
    "art-template": {"4.13.3", "4.13.5", "4.13.6"},
    # @tailwind-core/* Tailwind CSS typosquat cluster (May 27 2026)
    # Impersonates @tailwindcss/* platform-native packages; version 4.3.0
    # published across five platform-binary and plugin packages.
    # OSV MAL-2026-4448 through MAL-2026-4452.
    "@tailwind-core/oxide-linux-x64-gnu": {"4.3.0"},
    "@tailwind-core/oxide-win32-x64-msvc": {"4.3.0"},
    "@tailwind-core/postcss": {"4.3.0"},
    "@tailwind-core/vite": {"4.3.0"},
    "@tailwind-core/webpack": {"4.3.0"},
    # @tarojs/cli supply-chain compromise (May 27 2026)
    # Malicious beta releases of the Taro cross-platform app framework CLI.
    # OSV MAL-2026-4453.
    "@tarojs/cli": {"4.1.12-beta.47", "4.2.1-beta.0"},
    # msc-terminal npm infostealer (May 27 2026)
    # Pure-malware any-version package; OSV affected.ranges is >=0.
    # OSV MAL-2026-4823.
    "msc-terminal": set(),
    # polymarket-clob-client compromise (May 26 2026)
    # Specific malicious version of the official Polymarket CLOB npm client.
    # OSV MAL-2026-4643.
    "polymarket-clob-client": {"2.1.1"},
    # Baileys/WhatsApp bot malware campaign (May 27 2026)
    # Multiple malicious forks of the WhatsApp API (baileys / libsignal-node /
    # fca) targeting WhatsApp bot developers. Postinstall payloads steal
    # credentials, crypto wallets, and browser data.
    # OSV MAL-2026-4369, 4372, 4373, 4374, 4392, 4442, 4443, 4470,
    #     4478, 4519, 4559, 4560, 4578, 4597, 4619
    "@blckrose/baileys": {"2.0.6", "2.0.7"},
    "@budetzz/baileys": {"2.0.14", "2.0.16", "2.0.17", "2.0.18"},
    "@budetzz/libsignal-node": {"2.0.15"},
    "@budetzzgantenk/baileys": {"2.0.17"},
    "@hanssoft/baileys": {"10.0.0"},
    "@shadowmd/libsignal-node": {"8.6.59"},
    "@shinzepelly/libsignal-node": {"2.2.4"},
    "@zentrix23/baileys": {"1.0.0"},
    "alya-baileys": {
        "1.9.35", "1.9.36", "1.9.37", "1.9.38",
        "1.9.39", "1.9.42", "1.9.45", "1.9.46",
    },
    "chromestaff-baileys": {"1.1.3"},
    "fca-eryxenx": {"6.0.0"},
    "fca-official-uzair-rajput": {"1.16.0"},
    "hiura-baileys": {"1.0.0", "1.0.1", "1.0.3"},
    "kurumi-fca": {"1.1.7", "1.1.8"},
    "naileys": {"0.5.2"},
    # @onerjs scope — BabylonJS typosquat cluster (May 27 2026)
    # Six packages impersonating the @babylonjs/* rendering-engine ecosystem.
    # OSV MAL-2026-4410, 4411, 4412, 4413, 4414, 4415
    "@onerjs/addons": {"8.52.1", "8.52.3"},
    "@onerjs/inspector": {"8.52.2"},
    "@onerjs/procedural-textures": {"8.51.8"},
    "@onerjs/serializers": {"8.52.1"},
    "@onerjs/smart-filters": {"8.51.7", "8.51.8"},
    "@onerjs/smart-filters-blocks": {"8.51.9", "8.52.4"},
    # Claude Code / openclaw impersonation cluster (May 27 2026)
    # Multiple packages impersonating Claude Code or the OpenClaw AI tooling
    # layer. Install-time payloads harvest developer credentials and AI API keys.
    # OSV MAL-2026-4370, 4371, 4376, 4386, 4395, 4398, 4441, 4445,
    #     4457, 4468, 4485, 4593
    "@bonsai-ai/claude-code": {"2.1.141-1", "2.1.141"},
    "@bonsai-ai/claude-code-win32-x64": {"2.1.141"},
    "@cometix/claude-code": {"2.1.143", "2.1.147"},
    "@elvatis_com/openclaw-cli-bridge-elvatis": {"3.11.4"},
    "@inetafrica/open-claudia": {"2.2.15", "2.2.16"},
    "@jonusnattapong/claudecode": {"2.1.163"},
    "@shadanai/openclaw": {"2026.5.15-1", "2026.5.16", "2026.5.26"},
    "@signetai/signet-memory-openclaw": {"0.123.3", "0.123.12"},
    "@tmecontinue/claude": {"2.2.15-test.1"},
    "@wengine-ai/claude-code-router-shared": {
        "2.0.21", "2.0.22", "2.0.23", "2.0.24",
        "2.0.25", "2.0.26", "2.0.41",
    },
    "atel-mcp-openclaw": {"0.6.43", "0.6.44"},
    "klaudius": {"0.9.0", "0.11.0", "0.12.0", "0.12.1", "0.12.2", "0.12.3"},
    # local-mcp / lokal-mcp MCP malware campaign (May 27 2026)
    # Malicious MCP server packages targeting developers using the Model
    # Context Protocol toolchain. local-mcp published 21 malicious versions.
    # OSV MAL-2026-4601 (local-mcp), MAL-2026-4602 (lokal-mcp)
    "local-mcp": {
        "3.0.177", "3.0.178", "3.0.180", "3.0.183", "3.0.186", "3.0.188",
        "3.0.192", "3.0.197", "3.0.198", "3.0.199", "3.0.201", "3.0.203",
        "3.0.206", "3.0.207", "3.0.209", "3.0.210", "3.0.211", "3.0.212",
        "3.0.215", "3.0.217", "3.0.221",
    },
    "lokal-mcp": {"0.4.0"},
    # Dependency-confusion 99.x campaign (May 27 2026)
    # High-version packages published to the public registry to shadow private
    # internal packages in CI pipelines. OSV MAL-2026-4424, 4543, 4830, 4831, 4832
    "@remitee-money-transfer/rmt-base": {
        "99.99.99", "99.99.100", "99.99.102", "99.99.104",
    },
    "customerdigital-ui-containers-lib": {"99.12.9", "99.13.9"},
    "editorial-code": {"99.0.1"},
    "editorial-mse-authentication-ui": {"99.0.1"},
    "mse-authentication": {"99.0.1"},
    # Any-version wildcards — May 27 2026 pure-malware packages
    # OSV affected.ranges is >=0 for each; use empty-set wildcard.
    # OSV MAL-2026-2491, 4344, 4356, 4512, 4523, 4670, 4807, 4833
    "@not-nemo/crypto-tracker": set(),
    "bulletproof-json": set(),
    "chai-as-repaired": set(),
    "claude-channel-imessage": set(),
    "shop-minis": set(),
    "skills-detector": set(),
    "testing-on-npmjs": set(),
    "verify-mycommand": set(),
    # Miscellaneous npm malware — May 27 2026 bulk OSV disclosures
    # All confirmed by individual OSV MAL-2026-* records; exact-version pins.
    # Includes legitimate-package compromises (@ctrl/plex, opentiny-react,
    # rdflib, @nutui/nutui-react-taro) and pure-malware new packages.
    "@agora-sdk/react-js": {"1.0.2", "1.0.3"},
    "@aledan007/tester": {"0.4.5"},
    "@amswf/huoke": {"1.9.0", "1.9.1"},
    "@arbocollab/arbo-web-people": {
        "0.26.3-alpha.7", "0.26.3-alpha.9", "0.26.3-alpha.10",
        "0.26.3-alpha.13", "0.26.3-alpha.14", "0.26.3-alpha.15",
    },
    "@asura21232/fca-unofficial-nextgen": {"2.0.1"},
    "@aswinsparky/api": {"1.0.1"},
    "@atlisp/mcp": {"1.6.10"},
    "@autofleet/rabbit": {"1.3.0"},
    "@autoheal/setup": {"1.0.2"},
    "@bcrumbs.net/bc-chat": {"1.0.87"},
    "@beyondbday/vibe-terminal": {"1.1.14", "1.1.16", "1.1.17", "1.1.21"},
    "@catclaw/message-logger-plugin": {"0.2.9-beta.5"},
    "@citely/mcp-server": {"0.9.1", "0.10.0"},
    "@ctrl/plex": {"6.0.0"},
    "@dekuzxc/nexca": {"1.1.0", "1.2.0", "1.4.7"},
    "@digicroz/typed-api-kit": {"1.0.3", "1.0.4"},
    "@dknzo/soonex-ai": {"1.0.0", "1.0.1"},
    "@dreamlake/lakeshore": {"0.1.16", "0.1.17"},
    "@euqns/nudge-mcp": {"0.1.0", "0.1.1", "0.2.0", "0.2.1"},
    "@exocore/exocode": {"0.0.11", "0.0.15", "0.0.17"},
    "@flowselections/core": {"1.0.8", "1.0.9"},
    "@godscene/web": {"1.7.22"},
    "@iola_adm/iola-cli": {"0.1.2"},
    "@jemavidev/betteragents-pi": {
        "0.1.1", "0.1.3", "0.1.4", "0.1.5",
        "0.1.7", "0.1.9", "0.1.10", "0.1.11",
    },
    "@kedem/okdb": {"1.8.3"},
    "@kmmao/happy-coder": {
        "0.83.7", "0.85.2", "0.85.5", "0.85.12",
        "0.85.20", "0.85.21", "0.86.1", "0.86.2", "0.86.3",
    },
    "@kruzer/lib-ui": {"0.0.0-alpha.491", "0.0.0-alpha.497"},
    "@kyungseopk1m/holidays-kr": {"2.0.2"},
    "@leviyuan/lodestar": {"0.4.2"},
    "@link-assistant/hive-mind": {
        "1.69.17", "1.72.1", "1.72.3", "1.72.4", "1.72.5", "1.72.6",
    },
    "@lokuma/cli": {"2.0.1"},
    "@luke-101141/nobody": {"1.0.1"},
    "@mcpassure/mcp-anvisa-bulario": {
        "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5",
        "2.1.6", "2.1.7", "2.1.8", "2.1.9", "2.1.10",
    },
    "@mcpassure/mcp-cnes": {
        "0.2.1", "0.2.2", "0.2.4", "0.2.5", "0.2.6",
        "0.2.7", "0.2.8", "0.2.9", "0.3.0", "0.3.1", "0.3.2",
    },
    "@nolimit-x/win32-x64": {"1.0.105"},
    "@nutui/nutui-react-taro": {"3.0.21-cpp"},
    "@ornexus/neocortex": {"4.55.4", "4.55.5"},
    "@pisell/pisellos": {
        "0.0.546", "2.2.164", "2.2.168", "2.2.169", "2.2.172", "2.2.173",
    },
    "@pmate/utils": {"1.1.4"},
    "@qwedqwed/axios": {"1.16.2"},
    "@refactco/refact-os": {"1.5.0", "1.5.2", "1.6.0", "1.6.1"},
    "@riteshkumar04/stack-audit": {"1.0.7", "1.0.8", "1.0.11"},
    "@rspack-debug/core": {"2.0.4"},
    "@rui.branco/sentry-mcp": {"1.0.4"},
    "@saidddddddddd/somethingelse": {"2.0.0"},
    "@scp3500/openvl": {"1.0.40"},
    "@self-evolving-harness/kivo": {"1.29.3"},
    "@semacode/cli": {"1.5.28"},
    "@spcsn/taro-cli": {"0.1.5"},
    "@taskd/maritime-email-processor": {"1.0.6"},
    "@thebros/create-benjamin": {"1.0.12"},
    "@thesignup/cli": {"0.0.2"},
    "@toni77777/aora": {"0.1.0", "0.1.1"},
    "@touchvue/chat": {"1.0.0-beta.52", "1.0.0-beta.53", "1.0.0-beta.54"},
    "@venturo/playwright": {"1.1.0"},
    "@vino.tian/vibe-kanban": {"0.1.4413", "0.1.4418", "0.1.4420"},
    "@zaamx/netme": {"0.0.6", "0.0.7"},
    "@zesyn/zeditor": {"1.0.3"},
    "acc-document-editing": {"0.1.1", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.8"},
    "amaco-os": {"0.1.0", "0.1.1"},
    "ask-my-llm": {"1.1.3", "1.1.4", "1.1.5"},
    "clawpro-diagnostics-metrics-cls": {"3.0.4"},
    "etherproxy-lite": {"0.6.0"},
    "figma-d2c-utils": {"0.6.0"},
    "koishi-plugin-fusheng-car": {"1.0.6"},
    "koishi-plugin-fusheng-count": {"1.0.9"},
    "koishi-plugin-yuan": {"1.7.0"},
    "makecoder": {"4.0.54", "4.0.56", "4.0.57"},
    "mcp-server-iehub-proxy": {"1.0.0"},
    "n8n-nodes-whatsapp-business-api-by-automations-builder": {"0.1.0"},
    "omnius": {
        "1.0.136", "1.0.140", "1.0.141", "1.0.145",
        "1.0.147", "1.0.148", "1.0.153", "1.0.155", "1.0.157",
    },
    "onboardconnect-agent": {
        "1.1.5", "1.1.15", "1.1.16", "1.1.21",
        "1.1.22", "1.1.24", "1.1.25", "1.1.31", "1.1.32",
    },
    "open-agents-ai": {
        "0.187.587", "0.187.588", "0.187.589", "0.187.590",
        "0.187.591", "0.187.592", "0.187.593", "0.187.594",
        "0.187.595", "0.187.596",
    },
    "opentiny-react": {"6.9.31"},
    "peertube-plugin-google-analytics-js": {"0.0.1"},
    "prisma-client-python": {"0.3.8"},
    "promptbook-cli": {"0.1.0"},
    "promptbook-mcp": {"0.1.0"},
    "rdflib": {"2.3.7"},
    "seedcode-facturacion-electronica": {"2.5.35"},
    "share-anything-cli": {"0.5.6"},
    "skipshot-agent": {"2.0.3"},
    "tax4all-components": {"0.1.26"},
    "tdpilot": {"1.6.15", "1.6.16"},
    "tubebrain": {"0.1.10"},
    "use-context-selector-tony": {"2.0.5"},
    "venturo-playwright": {"1.0.13"},
    "venturo-playwright-runner": {"1.0.6", "1.0.8", "1.0.9", "1.0.12"},
    "vestibulect": {"0.0.1"},
    "wallet-agent-ai": {"1.0.1", "1.0.2"},
    "wallet-agent-ai-radix": {"1.0.0"},
    "workrally": {"2.4.0"},
    # May 26 2026 pure-malware typosquat batch — 17 packages, all fully malicious.
    # GHSA affected.ranges is >= 0 for every entry; use the empty-set wildcard.
    # Clusters: Web3/DeFi impersonators (web3-prices, web3.prc, int-node, @izumiswap/sdk),
    # JSON-utility typosquats (jsonlogbundler, fastjsonlog, jsonbson), Solidity/Hardhat
    # dev-tool impersonators (solidity-coverage-plus, hardhat-gas-analytics), document-
    # library typosquats (pdf-lib-enhanced, xlsx-enhanced), and miscellaneous malware
    # (corelia, license-checker-plus, lynx-keeper, lynx-keeper-cli, zest-product,
    # tailwind-style-typography).
    # GHSA-g3vg-qhhh-pfv7 (web3-prices), GHSA-r4j3-79hx-xpr6 (web3.prc),
    # GHSA-r4ww-65gv-rhv8 (int-node), GHSA-q782-j24w-vv68 (@izumiswap/sdk),
    # GHSA-hhf2-gfcc-vw45 (jsonlogbundler), GHSA-82gw-34fc-qfwj (fastjsonlog),
    # GHSA-44rg-m26f-r36f (jsonbson), GHSA-fg63-2vqh-93xf (corelia),
    # GHSA-9qcm-qgjc-h848 (pdf-lib-enhanced), GHSA-j5gx-8qjw-gp5q (xlsx-enhanced),
    # GHSA-j3fh-3pm4-rw5h (solidity-coverage-plus), GHSA-73xx-w222-rg6v (license-checker-plus),
    # GHSA-7pxc-2jp3-w7c8 (hardhat-gas-analytics), GHSA-x7hr-g7qr-7j7p (lynx-keeper),
    # GHSA-3p5r-gmr8-v7mr (lynx-keeper-cli), GHSA-qm6m-33hv-fvwv (zest-product),
    # GHSA-pv74-wmjg-4gp8 (tailwind-style-typography)
    "@izumiswap/sdk": set(),
    "corelia": set(),
    "fastjsonlog": set(),
    "hardhat-gas-analytics": set(),
    "int-node": set(),
    "jsonbson": set(),
    "jsonlogbundler": set(),
    "license-checker-plus": set(),
    "lynx-keeper": set(),
    "lynx-keeper-cli": set(),
    "pdf-lib-enhanced": set(),
    "solidity-coverage-plus": set(),
    "tailwind-style-typography": set(),
    "web3-prices": set(),
    "web3.prc": set(),
    "xlsx-enhanced": set(),
    "zest-product": set(),
    # Moika Tech out-of-band dependency confusion campaign (May 28 2026)
    # Attacker (npm user 'pik-libs') published 164 private internal packages
    # belonging to a Russian bank / cloud platform at inflated version 99.99.99,
    # exploiting npm's default highest-version resolution to hijack internal CI.
    # All five scopes are company-internal; any version on the public npm registry
    # is malicious. OSV ingestion pending; confirmed in ossf/malicious-packages
    # PR #1279 (merged 2026-05-28, authors KunalSin9h + calebbrown; references
    # SafeDep Moika Tech dependency confusion report).
    # @car-loans scope (19 packages)
    "@car-loans/applicaion-aff": set(),
    "@car-loans/application-aff": set(),
    "@car-loans/close-flow-module": set(),
    "@car-loans/deal-aff": set(),
    "@car-loans/deal": set(),
    "@car-loans/desktop-car-loans-application": set(),
    "@car-loans/feature-toggles-module": set(),
    "@car-loans/general-analytics": set(),
    "@car-loans/general-feature-toggles": set(),
    "@car-loans/gus": set(),
    "@car-loans/mobile-car-loans-application": set(),
    "@car-loans/online-scoring-aff": set(),
    "@car-loans/online-sign-aff": set(),
    "@car-loans/referrer-module": set(),
    "@car-loans/restore": set(),
    "@car-loans/safe-storage-module": set(),
    "@car-loans/save": set(),
    "@car-loans/show-car-year-module": set(),
    "@car-loans/wait-task-props": set(),
    # @cloudplatform-single-spa scope (122 packages)
    "@cloudplatform-single-spa/administration": set(),
    "@cloudplatform-single-spa/advanced": set(),
    "@cloudplatform-single-spa/agreements": set(),
    "@cloudplatform-single-spa/aifactory-notebooks": set(),
    "@cloudplatform-single-spa/airflow": set(),
    "@cloudplatform-single-spa/anti-ddos": set(),
    "@cloudplatform-single-spa/arenadata-db": set(),
    "@cloudplatform-single-spa/audit-log": set(),
    "@cloudplatform-single-spa/bare-metal-servers": set(),
    "@cloudplatform-single-spa/base-static-page": set(),
    "@cloudplatform-single-spa/billing": set(),
    "@cloudplatform-single-spa/business-solutions": set(),
    "@cloudplatform-single-spa/certificate-manager": set(),
    "@cloudplatform-single-spa/clickhouse": set(),
    "@cloudplatform-single-spa/cloud-dns": set(),
    "@cloudplatform-single-spa/cloudia": set(),
    "@cloudplatform-single-spa/cnapp-ui": set(),
    "@cloudplatform-single-spa/container-registry": set(),
    "@cloudplatform-single-spa/corax": set(),
    "@cloudplatform-single-spa/cp-api-gw": set(),
    "@cloudplatform-single-spa/datagrid": set(),
    "@cloudplatform-single-spa/dataplatform-bi": set(),
    "@cloudplatform-single-spa/dataplatform-cloudberry": set(),
    "@cloudplatform-single-spa/dataplatform-clusters": set(),
    "@cloudplatform-single-spa/dataplatform-connections": set(),
    "@cloudplatform-single-spa/dataplatform-flink": set(),
    "@cloudplatform-single-spa/dataplatform-metastore": set(),
    "@cloudplatform-single-spa/dataplatform-nessie": set(),
    "@cloudplatform-single-spa/dataplatform-spark": set(),
    "@cloudplatform-single-spa/dataplatform-trino": set(),
    "@cloudplatform-single-spa/dataplatform": set(),
    "@cloudplatform-single-spa/disks": set(),
    "@cloudplatform-single-spa/dns": set(),
    "@cloudplatform-single-spa/document-db": set(),
    "@cloudplatform-single-spa/edge-manager": set(),
    "@cloudplatform-single-spa/employees": set(),
    "@cloudplatform-single-spa/enterprise": set(),
    "@cloudplatform-single-spa/event-bus": set(),
    "@cloudplatform-single-spa/evocs": set(),
    "@cloudplatform-single-spa/evolution": set(),
    "@cloudplatform-single-spa/floating-ips": set(),
    "@cloudplatform-single-spa/iam": set(),
    "@cloudplatform-single-spa/installations": set(),
    "@cloudplatform-single-spa/key-manager": set(),
    "@cloudplatform-single-spa/logaas": set(),
    "@cloudplatform-single-spa/magic-bridge": set(),
    "@cloudplatform-single-spa/magic-router": set(),
    "@cloudplatform-single-spa/managed-identities": set(),
    "@cloudplatform-single-spa/marketplace-apps": set(),
    "@cloudplatform-single-spa/marketplace-gigachat": set(),
    "@cloudplatform-single-spa/marketplace-main": set(),
    "@cloudplatform-single-spa/ml-ai-agents-agent-system": set(),
    "@cloudplatform-single-spa/ml-ai-agents-agent": set(),
    "@cloudplatform-single-spa/ml-ai-agents-evo-claw": set(),
    "@cloudplatform-single-spa/ml-ai-agents-ide": set(),
    "@cloudplatform-single-spa/ml-ai-agents-marketplace": set(),
    "@cloudplatform-single-spa/ml-ai-agents-mcp-server": set(),
    "@cloudplatform-single-spa/ml-ai-agents-system-prompt": set(),
    "@cloudplatform-single-spa/ml-ai-agents-trigger": set(),
    "@cloudplatform-single-spa/ml-finetuning": set(),
    "@cloudplatform-single-spa/ml-foundation-models": set(),
    "@cloudplatform-single-spa/ml-inference-comfy-run": set(),
    "@cloudplatform-single-spa/ml-inference-docker-run": set(),
    "@cloudplatform-single-spa/ml-inference-marketplace": set(),
    "@cloudplatform-single-spa/ml-inference-model-run": set(),
    "@cloudplatform-single-spa/ml-inference-router": set(),
    "@cloudplatform-single-spa/ml-inference": set(),
    "@cloudplatform-single-spa/ml-rag": set(),
    "@cloudplatform-single-spa/mlspace-access-request": set(),
    "@cloudplatform-single-spa/monaas-ui": set(),
    "@cloudplatform-single-spa/monitoring": set(),
    "@cloudplatform-single-spa/notification-gateway": set(),
    "@cloudplatform-single-spa/observability": set(),
    "@cloudplatform-single-spa/onboarding": set(),
    "@cloudplatform-single-spa/opensearch": set(),
    "@cloudplatform-single-spa/paas-kafka": set(),
    "@cloudplatform-single-spa/paas-redis": set(),
    "@cloudplatform-single-spa/pangolin": set(),
    "@cloudplatform-single-spa/postgre": set(),
    "@cloudplatform-single-spa/profile": set(),
    "@cloudplatform-single-spa/rabbitmq": set(),
    "@cloudplatform-single-spa/redirect": set(),
    "@cloudplatform-single-spa/resource-manager": set(),
    "@cloudplatform-single-spa/search": set(),
    "@cloudplatform-single-spa/secret-manager": set(),
    "@cloudplatform-single-spa/security-groups": set(),
    "@cloudplatform-single-spa/self-service": set(),
    "@cloudplatform-single-spa/serverless-containers": set(),
    "@cloudplatform-single-spa/smk": set(),
    "@cloudplatform-single-spa/solutions": set(),
    "@cloudplatform-single-spa/ssh-keys": set(),
    "@cloudplatform-single-spa/static-page": set(),
    "@cloudplatform-single-spa/subnets": set(),
    "@cloudplatform-single-spa/support": set(),
    "@cloudplatform-single-spa/svp-agent-backup": set(),
    "@cloudplatform-single-spa/svp-anti-affinity": set(),
    "@cloudplatform-single-spa/svp-baas": set(),
    "@cloudplatform-single-spa/svp-bare-metal-servers": set(),
    "@cloudplatform-single-spa/svp-draas": set(),
    "@cloudplatform-single-spa/svp-gateways": set(),
    "@cloudplatform-single-spa/svp-gitaas": set(),
    "@cloudplatform-single-spa/svp-images": set(),
    "@cloudplatform-single-spa/svp-interfaces": set(),
    "@cloudplatform-single-spa/svp-lbaas": set(),
    "@cloudplatform-single-spa/svp-managed-kubernetes": set(),
    "@cloudplatform-single-spa/svp-pipeline": set(),
    "@cloudplatform-single-spa/svp-s3-storage": set(),
    "@cloudplatform-single-spa/svp-tags": set(),
    "@cloudplatform-single-spa/svp-tasks": set(),
    "@cloudplatform-single-spa/svp-vdi": set(),
    "@cloudplatform-single-spa/svp-vm-migration": set(),
    "@cloudplatform-single-spa/timescale-db": set(),
    "@cloudplatform-single-spa/vcenter-manager": set(),
    "@cloudplatform-single-spa/vcenter-virtual-machines": set(),
    "@cloudplatform-single-spa/vdi": set(),
    "@cloudplatform-single-spa/virtual-ip": set(),
    "@cloudplatform-single-spa/virtual-machines": set(),
    "@cloudplatform-single-spa/vmmanager": set(),
    "@cloudplatform-single-spa/vmware-draas": set(),
    "@cloudplatform-single-spa/vpc-endpoint": set(),
    "@cloudplatform-single-spa/vpc": set(),
    "@cloudplatform-single-spa/vpn": set(),
    # @debit-ib scope (2 packages)
    "@debit-ib/desktop-debit-ib-additional-card-form": set(),
    "@debit-ib/mobile-debit-ib-additional-card-form": set(),
    # @fb-deposit scope (4 packages)
    "@fb-deposit/form-deposit-auth": set(),
    "@fb-deposit/form-deposit-calc": set(),
    "@fb-deposit/form-deposit": set(),
    "@fb-deposit/form-savings-account": set(),
    # @mlspace scope (17 packages)
    "@mlspace/allocations": set(),
    "@mlspace/connectors": set(),
    "@mlspace/docker-registry": set(),
    "@mlspace/dtransfer-history": set(),
    "@mlspace/dtransfer": set(),
    "@mlspace/env-gitlab": set(),
    "@mlspace/env-jobs": set(),
    "@mlspace/env-jupyter-server": set(),
    "@mlspace/experiments-monitoring": set(),
    "@mlspace/experiments": set(),
    "@mlspace/file-manager": set(),
    "@mlspace/inference-build": set(),
    "@mlspace/inference-deploy": set(),
    "@mlspace/model-monitoring": set(),
    "@mlspace/model-registry": set(),
    "@mlspace/profile": set(),
    "@mlspace/shared-storage": set(),
}

# npm scopes hit in this campaign. Exact versions are pinned above; any
# additional package in these scopes still triggers a manual-review warning
# in case the advisory expands.
NPM_SUSPECT_SCOPES = (
    "@mistralai/", "@uipath/", "@opensearch-project/", "@antv/",
    # Moika Tech dependency confusion scopes (May 28 2026)
    "@car-loans/", "@cloudplatform-single-spa/",
    "@debit-ib/", "@fb-deposit/", "@mlspace/",
)

# crates.io: exact crate name -> set of malicious versions.
# All entries below are RustSec advisories tagged `categories = ["malicious"]`
# with `[versions] patched = []` — i.e. the package was removed from the
# registry and any installed version is malicious. Use the empty-set
# wildcard so re-uploads under different versions are still caught.
# Sources: rustsec/advisory-db, OSV crates.io ecosystem.
CRATES_BAD: dict[str, set[str]] = {
    # rustdecimal typosquat of rust_decimal (Mar 2022, GHSA-7pwq-f4pq-78gm)
    "rustdecimal": set(),
    # amaperf typosquat cluster (Aug 2023, Veracode/Phylum disclosure)
    "xrvrv": set(),
    "oncecell": set(),
    "serd": set(),
    "lazystatic": set(),
    "if-cfg": set(),
    "envlogger": set(),
    "postgress": set(),
    "littest": set(),
    "windowsservice": set(),
    "lfest-main": set(),
    "lasso-rs": set(),
    "monero-api": set(),
    "monero-rpc-rs": set(),
    "postgresderive": set(),
    "tauri-win-rt-notification": set(),
    "win-crypto": set(),
    "windows-service-rs": set(),
    "tauri-winrt-notifications": set(),
    "win-base64-rs": set(),
    "tiny-server": set(),
    "openvpn-plugin-rs": set(),
    "registry-win": set(),
    "win_run_rs": set(),
    "libusb1-main": set(),
    "winx-rs": set(),
    "hann-rs-service": set(),
    "bit-flags": set(),
    "acceptxmr-rs": set(),
    # Polymarket credential-stealer typosquat campaign (Feb 2026)
    "polymarket-clients-sdk": set(),
    "polymarket-client-sdks": set(),
    "polymarkets-client-sdk": set(),
    "polymarkets-rs-clob-client": set(),
    "clob-sdk": set(),
    "rpc-check": set(),
    # timeapi.io impersonation campaign (Mar 2026, Socket disclosure)
    "time_calibrator": set(),
    "time_calibrators": set(),
    "dnp3times": set(),
    "time-sync": set(),
    "chrono_anchor": set(),
    "tracing-check": set(),
    "tracings": set(),
    "tracing_checks": set(),
    "tracing-ethers": set(),
    # TrapDoor crates.io build.rs dropper cluster (May 22–26 2026) — Sui / Move developers
    # build.rs locates Sui, Solana, and Aptos wallet keystores, XOR-encrypts them
    # with hardcoded key "cargo-build-helper-2026", exfiltrates to GitHub Gists
    # (attacker account: ddjidd564). All six were removed from crates.io.
    # Sources: socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates (primary);
    #          theblock.co/post/402458/ (independent corroboration);
    #          socradar.io/blog/trapdoor-npm-pypi-cratesio-secrets-ai-tooling/;
    #          cybersecuritynews.com/supply-chain-trapdoor-malware/
    "move-analyzer-build": set(),
    "move-compiler-tools": set(),
    "move-project-builder": set(),
    "sui-framework-helpers": set(),
    "sui-move-build-helper": set(),
    "sui-sdk-build-utils": set(),
    # build.rs droppers / .env exfiltration (2025-2026)
    "uniswap-utils": set(),
    "sha-rust": set(),
    "evm-units": set(),
    "finch-rust": set(),
    "finch-rst": set(),
    "sha-rst": set(),
    "finch_cli_rust": set(),
    "rands": set(),
    "replit_ruspty": set(),
    "tree-sitter-pkl": set(),
    "custom-req-on-workers": set(),
    "statsrelay-protobuf": set(),
    "jfrog_quotes": set(),
    "sophosfirewall-python": set(),
    "logtrace": set(),
    "pretty-changelog-logger": set(),
    "microsoftsystem64": set(),
    "safe-agent-rs": set(),
    "mysten-metrics": set(),
    "sui-execution-cut": set(),
}

SKIP_DIRS = {"node_modules", ".venv", "venv", ".git",
             "dist", "build", "__pycache__", ".tox", ".mypy_cache",
             "target"}

PYPI_FILENAMES = {"Pipfile", "Pipfile.lock", "poetry.lock",
                  "pyproject.toml", "setup.py"}
NPM_FILENAMES = {"package.json", "package-lock.json",
                 "yarn.lock", "pnpm-lock.yaml"}
CRATES_FILENAMES = {"Cargo.toml", "Cargo.lock"}

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


# Cargo.lock: each [[package]] block holds name/version/source. Only entries
# sourced from the crates.io registry are reported; path/git dependencies
# can't be matched against a crates.io name list.
CARGO_LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.MULTILINE)
CARGO_LOCK_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)


def parse_cargo_lock(path: Path) -> Iterable[tuple[str, str]]:
    text = path.read_text(errors="ignore")
    for block in text.split("[[package]]")[1:]:
        if 'source = "registry+' not in block:
            continue
        name_m = CARGO_LOCK_NAME_RE.search(block)
        ver_m = CARGO_LOCK_VERSION_RE.search(block)
        if name_m and ver_m:
            yield name_m.group(1), ver_m.group(1)


# Cargo.toml: dependency tables can appear as
#   [dependencies]                 → inline `pkg = "1.2"` or `pkg = { version = "1.2", ... }`
#   [dev-dependencies]              → same
#   [build-dependencies]            → same
#   [target.'cfg(unix)'.dependencies] → same
#   [dependencies.pkg]              → version on its own line in the table body
# Workspace tables ([workspace.dependencies]) follow the same shape.
CARGO_SECTION_HEADER_RE = re.compile(r"^\[([^\]]+)\]\s*$", re.MULTILINE)
CARGO_INLINE_DEP_RE = re.compile(
    r'^\s*([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"\s*$', re.MULTILINE
)
CARGO_TABLE_DEP_RE = re.compile(
    r'^\s*([A-Za-z0-9_\-]+)\s*=\s*\{([^}]*)\}\s*$', re.MULTILINE
)
CARGO_TABLE_VERSION_RE = re.compile(r'version\s*=\s*"([^"]+)"')


def _is_cargo_dep_section(section: str) -> bool:
    """True for [dependencies], [dev-dependencies], [build-dependencies],
    workspace variants, and target-prefixed variants. Returns False for
    [dependencies.pkg] style (handled separately)."""
    s = section.strip()
    tail = s.rsplit(".", 1)[-1]
    return tail in {"dependencies", "dev-dependencies", "build-dependencies"}


def _cargo_subtable_dep_name(section: str) -> str | None:
    """For [dependencies.pkg] / [workspace.dependencies.pkg] /
    [target.X.dev-dependencies.pkg], return `pkg`. Otherwise None."""
    parts = section.strip().split(".")
    if len(parts) < 2:
        return None
    if parts[-2] in {"dependencies", "dev-dependencies", "build-dependencies"}:
        return parts[-1]
    return None


def parse_cargo_toml(path: Path) -> Iterable[tuple[str, str | None]]:
    text = path.read_text(errors="ignore")
    # Split text into (section_header, body) pairs.
    headers = list(CARGO_SECTION_HEADER_RE.finditer(text))
    for i, m in enumerate(headers):
        section = m.group(1)
        body_start = m.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[body_start:body_end]

        sub_dep = _cargo_subtable_dep_name(section)
        if sub_dep:
            ver_m = CARGO_TABLE_VERSION_RE.search(body)
            yield sub_dep, ver_m.group(1) if ver_m else None
            continue

        if not _is_cargo_dep_section(section):
            continue

        for line_m in CARGO_INLINE_DEP_RE.finditer(body):
            yield line_m.group(1), line_m.group(2)
        for line_m in CARGO_TABLE_DEP_RE.finditer(body):
            inner = line_m.group(2)
            ver_m = CARGO_TABLE_VERSION_RE.search(inner)
            yield line_m.group(1), ver_m.group(1) if ver_m else None


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
        if (name in PYPI_FILENAMES or name in NPM_FILENAMES
                or name in CRATES_FILENAMES or REQ_TXT_RE.match(name)):
            out.append(path)
    return out


def parse_manifest(path: Path) -> tuple[list[tuple[str, str | None]], str]:
    """Return (pairs, ecosystem) for the given manifest path.
    Ecosystem is one of: "npm", "pypi", "crates", or "" if unknown."""
    name = path.name
    if name == "package.json":
        return list(parse_package_json(path)), "npm"
    if name == "package-lock.json":
        return list(parse_package_lock(path)), "npm"
    if name == "yarn.lock":
        return list(parse_yarn_lock(path)), "npm"
    if name == "pnpm-lock.yaml":
        return list(parse_pnpm_lock(path)), "npm"
    if name == "pyproject.toml":
        return list(parse_pyproject_toml(path)), "pypi"
    if name in {"Pipfile", "Pipfile.lock", "poetry.lock", "setup.py"} or REQ_TXT_RE.match(name):
        return list(parse_requirements_txt(path)), "pypi"
    if name == "Cargo.toml":
        return list(parse_cargo_toml(path)), "crates"
    if name == "Cargo.lock":
        return list(parse_cargo_lock(path)), "crates"
    return [], ""


def scan(root: Path):
    hits: list[tuple[Path, str, str, str]] = []
    suspects: list[tuple[Path, str, str, str]] = []

    for path in find_manifests(root):
        try:
            pairs, ecosystem = parse_manifest(path)
        except Exception as exc:
            print(f"warn: failed to parse {path}: {exc}", file=sys.stderr)
            continue

        for pkg, version in pairs:
            if ecosystem == "npm":
                bad = NPM_BAD.get(pkg)
                # Empty set is the wildcard: any version of this package is
                # malicious (pure-malware typosquats; see PYPI_BAD docstring).
                if bad is not None and (not bad or version in bad):
                    hits.append((path, pkg, version or "?", "npm"))
                elif any(pkg.startswith(s) for s in NPM_SUSPECT_SCOPES):
                    suspects.append((path, pkg, version or "?", "npm-scope"))
            elif ecosystem == "pypi":
                bad = PYPI_BAD.get(pkg.lower())
                if bad is not None and (not bad or (version and version in bad)):
                    hits.append((path, pkg, version or "?", "pypi"))
            elif ecosystem == "crates":
                bad = CRATES_BAD.get(pkg)
                if bad is not None and (not bad or (version and version in bad)):
                    hits.append((path, pkg, version or "?", "crates.io"))

    return hits, suspects


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a repo for known-malicious npm/PyPI/crates.io package versions.",
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
