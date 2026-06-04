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
May 27 2026, the @limebike dependency-confusion campaign May 27 2026, the
CanisterSprawl TeamPCP npm worm / Namastex Labs packages April 2026,
the @velora-dex/sdk registry-only macOS backdoor April 2026, the DevTap
user0001 typosquat cluster April–May 2026, the xinference PyPI TeamPCP
compromise April 2026, the dependency-confusion 99.x batch May 27 2026,
and related Mistral / Guardrails / durabletask / pytorch-lightning
poisonings, the May 26 2026 17-package pure-malware batch covering
Web3/DeFi, JSON-utility, Solidity/Hardhat, and document-library
typosquats, the September 8 2025 Qix phishing attack on the
chalk/debug/color/ansi npm ecosystem (19 packages, >2B weekly downloads,
crypto-wallet interceptor), the September 15 2025 Shai-Hulud worm wave via
@ctrl/tinycolor and ngx-bootstrap account takeovers, the Moika Tech
out-of-band dependency confusion campaign May 28 2026 (five private
scopes, 164 npm packages: @car-loans, @cloudplatform-single-spa,
@debit-ib, @fb-deposit, @mlspace), the vpmdhaj OpenSearch/CI typosquat
cluster May 28 2026 (14 npm packages targeting OpenSearch, ElasticSearch,
and CI/CD environments), the Roblox/robase PyPI typosquat cluster May 29
2026 (52 packages impersonating Roblox API / database helper libraries),
and the oob-moika-tech dependency-confusion npm sub-wave May 29 2026
(@databus-service-ui, @service-suppliers, @service-user-notifications,
@polka-ui, @pulse-web-platform-core, @loans, nemo-reporter), the
oob-moika-tech Wave 2 npm dependency-confusion cluster May 29 2026
(17 packages by actor t-in-one / nath.dr4k3@gmail.com, C2 oob.moika.tech:
15 @t-in-one/* Angular DI token packages, @capibar.chat/ui-kit,
@sber-ecom-core/sberpay-widget; OSV MAL-2026-3337, 5031–5046), the
mixed npm malware batch May 29 2026 (buffer-util-extend GHSA-g44v-3gq3-j8p6,
hellowornd GHSA-4f9q-ffgq-5w82, tiny-naturalsort GHSA-mqp5-9r9w-8hg4,
@neon-i18n/core-ui and sorenson-webfonts dependency-confusion;
OSV MAL-2026-2920/4839/5027/5028/5030), and the modulebuild3240234t
PyPI Roblox infostealer May 29 2026 (OSV MAL-2026-5029), the puppeteer
25.0.1 maintainer-account compromise May 29 2026 (GHSA-8r2f-2qg4-cv9v),
Mini Shai-Hulud additional packages @beproduct/nestjs-auth and
@tallyui/storage-sqlite (May 2026; GHSA-cqpw-mfqj-f2j7 / MAL-2026-3433/3604),
supplemental @antv-wave non-@antv npm packages May 19 2026 (@lint-md/*,
canvas-nest.js, onfire.js, etc.; OSV MAL-2026-4123-4159), and the May 29-30
2026 multi-campaign dependency confusion + typosquat batch (100 new npm
packages across @clearpool, axis-*, ally-*, @breezeai-frontend,
@citi-icg-158830, apexomni/apexpro, @cplace-*, @rsi-community, @timelycare,
ethers.js/EVM typosquats, chai/tailwind plugin typosquats, zod-to-js, and
misc; OSV MAL-2026-3056 through MAL-2026-5085)), and the
polymarket-data PyPI crypto/credentials infostealer May 30 2026
(OSV MAL-2026-5086), and the crypto-helper / cryptolock PyPI install-time
malware batch May 30 2026 (OSV MAL-2026-5088/5089), the discord-ban PyPI
browser-credential infostealer May 30 2026 (OSV MAL-2026-5091), and the
neuralforge-ml PyPI env-variable exfiltrator May 30 2026 (OSV MAL-2026-5090),
and the retail-location-strategy-frontend npm malware May 30 2026
(OSV MAL-2026-5092), and the js-shared-modules npm malware May 31 2026
(OSV MAL-2026-5098), and the discord-massban PyPI browser-credential infostealer
May 31 2026 (OSV MAL-2026-5099), and the obfuscation PyPI install-time malware
May 31 2026 (OSV MAL-2026-5100), and the June 1 2026 npm batch: CMS-dropper
typosquat cluster (to-cms, cms-github, cms-helpgit, shopifyto-cms; OSV
MAL-2026-4693/5107/5108/5109), Amazon Inspector postinstall-exfiltration batch
(collected-forms-embed-js, audit-logsss, chainix; OSV MAL-2026-4175/4487/4817),
chai-as-minted Chai typosquat (OSV MAL-2026-5106), AWS/CLI typosquats
(@antoncallahan/aws-user-helper, @tmecontinue/cli; OSV MAL-2026-5101/5105),
and three GHSA-confirmed test-scope malware packages
(@ewfewfewf/testhackerrr, @osamdefeirrighs/testhackfrrferrr,
@pcldpvkoewpogw/testhacker; OSV MAL-2026-5102/5103/5104), the
@redhat-cloud-services scope account compromise June 1 2026 (nine packages:
chrome, eslint-config, frontend-components, frontend-components-config-utilities,
quickstarts-client, rbac-client, rule-components, topological-inventory-client,
types; OSV MAL-2026-5111 through MAL-2026-5119), loading-session npm package
compromise June 1 2026 (OSV MAL-2026-4600 / GHSA-7vwr-8v2c-gjvr), jingmeideshishi
npm throwaway malware June 1 2026 (OSV MAL-2026-5110 / GHSA-pc3j-w4f9-94hj), and
redteam-qxz7-utils PyPI malware June 1 2026 (OSV MAL-2026-5120), and
rookie-security-test-pkg npm malware June 1 2026 (OSV MAL-2026-5132), and
the June 2 2026 dep-confusion + PyPI RAT batch: @aonunited/angular dependency
confusion (OSV MAL-2026-5150), @att-ebiz/abs-components-bc dependency confusion
(OSV MAL-2026-5153), parsimonius Telegram-RAT typosquat of parsimonious
(OSV MAL-2026-5151), quant-backtest-helpers env/cloud-token exfiltrator
(OSV MAL-2026-5152), and bt-signal-utils env/cloud-token exfiltrator
(OSV MAL-2026-5160; same campaign as quant-backtest-helpers),
the @antv/color-util npm infostealer (Mini Shai-Hulud supplemental, June 2 2026;
OSV MAL-2026-3862 / GHSA-rh6v-hwr4-6jcp), the Scandinavian telecom dep-confusion
npm cluster June 2 2026 (@customer-threesixty/assets, @ownit/core, @telenor-se/core,
@tse-digital/core; actor debating0166; OSV MAL-2026-5154/5155/5156/5157), the
oob-moika-tech EMCD-impersonation Wave 3 npm dep-confusion cluster June 2 2026
(@emcd-vue/auth, @emcd-vue/b2b-pay-form, @emcd-vue/loans; OSV MAL-2026-5163/5164/5165),
the dep-confusion 99.x npm batch June 2 2026 (page-info-service 99.9.1,
po-ops-local-dev 99.9.1, sourceflow-tracker 99.91.9; OSV MAL-2026-5158/5159/5166),
and the jules-test-utils PyPI host-info exfiltrator June 2 2026 (OSV MAL-2026-5167),
vg-interaction-model npm dep-confusion June 2 2026 (OSV MAL-2026-5168; updated June 3
2026 to add version 40.0.4), chai-parse Chai typosquat any-version malware June 2 2026
(OSV MAL-2026-5169), and fundraiserserv npm malware June 3 2026 (OSV MAL-2026-5172;
communicates with a malicious domain; detected by OpenSSF Package Analysis),
and brave-search-mcp-server npm malware June 3 2026 (OSV MAL-2026-5182;
communicates with a malicious domain and executes malicious commands; detected
by OpenSSF Package Analysis), the sf-silly-goose-requests PyPI TruffleHog-based
secret exfiltrator June 4 2026 (OSV MAL-2026-5184), and the June 4 2026 npm
full-compromise batch: @jagreehal/workflow (OSV MAL-2026-5185 / GHSA-6w7v-23mf-65g3),
autotel-terminal (OSV MAL-2026-5186 / GHSA-cw9v-v9rh-r449), and supabase CLI
(OSV MAL-2026-5187 / GHSA-x96m-c5fj-q75c; fresh single-source advisory filed on
the same day version 2.105.0 was published).

Note: a large batch of packages initially flagged from the May 27 2026
bulk OSV disclosures were subsequently withdrawn as false positives by the
ossf/malicious-packages project (PRs #1276/#1278) — including the
fastapi / strawberry-graphql / notebook-intelligence PyPI reports, the
@tailwind-core and @onerjs npm typosquat clusters, the Baileys/WhatsApp,
Claude Code/openclaw, and local-mcp/lokal-mcp campaigns, and the bulk
edison-tools/heims/openirf/ranno PyPI batch. Those entries have been
removed. Only packages with an active (non-withdrawn) OSV MAL record, or
independent authoritative corroboration, are retained.

Author:    Jascha Wanger / Tarnover, LLC
Date:      2026-06-03
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
    "quatres": {"3.0.1"},
    # Roblox/robase PyPI typosquat cluster (May 29 2026)
    # 52 packages impersonating Roblox API / database helper libs.
    # All confirmed by individual OSV MAL-2026-* records (active, not withdrawn).
    "api-analysis": {"0.0.8"},
    "api-feature": {"0.0.8"},
    "bloxy-api": {"3.4.0"},
    "core-roblox-utils": {"2.4.0"},
    "database-roblox": {"0.0.1"},
    "databaselooks": {"0.0.4"},
    "databasenaps": {"0.0.4", "0.0.5"},
    "databaseroboat": {"0.0.1", "0.0.2"},
    "databaseroboats": {"0.0.3", "0.0.4"},
    "databaserobooms": {"0.0.4"},
    "databaserotacos": {"0.0.4"},
    "databasesupalake": {"1.2.0"},
    "databasesupasafe": {"1.0.0", "1.2.0"},
    "databasetapes": {"0.0.4"},
    "databasetrace": {"0.0.5", "0.0.6", "0.0.7"},
    "pycolorlib001": {"0.0.1"},
    "pycolorlib3": {"0.0.4", "0.0.5"},
    "quicksolving": {"2.3.0"},
    "quicktestybesty": {"2.3.0"},
    "rblx-api": {"2.6.0"},
    "rblx-http": {"2.4.0"},
    "rblx-https": {"2.4.0"},
    "rblx-studio-api": {"2.6.0", "2.7.0", "2.8.0"},
    "ro-db": {"2.4.0"},
    "robase": {"2.1.0", "2.2.0"},
    "robase-api": {"2.4.0", "2.6.0"},
    "robase-apis": {"2.4.0"},
    "robase-app": {"2.1.0", "3.4.0"},
    "robase-dnb": {"2.4.0"},
    "robase-fallback": {"2.2.0", "2.4.0"},
    "robase-fast-install": {"2.3.0"},
    "robase-gui": {"2.3.0"},
    "robase-gui-api": {"2.3.0"},
    "robase-help": {"0.0.9"},
    "robase-install": {"2.1.0"},
    "robase-installer": {"2.2.0"},
    "robase-library-quick-install": {"2.3.0", "2.4.0", "2.5.0"},
    "robase-quick-install": {"2.6.0"},
    "robase-setup": {"2.0.0", "2.1.0", "2.2.0", "2.3.0"},
    "robase-start": {"2.4.0"},
    "robase-ui": {"2.3.0"},
    "robase-utils": {"2.3.0"},
    "roboat-addition": {"0.0.1"},
    "roboat-additions": {"0.0.1"},
    "roboat-utilities": {"2.1.0"},
    "roboat-utils": {
        "1.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0",
        "2.6.0", "2.7.0", "2.8.0", "2.9.0", "3.0.0",
    },
    "roboats-addition": {"0.0.1"},
    "rogiant": {"2.4.0"},
    "rogiant-install": {"2.5.0"},
    "rogiant-quick-install": {"2.4.0"},
    "rosolver": {"0.0.1"},
    "rostilesolver": {"2.4.0"},
    # modulebuild3240234t PyPI Roblox infostealer (May 29 2026)
    # Exfiltrates Roblox session data and credentials on import.
    # OSV MAL-2026-5029 (active, confirmed by kam193 / bad-packages.kam193.eu)
    "modulebuild3240234t": {"1.0.0", "1.0.1", "2.0.0", "3.0.0"},
    # polymarket-data PyPI crypto/credentials infostealer (May 30 2026)
    # Exfiltrates cryptocurrency-related data and API keys; establishes persistence.
    # Likely a typosquat of polymarket-data-fetcher. Specific malicious versions only.
    # OSV MAL-2026-5086 (active, confirmed by kam193 / bad-packages.kam193.eu)
    "polymarket-data": {"2.0.0", "2.0.1"},
    # crypto-helper / cryptolock / obfuscation PyPI install-time malware batch (May 30–31 2026)
    # All three tamper with security settings and download + execute a malicious executable
    # during pip install. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5088 (crypto-helper), MAL-2026-5089 (cryptolock), MAL-2026-5100 (obfuscation)
    # obfuscation: part of same 2026-05-cryptolock campaign; VirusTotal confirms setup.py backdoor
    # with IOC URLs pointing to seIfrighteous/x GitHub releases and tmpfiles.org executables.
    "crypto-helper": {"1.0.0"},
    "cryptolock": {"1.0.0", "1.0.1"},
    "obfuscation": {"3.23.0", "3.23.2", "3.23.3"},
    # discord-ban / discord-massban PyPI browser-credential infostealers (May 30–31 2026)
    # Both steal credentials, credit cards, and browsing history from web browsers.
    # Part of the same 2026-05-discord-ban campaign; detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5091 (discord-ban), MAL-2026-5099 (discord-massban)
    "discord-ban": {"1.0.0", "1.0.1", "1.0.2"},
    "discord-massban": {"0.1.0"},
    # neuralforge-ml PyPI env-variable exfiltrator (May 30 2026)
    # Stub package imitating a real ML library; version 0.9.9 adds obfuscated
    # exfiltration of environment variables. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5090
    "neuralforge-ml": {"0.9.9"},
    # h4xupdate / hell-cipher PyPI malware batch (May 31 2026)
    # h4xupdate: remote-control tool taking orders from a hardcoded Telegram bot;
    # impersonates a legitimate company. OSV MAL-2026-5093
    # hell-cipher: tampers with security settings during install and downloads + executes
    # a malicious executable. OSV MAL-2026-5094
    "h4xupdate": {"0.0.1"},
    "hell-cipher": {"1.0.1"},
    # cscc-glass-house PyPI cloud-credential exfiltrator (May 31 2026)
    # Exfiltrates credentials from cloud environments to a hardcoded location;
    # analyst notes suggest possible CTF origin but intent is clearly malicious.
    # OSV MAL-2026-5096 / https://bad-packages.kam193.eu/pypi/package/cscc-glass-house
    "cscc-glass-house": {"1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # redteam-qxz7-utils PyPI malware (June 1 2026)
    # Malicious code detected by kam193 / bad-packages.kam193.eu; single version published.
    # OSV MAL-2026-5120
    "redteam-qxz7-utils": {"1.0.0"},
    # imgmatrix-analysis PyPI remote-command executor (June 1 2026)
    # Executes remote commands during import; 10 versions published before takedown.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5123
    "imgmatrix-analysis": {
        "0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4",
        "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9",
    },
    # parsimonius PyPI RAT (June 2 2026)
    # Typosquat of the legitimate parsimonious PEG-parser library; all published
    # versions are clones of the real package with an injected RAT that takes orders
    # via a hardcoded Telegram bot and exfiltrates environment variables. The payload
    # is geo-filtered to skip systems whose timezone or geolocation suggests Russia.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5151
    "parsimonius": {
        "0.10.0", "0.11.0", "0.11.1", "0.11.2", "0.11.3",
        "0.11.4", "0.11.5", "0.11.6", "0.12.0",
    },
    # quant-backtest-helpers / bt-signal-utils PyPI env-variable / cloud-token exfiltrator campaign (June 2 2026)
    # During import, exfiltrates environment variables and cloud tokens to a hardcoded
    # ngrok endpoint (disrupt-evasive-sterility.ngrok-free.app). Targets quantitative
    # finance / backtesting developers with cloud credentials in their environment.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5152
    "quant-backtest-helpers": {"1.0.1"},
    # OSV MAL-2026-5160 — same campaign (2026-06-quant-backtest-helpers)
    "bt-signal-utils": {"1.0.0", "1.0.1"},
    # jules-test-utils PyPI host-info exfiltrator (June 2 2026)
    # Single-purpose recon package: installing or importing the module exfiltrates basic
    # information about the host. No other functionality. Detected by kam193.
    # OSV MAL-2026-5167 / https://bad-packages.kam193.eu/pypi/package/jules-test-utils
    "jules-test-utils": {"0.1.0"},
    # spaysrbdata / spaysdata PyPI Roblox-cookie infostealer campaign (June 2 2026)
    # Both packages exfiltrate Roblox session cookies from the victim machine.
    # Same campaign (2026-06-spaysrbdata); reported by kam193.
    # OSV MAL-2026-5170 / https://bad-packages.kam193.eu/pypi/package/spaysrbdata
    "spaysrbdata": {"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0"},
    # OSV MAL-2026-5171 / https://bad-packages.kam193.eu/pypi/package/spaysdata
    "spaysdata": {"0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.4.2", "0.4.4", "0.4.5"},
    # spadata PyPI Roblox-cookie infostealer (June 3 2026)
    # Same campaign (2026-06-spaysrbdata); exfiltrates Roblox session cookies.
    # OSV MAL-2026-5173 / https://bad-packages.kam193.eu/pypi/package/spadata
    "spadata": {"0.1.0", "0.1.1"},
    # internal-tracker PyPI host-info exfiltrator (June 3 2026)
    # Overrides setup.py install command to exfiltrate basic host info (IP, username) on install.
    # OSV MAL-2026-5176 / https://bad-packages.kam193.eu/pypi/package/internal-tracker
    "internal-tracker": {"0.0.1", "0.0.2", "0.0.5"},
    # fia-signals PyPI host-info exfiltrator (June 3 2026)
    # Overrides setup.py install command to exfiltrate basic host data (IP, username)
    # during installation; no other functionality. Detected by kam193.
    # OSV MAL-2026-5177 / https://bad-packages.kam193.eu/pypi/package/fia-signals
    "fia-signals": {"0.1.0", "0.1.3"},
    # tronlab / tronlabpy3 PyPI Tron/TRX private-key exfiltrators (June 3 2026)
    # Impersonate Tron blockchain tooling; designed for crypto private-key exfiltration,
    # sending stolen data to hardcoded mockapi.io / ngrok endpoints. Part of the
    # 2025-04-tronix campaign tracked by kam193.
    # OSV MAL-2026-5178 / https://bad-packages.kam193.eu/pypi/package/tronlab
    "tronlab": {"0.0.1"},
    # OSV MAL-2026-5181 / https://bad-packages.kam193.eu/pypi/package/tronlabpy3
    "tronlabpy3": {"0.0.1"},
    # hpe-glcp-automation-lib PyPI host-info exfiltrator (June 4 2026)
    # Overrides setup.py install command to exfiltrate basic host data (IP, username)
    # during installation; no other functionality. Impersonates an HPE GLCP automation
    # library. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5183
    "hpe-glcp-automation-lib": {"2.2160.0"},
    # sf-silly-goose-requests PyPI TruffleHog-based secret exfiltrator (June 4 2026)
    # Uses TruffleHog to scan the victim's environment for secrets, then exfiltrates
    # discovered credentials to a hardcoded endpoint (13.219.230.105:80/beacon).
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5184
    "sf-silly-goose-requests": {"0.1.0", "0.2.0"},
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
    # MAL-2026-3839, MAL-2026-4083, MAL-2026-4153, MAL-2026-4132, MAL-2026-4156,
    # MAL-2026-3862 (@antv/color-util)
    "@antv/g2": {"5.5.8", "5.6.8"},
    "@antv/g6": {"5.2.1", "5.3.1"},
    "@antv/l7": {"2.26.10", "2.27.10"},
    "@antv/s2": {"2.8.1", "2.9.1"},
    "@antv/x6": {"3.2.7", "3.3.7"},
    "@antv/scale": {"0.6.2", "0.7.2"},
    # @antv/color-util: both specific versions (2.1.6, 2.2.6) and SEMVER >=0 range in OSV;
    # per SKILLS.md the combination means the whole package is malicious — use empty-set wildcard.
    # OSV MAL-2026-3862 / GHSA-rh6v-hwr4-6jcp (ghsa-malware + amazon-inspector + google-open-source-security)
    "@antv/color-util": set(),
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
    # msc-terminal npm infostealer (May 27 2026)
    # Pure-malware any-version package; OSV affected.ranges is >=0.
    # OSV MAL-2026-4823.
    "msc-terminal": set(),
    # polymarket-clob-client compromise (May 26 2026)
    # Specific malicious version of the official Polymarket CLOB npm client.
    # OSV MAL-2026-4643.
    "polymarket-clob-client": {"2.1.1"},
    # Dependency-confusion 99.x campaign (May 27 2026)
    # High-version packages published to the public registry to shadow private
    # internal packages in CI pipelines. OSV MAL-2026-4424, 4543, 4830, 4831, 4832
    "@remitee-money-transfer/rmt-base": {
        "99.99.99", "99.99.100", "99.99.102", "99.99.104",
    },
    "customerdigital-ui-containers-lib": set(),  # >=0 wildcard (OSV MAL-2026-4543)
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
    "@luke-101141/nobody": {"1.0.1"},
    "wallet-agent-ai-radix": {"1.0.0"},
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
    # vpmdhaj OpenSearch/CI typosquat cluster (May 28, 2026)
    # A single threat actor (alias vpmdhaj, a39155771@gmail.com) published 14
    # malicious packages within a four-hour window, typosquatting OpenSearch,
    # ElasticSearch, DevOps, and environment-config libraries. All packages spoof
    # the upstream opensearch-project repository metadata in package.json to appear
    # legitimate. Postinstall stager deploys a ~195 KB Bun-compiled second-stage
    # payload that harvests AWS credentials, HashiCorp Vault tokens, and CI/CD
    # pipeline secrets. Packages were removed from the registry; no prior legitimate
    # versions exist — use the empty-set wildcard.
    # Microsoft Threat Intelligence (primary disclosure, versions enumerated):
    #   microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/
    # GBHackers (independent corroboration):
    #   gbhackers.com/typosquatted-npm-packages/
    "@vpmdhaj/devops-tools": set(),
    "@vpmdhaj/elastic-helper": set(),
    "@vpmdhaj/opensearch-setup": set(),
    "@vpmdhaj/search-setup": set(),
    "app-config-utility": set(),
    "elastic-opensearch-helper": set(),
    "env-config-manager": set(),
    "opensearch-config-utility": set(),
    "opensearch-security-scanner": set(),
    "opensearch-setup": set(),
    "opensearch-setup-tool": set(),
    "search-cluster-setup": set(),
    "search-engine-setup": set(),
    "vpmdhaj-opensearch-setup": set(),
    # oob-moika-tech dependency-confusion + Roblox-adjacent npm cluster (May 29 2026)
    # Internal-package-name dependency-confusion (@databus-service-ui, @service-suppliers,
    # @service-user-notifications, @polka-ui, @pulse-web-platform-core, @loans) plus nemo-reporter.
    # All confirmed by individual OSV MAL-2026-* records (active, not withdrawn).
    "@databus-service-ui/scroll-up-content": set(),
    "@databus-service-ui/ui-event": set(),
    "@loans/vehicles-api": set(),
    "@polka-ui/config": {"9.9.11"},
    "@polka-ui/loader": set(),
    "@polka-ui/reco": set(),
    "@polka-ui/recoc": set(),
    "@pulse-web-platform-core/scripts-loader": set(),
    "@service-suppliers/fetch-suppliers-watcher-saga": set(),
    "@service-suppliers/fetch_suppliers_action_saga": set(),
    "@service-suppliers/reset_country_list": set(),
    "@service-suppliers/select-supplier-watcher-saga": set(),
    "@service-suppliers/set_selected_supplier": set(),
    "@service-suppliers/set_suppliers_data": set(),
    "@service-suppliers/set_suppliers_loading_start": set(),
    "@service-suppliers/set_suppliers_loading_stop": set(),
    "@service-suppliers/suppliers": set(),
    "@service-user-notifications/set_notifications_not_removable": set(),
    "nemo-reporter": {"1.8.3"},
    # oob-moika-tech Wave 2 npm dependency-confusion cluster (May 29 2026)
    # Same actor (npm user t-in-one, nath.dr4k3@gmail.com) and C2 (oob.moika.tech) as May 28
    # Moika Tech wave. Targets the @t-in-one scope (attacker's own npm username) with 15 packages
    # impersonating private Angular DI token packages, plus two external-scope targets
    # (@capibar.chat/ui-kit and @sber-ecom-core/sberpay-widget). All 17 packages have
    # OSV affected.ranges >=0 — use empty-set wildcard.
    # OSV MAL-2026-3337 (@t-in-one/save_application_hid_to_storage, first discovery),
    # MAL-2026-5031 (@capibar.chat/ui-kit), MAL-2026-5032 (@sber-ecom-core/sberpay-widget),
    # MAL-2026-5033–5046 (remaining @t-in-one/* packages)
    # Primary source: SafeDep safedep.io/oob-moika-tech-dependency-confusion-campaign/
    "@capibar.chat/ui-kit": set(),
    "@sber-ecom-core/sberpay-widget": set(),
    "@t-in-one/add_app_middleware_token": set(),
    "@t-in-one/add_application": set(),
    "@t-in-one/add_application_service_token": set(),
    "@t-in-one/add_application_tid": set(),
    "@t-in-one/application_id_storage_key_token": set(),
    "@t-in-one/form_product_token": set(),
    "@t-in-one/get_application_hid": set(),
    "@t-in-one/only_difference_payload": set(),
    "@t-in-one/prefill_bundle_data_token": set(),
    "@t-in-one/prefill_credit_data_token": set(),
    "@t-in-one/prefill_transformers_data_token": set(),
    "@t-in-one/restore_application_hid_from_storage": set(),
    "@t-in-one/safe_local_storage_token": set(),
    "@t-in-one/save_application_hid_to_storage": set(),
    "@t-in-one/send_add_application": set(),
    # oob-moika-tech Wave 3 / EMCD-impersonation npm dep-confusion cluster (June 2 2026)
    # Attacker registered the @emcd-vue npm scope to impersonate EMCD (emcd.io), a legitimate
    # Russian cryptocurrency exchange and mining pool, distributing packages posing as internal
    # Vue.js front-end tooling. SEMVER >=0 range in all three OSV records; use empty-set wildcard.
    # Same C2 infrastructure (oob.moika.tech) and discovery source as May 28–29 oob-moika-tech waves.
    # OSV MAL-2026-5163 (@emcd-vue/auth), MAL-2026-5164 (@emcd-vue/b2b-pay-form),
    # MAL-2026-5165 (@emcd-vue/loans)
    # Source: safedep.io/oob-moika-tech-dependency-confusion-campaign/
    "@emcd-vue/auth": set(),
    "@emcd-vue/b2b-pay-form": set(),
    "@emcd-vue/loans": set(),
    # Mixed npm malware batch (May 29 2026)
    # buffer-util-extend: decodes and executes base64 payload on require/import.
    #   OSV MAL-2026-2920 / GHSA-g44v-3gq3-j8p6 (Amazon Inspector primary discovery)
    # hellowornd: generic credential stealer, any-version wildcard.
    #   OSV MAL-2026-4839 / GHSA-4f9q-ffgq-5w82
    # tiny-naturalsort: any-version wildcard.
    #   OSV MAL-2026-5030 / GHSA-mqp5-9r9w-8hg4
    # @neon-i18n/core-ui: dependency-confusion package at inflated version 99.99.99.
    #   OSV MAL-2026-5027 (OpenSSF Package Analysis)
    # sorenson-webfonts: dependency-confusion package at inflated version 99.9.1.
    #   OSV MAL-2026-5028 (OpenSSF Package Analysis)
    "buffer-util-extend": set(),
    "hellowornd": set(),
    "tiny-naturalsort": set(),
    "@neon-i18n/core-ui": {"99.99.99"},
    "sorenson-webfonts": {"99.9.1"},
    # puppeteer maintainer-account compromise (May 29 2026)
    # A single malicious version published to the official puppeteer package
    # (Google's headless Chrome library, 25M+ weekly downloads). Any computer
    # with this version installed should be considered fully compromised.
    # OSV MAL-2026-5077 / GHSA-8r2f-2qg4-cv9v
    "puppeteer": {"25.0.1"},
    # Mini Shai-Hulud wave additional packages (May 2026)
    # @beproduct/nestjs-auth: every published version is infected;
    #   same Shai-Hulud postinstall bundle as @tanstack/* packages.
    #   OSV MAL-2026-3433 / GHSA-cqpw-mfqj-f2j7 (Aikido + StepSecurity)
    # @tallyui/storage-sqlite: three malicious versions in same campaign.
    #   OSV MAL-2026-3604 (Socket + Aikido + StepSecurity)
    "@beproduct/nestjs-auth": {
        "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8",
        "0.1.9", "0.1.10", "0.1.11", "0.1.12", "0.1.13", "0.1.14",
        "0.1.15", "0.1.16", "0.1.17", "0.1.18", "0.1.19",
    },
    "@tallyui/storage-sqlite": {"0.2.1", "0.2.2", "0.2.3"},
    # @antv / atool wave supplemental packages (May 19 2026)
    # Non-@antv-scope packages compromised in the same 317-package campaign.
    # Compromised versions follow the same +1-minor pattern as the @antv/* entries.
    # Sources: safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/;
    #          socket.dev/blog/antv-packages-compromised
    # OSV MAL-2026-4123 (@lint-md/cli), MAL-2026-4124 (@lint-md/core),
    # MAL-2026-4125 (@lint-md/parser), MAL-2026-4128 (ast-plugin),
    # MAL-2026-4131 (canvas-nest.js), MAL-2026-4134 (fixed-round),
    # MAL-2026-4137 (jest-date-mock), MAL-2026-4140 (jest-less-loader),
    # MAL-2026-4143 (limit-size), MAL-2026-4148 (miz), MAL-2026-4149 (onfire.js),
    # MAL-2026-4151 (relationship.js), MAL-2026-4154 (slice.js),
    # MAL-2026-4158 (word-width), MAL-2026-4159 (xmorse)
    "@lint-md/cli": {"2.1.0", "2.2.0"},
    "@lint-md/core": {"2.1.0", "2.2.0"},
    "@lint-md/parser": {"0.1.14", "0.2.14"},
    "ast-plugin": {"0.1.7", "0.2.7"},
    "canvas-nest.js": {"2.1.4", "2.2.4"},
    "fixed-round": {"1.1.2", "1.2.2"},
    "jest-date-mock": {"1.0.11", "1.1.11", "1.2.11"},
    "jest-less-loader": {"0.3.0", "0.4.0"},
    "limit-size": {"0.2.4", "0.3.4"},
    "miz": {"1.1.1", "1.2.1"},
    "onfire.js": {"2.1.1", "2.2.1"},
    "relationship.js": {"1.3.9", "1.4.9"},
    "slice.js": {"1.2.1", "1.3.1"},
    "word-width": {"1.1.1", "1.2.1"},
    "xmorse": {"1.1.0", "1.2.0"},
    # Multi-campaign dependency confusion batch (May 29–30 2026)
    # Multiple independent actors published high-version packages to public npm
    # to shadow private internal packages in CI. All have OSV affected.ranges >=0;
    # use empty-set wildcard.
    #
    # @clearpool dependency confusion (GHSA-fr5f-hf7f-p9w9 + siblings)
    # OSV MAL-2026-3056..3058
    "@clearpool/comms": set(),
    "@clearpool/streaming": set(),
    "@clearpool/table": set(),
    # Axis Communications dependency confusion
    # OSV MAL-2026-3075..3078
    "axis-abc-search-account": set(),
    "axis-abc-search-address": set(),
    "axis-notification": set(),
    # BreezeAI dependency confusion
    # OSV MAL-2026-3183, 3184, 3292, 3293
    "@breezeai-frontend/cargo-ui": set(),
    "@breezeai-frontend/tailwind-config": set(),
    "@breezeai-frontend/i18n-config": set(),
    "@breeze-ai/ui-library": set(),
    # Ally Financial dependency confusion (GHSA-2892-cpv4-xqr4 + siblings)
    # OSV MAL-2026-3289, 3290, 3295, 3296, 3298, 3299, 3301
    "@allybank/ally-sdk": set(),
    "@allyfinancial/allyfinancial-api": set(),
    "ally-antivirus": set(),
    "ally-badges": set(),
    "ally-ccapi": set(),
    "ally-eagw-identity": set(),
    "ally-json-threat-protect": set(),
    # Citigroup ICG dependency confusion (GHSA-gw7h-mv77-3wv8 + sibling)
    # OSV MAL-2026-3807, 3808
    "@citi-icg-158830/elemental-ui-react": set(),
    "@citi-icg-158830/icgds-react-css": set(),
    # ApexOmni / ApexPro crypto exchange API typosquats (GHSA-m6v2-w5cf-f85x + siblings)
    # OSV MAL-2026-3233, 3234, 3818, 3819
    "apexomni": set(),
    "apexpro": set(),
    "apexomni-node": set(),
    "apexpro-node": set(),
    # cplace software dependency confusion (GHSA-fmm7-x566-j93x + siblings)
    # OSV MAL-2026-3427, 5047, 5048
    "@cplace-workflow-fe/cf-workflow": set(),
    "@cplace-paw-fe/cf-training-extended": set(),
    "@cplace-project-planning-fe/cf-project-planning": set(),
    # RSI Community dependency confusion (GHSA-j83r-w4f8-v7m9 + sibling)
    # OSV MAL-2026-3414, 5050
    "@rsi-community/hub-schema": set(),
    "@rsi-community/hub-client-app": set(),
    # @lir-portal dependency confusion (GHSA-pvc4-pwx8-4c4g)
    # OSV MAL-2026-5049
    "@lir-portal/web-components": set(),
    # @tc-core dependency confusion
    # OSV MAL-2026-5051
    "@tc-core/provider-service": set(),
    # TimelyCare dependency confusion (GHSA-h3x2-x2gh-2hcm + siblings)
    # OSV MAL-2026-5052..5055
    "@timelycare/api": set(),
    "@timelycare/common": set(),
    "@timelycare/config-service": set(),
    "@timelycare/core": set(),
    # @trp-individual-investor-adv-disc dependency confusion
    # OSV MAL-2026-5056
    "@trp-individual-investor-adv-disc/adv-shared": set(),
    # Miscellaneous dependency-confusion and pure-malware packages (May 29–30 2026)
    # OSV MAL-2023-1274 (proton-pack, GHSA-gj36-855r-fpmf)
    # OSV MAL-2026-2909 (tailwind-typography-cssstyle)
    # OSV MAL-2026-2926 (material-ui-plugin-cache-endpoint)
    # OSV MAL-2026-3241 (nextjs-chat-with-ai-service)
    # OSV MAL-2026-3304 (apcyber-test-package)
    # OSV MAL-2026-3326 (paychex-common-vendor-lib)
    # OSV MAL-2026-3363 (mrdaa-frontend)
    # OSV MAL-2026-3645 (dit-envv), MAL-2026-3646 (erslove)
    # OSV MAL-2026-3745 (deepl-sync, GHSA-qvrg-265v-cqvc)
    # OSV MAL-2026-4254 (reactive-cdk-app), MAL-2026-4274 (power-apps)
    # OSV MAL-2026-4548 (dds-js-idl-types), MAL-2026-4612 (mmt-static)
    # OSV MAL-2026-4644 (power-platform-playwright-toolkit)
    # OSV MAL-2026-5057 (appkit-react-utils), MAL-2026-5058 (argpras)
    # OSV MAL-2026-5062 (codex-devcontainer-install, GHSA-frcf-f9wx-gq64)
    # OSV MAL-2026-5063 (customerdigital-service-lib, GHSA-9vx3-fc8v-7w96)
    # OSV MAL-2026-5071 (gcp-api-enabler), MAL-2026-5073 (midoss)
    # OSV MAL-2026-5074 (one-view-chat-ui-module), MAL-2026-5075 (ota_web_admin)
    # OSV MAL-2026-5076 (private-next-instrumentation-client, GHSA-cx3x-gvpc-g35w)
    # OSV MAL-2026-5078 (raven-i18n-react), MAL-2026-5079 (react-svg-animator)
    "proton-pack": set(),
    "tailwind-typography-cssstyle": set(),
    "material-ui-plugin-cache-endpoint": set(),
    "nextjs-chat-with-ai-service": set(),
    "apcyber-test-package": set(),
    "paychex-common-vendor-lib": set(),
    "mrdaa-frontend": set(),
    "dit-envv": set(),
    "erslove": set(),
    "deepl-sync": set(),
    "reactive-cdk-app": set(),
    "power-apps": set(),
    "dds-js-idl-types": set(),
    "mmt-static": set(),
    "power-platform-playwright-toolkit": set(),
    "appkit-react-utils": set(),
    "argpras": set(),
    "codex-devcontainer-install": set(),
    "customerdigital-service-lib": set(),
    "gcp-api-enabler": set(),
    "midoss": set(),
    "one-view-chat-ui-module": set(),
    "ota_web_admin": set(),
    "private-next-instrumentation-client": set(),
    "raven-i18n-react": set(),
    "react-svg-animator": set(),
    # ethers.js / EVM toolchain typosquat cluster (May 29–30 2026)
    # Pure-malware typosquats targeting Ethereum/EVM developers by impersonating
    # ethers.js sub-modules, Foundry, Hardhat, and viem toolchain packages.
    # All have OSV affected.ranges >=0; use empty-set wildcard.
    # OSV MAL-2026-3760 (ethers-abstract-signer, GHSA-2f7m-g9qw-8288)
    # OSV MAL-2026-3761 (ethers-signing-key)
    # OSV MAL-2026-5064 (ethers-contract, GHSA-gxfh-j6jv-hc58)
    # OSV MAL-2026-5065 (ethers-errors), MAL-2026-5066 (ethers-hash)
    # OSV MAL-2026-5067 (ethers-hdnode)
    # OSV MAL-2026-5068 (evmchain-cli), MAL-2026-5069 (evmchain-config)
    # OSV MAL-2026-5070 (foundry-config), MAL-2026-5072 (hardhat-evmchain)
    # OSV MAL-2026-5084 (viem-multichain), MAL-2026-5085 (web3-config-loader)
    "ethers-abstract-signer": set(),
    "ethers-signing-key": set(),
    "ethers-contract": set(),
    "ethers-errors": set(),
    "ethers-hash": set(),
    "ethers-hdnode": set(),
    "evmchain-cli": set(),
    "evmchain-config": set(),
    "foundry-config": set(),
    "hardhat-evmchain": set(),
    "viem-multichain": set(),
    "web3-config-loader": set(),
    # chai testing-library typosquat cluster (May 29–30 2026)
    # Fake Chai extensions; any installed version is malicious.
    # OSV MAL-2026-4513 (chai-as-tuned, GHSA-2f37-mh3q-7394)
    # OSV MAL-2026-5059 (chai-bundle, GHSA-q36r-56hw-2r46)
    # OSV MAL-2026-5060 (chai-extensions-extras), MAL-2026-5061 (chai-use-test)
    "chai-as-tuned": set(),
    "chai-bundle": set(),
    "chai-extensions-extras": set(),
    "chai-use-test": set(),
    # Tailwind CSS plugin typosquat cluster (May 29–30 2026)
    # Fake Tailwind CSS plugins; any installed version is malicious.
    # OSV MAL-2026-2909 (tailwind-typography-cssstyle — already listed above)
    # OSV MAL-2026-5080 (tailwind-clamps-line, GHSA-29g5-vw2p-x29p)
    # OSV MAL-2026-5081 (tailwind-effect), MAL-2026-5082 (tailwind-smooth-slider)
    # OSV MAL-2026-5083 (tailwindcss-basic-animation)
    "tailwind-clamps-line": set(),
    "tailwind-effect": set(),
    "tailwind-smooth-slider": set(),
    "tailwindcss-basic-animation": set(),
    # zod-to-js Zod-ecosystem typosquat (May 29 2026)
    # Impersonates a Zod-to-JS bridge library; two specific malicious versions.
    # OSV MAL-2026-4740 / GHSA-8cm2-vv7w-4c27
    "zod-to-js": {"13.4.3", "13.4.4"},
    # buffer-utilities npm malware (May 30 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # Only one version published before takedown; pin it (no >=0 range in OSV record).
    # OSV MAL-2026-5087
    "buffer-utilities": {"1.0.0"},
    # retail-location-strategy-frontend npm malware (May 30 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Two specific versions published; no >=0 range.
    # OSV MAL-2026-5092
    "retail-location-strategy-frontend": {"1.1.1", "1.1.2"},
    # @challenger6/vm-pattern-library npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5095
    "@challenger6/vm-pattern-library": {"99.0.0"},
    # cms-storehub npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5097
    "cms-storehub": {"1.3.6"},
    # js-shared-modules npm malware (May 31 2026)
    # Communicates with a domain associated with malicious activity; detected by
    # OpenSSF Package Analysis. Single version published; no >=0 range.
    # OSV MAL-2026-5098
    "js-shared-modules": {"1.11.7"},
    # CMS-dropper typosquat cluster (June 1 2026)
    # to-cms: postinstall downloads https://meet-fr.com/ChromeSetup.exe on install.
    # cms-github / cms-helpgit / shopifyto-cms: GHSA full-compromise packages in the
    # same CMS typosquat family; any installed version is treated as fully compromised.
    # OSV MAL-2026-4693 / GHSA-789x-j439-qx3f (to-cms)
    # OSV MAL-2026-5107 / GHSA-3r39-h7xh-jg85 (cms-github)
    # OSV MAL-2026-5108 / GHSA-hjw8-jc8q-mvwj (cms-helpgit)
    # OSV MAL-2026-5109 / GHSA-92q8-c63v-g77x (shopifyto-cms)
    "to-cms": set(),
    "cms-github": set(),
    "cms-helpgit": set(),
    "shopifyto-cms": set(),
    # Amazon Inspector postinstall-exfiltration batch (June 1 2026)
    # collected-forms-embed-js: postinstall hook performs recon + credential exfiltration.
    # audit-logsss: postinstall runs id/whoami/hostname, fetches public IP from external API.
    # chainix: presents as a pino-compatible logger; contains malicious postinstall payload.
    # OSV MAL-2026-4175 / GHSA-9j37-8wjm-pcxq (collected-forms-embed-js)
    # OSV MAL-2026-4487 / GHSA-gcq4-52q3-v4fm (audit-logsss)
    # OSV MAL-2026-4817 / GHSA-mrx8-p3w9-5cfm (chainix)
    "collected-forms-embed-js": set(),
    "audit-logsss": set(),
    "chainix": set(),
    # Chai typosquat cluster extension (June 1 2026)
    # Extends the existing chai-as-* / chai-bundle typosquat family.
    # OSV MAL-2026-5106 / GHSA-85px-g4cg-g2g3
    "chai-as-minted": set(),
    # AWS/CLI typosquats (June 1 2026)
    # @antoncallahan/aws-user-helper: AWS credential-helper typosquat; GHSA full-compromise.
    # @tmecontinue/cli: CLI tool impersonation package; GHSA full-compromise.
    # OSV MAL-2026-5101 / GHSA-v2cq-j5gf-pf5g (@antoncallahan/aws-user-helper)
    # OSV MAL-2026-5105 / GHSA-jq5f-g7j2-8f9g (@tmecontinue/cli)
    "@antoncallahan/aws-user-helper": set(),
    "@tmecontinue/cli": set(),
    # GHSA full-compromise test-scope packages (June 1 2026)
    # Garbage-scoped names consistent with security-research pipeline test submissions;
    # included because active OSV MAL records pass the evidence threshold.
    # OSV MAL-2026-5102 / GHSA-p4gj-2hmg-hj4f (@ewfewfewf/testhackerrr)
    # OSV MAL-2026-5103 / GHSA-rrrc-gchv-j329 (@osamdefeirrighs/testhackfrrferrr)
    # OSV MAL-2026-5104 / GHSA-xjcm-hjvm-fmhp (@pcldpvkoewpogw/testhacker)
    "@ewfewfewf/testhackerrr": set(),
    "@osamdefeirrighs/testhackfrrferrr": set(),
    "@pcldpvkoewpogw/testhacker": set(),
    # @redhat-cloud-services scope account compromise (June 1–2 2026)
    # Red Hat Cloud Services npm scope; malicious versions follow the +0.0.1-patch
    # pattern seen in prior maintainer-account-takeover waves. Additional packages
    # and supplemental versions published across June 1–2.
    # OSV MAL-2026-5111 / GHSA-942v-f47r-w9c3 (chrome)
    # OSV MAL-2026-5112 / GHSA-c3mv-fjj4-2542 (eslint-config-redhat-cloud-services)
    # OSV MAL-2026-5113 / GHSA-mrgj-mcjh-5mf2 (frontend-components)
    # OSV MAL-2026-5114 / GHSA-cxfw-p322-rfrv (frontend-components-config-utilities)
    # OSV MAL-2026-5115 / GHSA-mj98-cgm5-6xrr (quickstarts-client)
    # OSV MAL-2026-5116 / GHSA-2p99-xvqh-j893 (rbac-client)
    # OSV MAL-2026-5117 / GHSA-c4gm-6fh3-76v9 (rule-components)
    # OSV MAL-2026-5118 / GHSA-9wp8-557p-2hvf (topological-inventory-client)
    # OSV MAL-2026-5119 / GHSA-8xj2-9c64-m64h (types)
    # OSV MAL-2026-5125 / GHSA-28hc-2275-h287 (entitlements-client)
    # OSV MAL-2026-5126 / GHSA-h43w-g623-gfmv (frontend-components-config)
    # OSV MAL-2026-5127 / GHSA-4rjr-7qhx-vjwg (frontend-components-remediations)
    # OSV MAL-2026-5128 / GHSA-wgvx-w8g7-vh4h (frontend-components-testing)
    # OSV MAL-2026-5129 / GHSA-vgm5-jmvr-cjgf (hcc-feo-mcp)
    # OSV MAL-2026-5130 / GHSA-8x4g-q845-wpfc (integrations-client)
    # OSV MAL-2026-5131 / GHSA-vp9c-9mjm-2f7w (sources-client)
    # OSV MAL-2026-5133 (compliance-client)
    # OSV MAL-2026-5134 (config-manager-client)
    # OSV MAL-2026-5135 (frontend-components-advisor-components)
    # OSV MAL-2026-5136 (frontend-components-notifications)
    # OSV MAL-2026-5137 (frontend-components-translations)
    # OSV MAL-2026-5138 (frontend-components-utilities)
    # OSV MAL-2026-5139 (hcc-kessel-mcp)
    # OSV MAL-2026-5140 (hcc-pf-mcp)
    # OSV MAL-2026-5141 (host-inventory-client)
    # OSV MAL-2026-5142 (insights-client)
    # OSV MAL-2026-5143 (javascript-clients-shared)
    # OSV MAL-2026-5144 (notifications-client)
    # OSV MAL-2026-5145 (patch-client)
    # OSV MAL-2026-5146 (remediations-client)
    # OSV MAL-2026-5147 (tsc-transform-imports)
    # OSV MAL-2026-5148 (vulnerabilities-client)
    "@redhat-cloud-services/chrome": {"2.3.1", "2.3.2", "2.3.4"},
    "@redhat-cloud-services/compliance-client": {"4.0.3", "4.0.4", "4.0.6"},
    "@redhat-cloud-services/config-manager-client": {"5.0.4", "5.0.5", "5.0.7"},
    "@redhat-cloud-services/entitlements-client": {"4.0.11", "4.0.12", "4.0.14"},
    "@redhat-cloud-services/eslint-config-redhat-cloud-services": {"3.2.1", "3.2.2", "3.2.4"},
    "@redhat-cloud-services/frontend-components": {"7.7.2", "7.7.3", "7.7.5"},
    "@redhat-cloud-services/frontend-components-advisor-components": {"3.8.2", "3.8.4", "3.8.6"},
    "@redhat-cloud-services/frontend-components-config": {"6.11.3", "6.11.4", "6.11.6"},
    "@redhat-cloud-services/frontend-components-config-utilities": {"4.11.2", "4.11.3", "4.11.5"},
    "@redhat-cloud-services/frontend-components-notifications": {"6.9.2", "6.9.3", "6.9.5"},
    "@redhat-cloud-services/frontend-components-remediations": {"4.9.2", "4.9.3", "4.9.5"},
    "@redhat-cloud-services/frontend-components-testing": {"1.2.1", "1.2.2", "1.2.4"},
    "@redhat-cloud-services/frontend-components-translations": {"4.4.1", "4.4.2", "4.4.4"},
    "@redhat-cloud-services/frontend-components-utilities": {"7.4.1", "7.4.2", "7.4.4"},
    "@redhat-cloud-services/hcc-feo-mcp": {"0.3.1", "0.3.2", "0.3.4"},
    "@redhat-cloud-services/hcc-kessel-mcp": {"0.3.1", "0.3.2", "0.3.4"},
    "@redhat-cloud-services/hcc-pf-mcp": {"0.6.1", "0.6.2", "0.6.4"},
    "@redhat-cloud-services/host-inventory-client": {"5.0.3", "5.0.4", "5.0.6"},
    "@redhat-cloud-services/insights-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/integrations-client": {"6.0.4", "6.0.5", "6.0.7"},
    "@redhat-cloud-services/javascript-clients-shared": {"2.0.8", "2.0.9", "2.0.11"},
    "@redhat-cloud-services/notifications-client": {"6.1.4", "6.1.5", "6.1.7"},
    "@redhat-cloud-services/patch-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/quickstarts-client": {"4.0.11", "4.0.12", "4.0.14"},
    "@redhat-cloud-services/rbac-client": {"9.0.3", "9.0.4", "9.0.6"},
    "@redhat-cloud-services/remediations-client": {"4.0.4", "4.0.5", "4.0.7"},
    "@redhat-cloud-services/rule-components": {"4.7.2", "4.7.3", "4.7.5"},
    "@redhat-cloud-services/sources-client": {"3.0.10", "3.0.11", "3.0.13"},
    "@redhat-cloud-services/topological-inventory-client": {"3.0.10", "3.0.11", "3.0.13"},
    "@redhat-cloud-services/tsc-transform-imports": {"1.2.2", "1.2.4", "1.2.6"},
    "@redhat-cloud-services/types": {"3.6.1", "3.6.2", "3.6.4"},
    "@redhat-cloud-services/vulnerabilities-client": {"2.1.8", "2.1.9", "2.1.11"},
    # loading-session npm package compromise (June 1 2026)
    # Session-management package with malicious code injected; OSV reports both
    # specific versions and a >=0 range — per convention, entire package is malicious.
    # OSV MAL-2026-4600 / GHSA-7vwr-8v2c-gjvr
    "loading-session": set(),
    # jingmeideshishi npm throwaway malware (June 1 2026)
    # Gibberish-name pure-malware package; OSV confirmed any-version malicious.
    # OSV MAL-2026-5110 / GHSA-pc3j-w4f9-94hj
    "jingmeideshishi": set(),
    # Amazon Inspector npm malware batch (June 1 2026)
    # xarc-webpack-cli: preinstall hook with malicious payload; typosquat of @xarc/webpack-cli.
    # json-to-simple-graphql-schema: contains poc.js script with malicious code.
    # motion-tool: masquerades as pino logger; any-version malicious.
    # randomlogs: main module carries malicious code across multiple versions.
    # All four have OSV affected.ranges >=0 (any-version); use empty-set wildcard.
    # OSV MAL-2026-4352 / GHSA-2xcr-5qfc-fq54 (xarc-webpack-cli)
    # OSV MAL-2026-4590 / GHSA-2qqv-9mw5-52q2 (json-to-simple-graphql-schema)
    # OSV MAL-2026-4615 / GHSA-hw79-5457-g9c3 (motion-tool)
    # OSV MAL-2026-4657 / GHSA-6x8j-5cx8-5qv6 (randomlogs)
    "xarc-webpack-cli": set(),
    "json-to-simple-graphql-schema": set(),
    "motion-tool": set(),
    "randomlogs": set(),
    # Dependency-confusion 9999.x batch (June 1 2026)
    # nepsnowplow: targets Snowplow Analytics internal CI; high-version shadow package.
    # picnic-react-mise-en-place: targets Picnic internal React packages in CI.
    # Detected by OpenSSF Package Analysis; specific malicious version pinned (no >=0 range).
    # OSV MAL-2026-5121 (nepsnowplow), MAL-2026-5122 (picnic-react-mise-en-place)
    "nepsnowplow": {"9999.0.0"},
    "picnic-react-mise-en-place": {"9999.0.0"},
    # @chat-template/auth GHSA full-compromise (June 1 2026)
    # Any installed version is malicious; OSV affected.ranges >=0.
    # OSV MAL-2026-5124 / GHSA-5jx8-qv7v-hv32
    "@chat-template/auth": set(),
    # rookie-security-test-pkg npm malware (June 1 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # Single version published; specific version pinned (no >=0 range in OSV record).
    # OSV MAL-2026-5132
    "rookie-security-test-pkg": {"1.0.0"},
    # Dependency-confusion 99.x batch (June 2 2026)
    # @aonunited/angular: high-version (99.0.1) shadow package targeting AON United's
    #   internal Angular component library in CI; detected by OpenSSF Package Analysis
    #   communicating with a domain associated with malicious activity.
    #   OSV MAL-2026-5150
    # @att-ebiz/abs-components-bc: high-version (99.9.1) shadow package targeting AT&T
    #   eBusiness ABS Components BC library in CI; same detection pattern.
    #   OSV MAL-2026-5153
    "@aonunited/angular": {"99.0.1"},
    "@att-ebiz/abs-components-bc": {"99.9.1"},
    # Scandinavian telecom dep-confusion npm cluster (June 2 2026)
    # Actor debating0166 published four packages to the public registry using inflated version
    # numbers (99.0.x) to override private packages used by Telenor SE, Ownit, Customer 360
    # (C360), and TSE Digital. No prior legitimate versions exist; SEMVER >=0 range in all four
    # OSV records — use empty-set wildcard.
    # OSV MAL-2026-5154 (@customer-threesixty/assets), MAL-2026-5155 (@ownit/core),
    # MAL-2026-5156 (@telenor-se/core), MAL-2026-5157 (@tse-digital/core)
    "@customer-threesixty/assets": set(),
    "@ownit/core": set(),
    "@telenor-se/core": set(),
    "@tse-digital/core": set(),
    # Dep-confusion 99.x npm batch (June 2 2026)
    # Three packages detected by OpenSSF Package Analysis communicating with domains
    # associated with malicious activity and executing malicious commands.
    # page-info-service and po-ops-local-dev use version 99.9.1 (high-version shadow pattern).
    # sourceflow-tracker uses version 99.91.9; same detection pattern.
    # OSV MAL-2026-5158 (page-info-service), MAL-2026-5159 (po-ops-local-dev),
    # MAL-2026-5166 (sourceflow-tracker)
    "page-info-service": {"99.9.1"},
    "po-ops-local-dev": {"99.9.1"},
    "sourceflow-tracker": {"99.91.9"},
    # vg-interaction-model dep-confusion (June 2 2026; updated June 3 2026)
    # Detected by OpenSSF Package Analysis executing malicious commands; high-version shadow
    # packages (40.0.1, 40.0.4) typical of dep-confusion attacks. Both versions communicate
    # with a domain associated with malicious activity and execute malicious commands.
    # OSV MAL-2026-5168
    "vg-interaction-model": {"40.0.1", "40.0.4"},
    # chai-parse Chai typosquat (June 2 2026)
    # GHSA-confirmed any-version malware: "Any computer that has this package installed or
    # running should be considered fully compromised." OSV affected.ranges >=0 — use
    # the empty-set wildcard so any re-uploaded version is caught.
    # OSV MAL-2026-5169
    "chai-parse": set(),
    # fundraiserserv npm malware (June 3 2026)
    # Detected by OpenSSF Package Analysis communicating with a domain associated with
    # malicious activity. Single malicious version pinned (no >=0 range in OSV record).
    # OSV MAL-2026-5172
    "fundraiserserv": {"1.0.0"},
    # nodemon-pack / webpack-json npm typosquats (June 3 2026)
    # Full-compromise typosquats (of nodemon and webpack); GHSA flags any installed
    # version as fully malicious. SEMVER >=0 range in OSV — use empty-set wildcard.
    # OSV MAL-2026-5174 / GHSA-pqxq-jw84-3x8f (nodemon-pack)
    # OSV MAL-2026-5175 / GHSA-69hx-wrc9-h5wq (webpack-json)
    "nodemon-pack": set(),
    "webpack-json": set(),
    # chai-midpatch / nodemon-webpatch npm full-compromise typosquats (June 3 2026)
    # Both carry SEMVER >=0 range: "Any computer that has this package installed or
    # running should be considered fully compromised." chai-midpatch continues the
    # Chai-typosquat campaign (cf. chai-parse); nodemon-webpatch continues the
    # nodemon-typosquat wave (cf. nodemon-pack).
    # OSV MAL-2026-5179 / GHSA-qq87-jvv3-6c7r (chai-midpatch)
    # OSV MAL-2026-5180 / GHSA-q398-93fh-ghmj (nodemon-webpatch)
    "chai-midpatch": set(),
    "nodemon-webpatch": set(),
    # brave-search-mcp-server npm malware (June 3 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package
    # Analysis. Single version published; specific version pinned (no >=0 range).
    # OSV MAL-2026-5182
    "brave-search-mcp-server": {"1.0.0"},
    # June 4 2026 npm full-compromise batch (ghsa-malware source)
    # Three packages reported via GitHub Advisory Database automated malware detection.
    # All three carry SEMVER >=0 range ("any installed version fully compromised");
    # no specific versions enumerated by the reporters.
    # @jagreehal/workflow: obscure workflow-automation package; SEMVER >=0.
    #   OSV MAL-2026-5185 / GHSA-6w7v-23mf-65g3
    "@jagreehal/workflow": set(),
    # autotel-terminal: terminal-utility package; SEMVER >=0.
    #   OSV MAL-2026-5186 / GHSA-cw9v-v9rh-r449
    "autotel-terminal": set(),
    # supabase (npm): the official Supabase CLI. Advisory was filed on June 4 2026
    # (the same day version 2.105.0 was published from the supabase/cli GitHub Actions
    # pipeline). GHSA source, single reporter, SEMVER >=0 — no specific compromised
    # version enumerated. Gate: active OSV MAL record, not withdrawn.
    # OSV MAL-2026-5187 / GHSA-x96m-c5fj-q75c
    "supabase": set(),
}

# npm scopes hit in this campaign. Exact versions are pinned above; any
# additional package in these scopes still triggers a manual-review warning
# in case the advisory expands.
NPM_SUSPECT_SCOPES = (
    "@mistralai/", "@uipath/", "@opensearch-project/", "@antv/",
    # Moika Tech dependency confusion scopes (May 28 2026)
    "@car-loans/", "@cloudplatform-single-spa/",
    "@debit-ib/", "@fb-deposit/", "@mlspace/",
    # vpmdhaj typosquat cluster (May 28 2026) — entire scope is malicious
    "@vpmdhaj/",
    # oob-moika-tech Wave 2 (May 29 2026) — attacker's own npm username scope
    "@t-in-one/",
    # Red Hat Cloud Services account compromise (June 1 2026)
    "@redhat-cloud-services/",
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
    # crates.io dep-confusion batch (April 2026, ingested ossf/malicious-packages May 31 2026)
    # High-version (99.x) packages published to the public registry to hijack internal CI
    # dependency resolution. All detected by OpenSSF Package Analysis as communicating with
    # domains associated with malicious activity and executing malicious commands.
    # OSV MAL-2026-3101 (amzn-consolas-client), MAL-2026-3102 (semantic-search-client),
    # MAL-2026-3103 (amzn-codewhisperer-streaming-client),
    # MAL-2026-3126 (lsh), MAL-2026-3129 (supertag)
    "amzn-consolas-client": {"99.0.1"},
    "amzn-codewhisperer-streaming-client": {"99.0.1"},
    "semantic-search-client": {"99.0.1"},
    "lsh": {"99.0.1", "99.1.0"},
    "supertag": {"99.1.1"},
    # exploration remote-execute dropper (June 2 2026)
    # A method within the crate attempted to download and execute a payload from
    # a remote site; 1 version published ~1 hour before removal. Any version is
    # malicious (ranges: introduced 0.0.0-0, patched = []).
    # RUSTSEC-2026-0155; reported by Socket Threat Research Team.
    "exploration": set(),
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
