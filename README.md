# compromised-packages-check

A single-file Python scanner that flags known-malicious package versions from
recent npm, PyPI, and crates.io supply-chain compromises in any repository.

Pure stdlib. No dependencies. Drop into CI or run locally.

## Usage

```bash
python3 check_compromised_packages.py [path]   # defaults to current dir
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | clean |
| `1` | at least one malicious package version found |
| `2` | usage error |

The scanner walks the tree (skipping `node_modules`, `.venv`, `.git`,
`target`, `dist`, `build`, etc.) and parses:

- **npm:** `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock`,
  `pnpm-lock.yaml`
- **PyPI:** `requirements*.txt`, `pyproject.toml`, `Pipfile`,
  `Pipfile.lock`, `poetry.lock`, `setup.py`
- **crates.io:** `Cargo.toml` (inline, table, sub-table, and
  target-prefixed dependency forms), `Cargo.lock` (only entries sourced
  from the crates.io registry — path/git dependencies are skipped)

Output:

```
FOUND 3 MALICIOUS PACKAGE VERSION(S):
  [npm]       @tanstack/react-router@1.169.8  (web-app/package-lock.json)
  [pypi]      durabletask@1.4.2               (requirements.txt)
  [crates.io] rustdecimal@0.5.0               (Cargo.lock)

1 package(s) in advisory-affected scopes (verify versions manually):
  @uipath/new-pkg@0.0.1  (services/foo/package.json)
```

The scanner also emits a warning (no failure) for any package living under
an advisory-affected npm scope (`@mistralai/`, `@uipath/`, `@opensearch-project/`,
`@antv/`, `@car-loans/`, `@cloudplatform-single-spa/`, `@debit-ib/`, `@fb-deposit/`,
`@mlspace/`, `@vpmdhaj/`, `@t-in-one/`, `@redhat-cloud-services/`) where the version doesn't exactly match the malicious list —
useful for catching newly-disclosed entries before this repo has been updated.

## What's tracked

| Wave | Scope / Packages |
| --- | --- |
| September 8 2025 Qix phishing attack — chalk/debug/color/ansi npm ecosystem | 19 packages with >2B combined weekly downloads: `chalk` 5.6.1; `debug` 4.4.2; `color` 5.0.1; `color-name` 2.0.1; `color-convert` 3.1.1; `color-string` 2.1.1; `error-ex` 1.3.3; `ansi-regex` 6.2.1; `strip-ansi` 7.1.1; `ansi-styles` 6.2.2; `wrap-ansi` 9.0.1; `backslash` 0.2.1; `is-arrayish` 0.3.3; `simple-swizzle` 0.2.3; `supports-color` 10.2.1; `slice-ansi` 7.1.1; `has-ansi` 6.0.1; `chalk-template` 1.1.1; `supports-hyperlinks` 4.1.1 — browser-based crypto-wallet address interceptor injected via phished maintainer account (npmjs.help phishing); live ~2.5 h before removal |
| September 15 2025 Shai-Hulud worm — @ctrl/tinycolor / ngx-bootstrap wave | `@ctrl/tinycolor` 4.1.1, 4.1.2 (OSV MAL-2025-47141); `ngx-bootstrap` 18.1.4, 19.0.3–19.0.4, 20.0.3–20.0.6 (GHSA-6m4g-vm7c-f8w6 / MAL-2025-47197) — self-propagating credential stealer (postinstall bundle.js harvests npm/GitHub/cloud tokens and republishes infected versions); ultimately spread to 582 compromised versions across 194 packages |
| CanisterSprawl / TeamPCP npm worm — April 8–22 2026 | `@fairwords/websocket` 1.0.38–1.0.39; `@fairwords/loopback-connector-es` 1.4.3–1.4.4 (April 8); `pgserve` 1.1.11–1.1.13; `@automagik/genie` 4.260421.33–4.260421.40; `@openwebconcept/theme-owc` 1.0.1–1.0.3; `@openwebconcept/design-tokens` 1.0.1–1.0.3 (April 21–22) — self-propagating ICP-canister credential stealer |
| @velora-dex/sdk registry-only compromise — April 7 2026 | `@velora-dex/sdk` 9.4.1 — Go RAT (minirat) + macOS launchctl persistence injected into dist/index.js without GitHub commit |
| DevTap user0001 typosquat cluster — April–May 2026 | `centralogger`, `connector-agent`, `dom-utils-lite`, `node-env-resolve`, `node-fetch-lite`, `node-gyp-runtime` — any-version (six packages, single throwaway account, SSH-key backdoor + Windows RAT + browser-history theft) |
| xinference PyPI TeamPCP compromise — April 22 2026 | `xinference` 2.6.0–2.6.2 — 600k-download AI-inference framework; obfuscated base64 infostealer exfiltrates cloud/SSH/K8s credentials on import |
| dYdX — January 27 2026 (PYSEC-2026-1) | `@dydxprotocol/v4-client-js` 3.4.1, 1.22.1, 1.15.2, 1.0.31 (npm); `dydx-v4-client` 1.1.5.post1 (PyPI) |
| TeamPCP / Trivy cascade — March 2026 (GHSA-5mg7-485q-xm76, GHSA-955r-262c-33jc) | `litellm` 1.82.7, 1.82.8; `telnyx` 4.87.1, 4.87.2 (PyPI) |
| elementary-data — April 24 2026 | `elementary-data` 0.23.3 (PyPI) — GitHub Actions script-injection |
| TanStack — May 2026 (GHSA-g7cv-rxg3-hmpx, CVE-2026-45321) | 42 `@tanstack/*` packages, 84 versions |
| Mini Shai-Hulud — May 2026 | `@mistralai/mistralai`, `@mistralai/mistralai-gcp`, `@mistralai/mistralai-azure`; `@opensearch-project/opensearch`; 66 `@uipath/*` packages; `@squawk/{mcp,weather,flightplan}`; `@tallyui/connector-{medusa,vendure}` |
| @antv / atool mass wave — May 19 2026 (317 packages, 631 versions) | `@antv/{g2,g6,l7,s2,x6,scale}`, `size-sensor`, `echarts-for-react`, `timeago.js` (high-impact subset); rest covered by `@antv/` suspect scope |
| node-ipc — May 14 2026 (GHSA-g7cv-rxg3-hmpx) | `node-ipc` 9.1.6, 9.2.3, 12.0.1 |
| @bitwarden/cli — April 22 2026 (GHSA-g98r-qjhg-4fmr) | `@bitwarden/cli` 2026.4.0 |
| axios — March 31 2026 (GHSA-fw8c-xr5c-95f9, Sapphire Sleet / DPRK) | `axios` 0.30.4, 1.14.1; `plain-crypto-js` 4.2.0, 4.2.1 |
| PyPI — May 2026 | `durabletask` 1.4.1 – 1.4.3, `mistralai` 2.4.6, `guardrails-ai` 0.10.1 |
| PyTorch Lightning — April 30 2026 (GHSA-w37p-236h-pfx3, CVE-2026-44484) | `pytorch-lightning` 2.6.2, 2.6.3 |
| intercom-client — April 30 2026 (GHSA-54pg-9963-v8vg) | `intercom-client` 7.0.4 (npm) — maintainer credential compromise, Shai-Hulud campaign |
| @cap-js / mbt — April 2026 | `@cap-js/sqlite` 2.2.2, `@cap-js/postgres` 2.2.2, `@cap-js/db-service` 2.10.1, `mbt` 1.2.48 |
| TrapDoor crypto-stealer — May 22 2026 | 21 npm typosquats (`async-pipeline-builder`, `build-scripts-utils`, `chain-key-validator`, …) flagged any-version; 7 PyPI typosquats (`eth-security-auditor`, `cryptowallet-safety`, `defi-risk-scanner`, `solidity-build-guard` @ 0.1.0; `data-pipeline-check`, `env-loader-cli`, `git-config-sync` @ 0.1.0, 0.1.1); 6 crates.io build.rs droppers (`move-analyzer-build`, `move-compiler-tools`, `move-project-builder`, `sui-framework-helpers`, `sui-move-build-helper`, `sui-sdk-build-utils`) targeting Sui/Move developers |
| Multi-cluster npm typosquat wave — May 25 2026 | 25 malicious-from-creation npm packages across 5 sub-clusters: 6 `ts-*` utilities (`ts-stream-compose`, `ts-result-pipe`, `ts-typeguard-utils`, `ts-config-mapper`, `ts-iter-utils`, `ts-schema-config`); 3 `@gbrlxvii/ts-*`; 6 `auth0-*` SDK typosquats; 2 `webservices.rest*`; 2 `vite-plugin-env-compat*`; 6 miscellaneous (`fivem-monitor`, `jules-standard`, `internallib_v95`, `chai-as-redeploy`, `expo-config-plugin-typescript`, `unique-string-64`) |
| toskypi npm RAT/infostealer — May 25 2026 (MAL-2026-4345, MAL-2026-4346) | `eo-terminal`, `logger-draft` (npm) — multi-platform RAT + infostealer disguised as terminal/logger utilities; second-stage from HuggingFace; C2 ws://195.201.194.107:8010 |
| CLOB IPFS dropper — May 26 2026 (MAL-2026-4347–4350) | `@devcarron/clob`, `api-rs-node`, `clob.api`, `clobprice.api` (npm) — DeFi/CLOB-API typosquats fetching Windows executable via IPFS; registry persistence; C2 45.8.22.112:2026 |
| DPRK js-logger-pack / terminal-logger-utils cluster — April–May 2026 (OSV MAL-2026-2827) | `js-logger-pack` (23 versions, any-version), `terminal-logger-utils`, `pretty-logger-utils`, `ts-logger-pack`, `pinno-loggers` (npm) — multi-stage dropper + infostealer + RAT; HuggingFace second-stage; targets Telegram sessions, SSH keys, crypto wallets, cloud credentials |
| Leaked Shai-Hulud / deadcode09284814 cluster — May 26 2026 | `chalk-tempalte` (Shai-Hulud worm clone), `@deadcode09284814/axios-util` (credential stealer), `axois-utils` (Phantom Bot DDoS botnet), `color-style-utils` (wallet/credential stealer) — any-version |
| Nx build-system supply-chain compromise — May 27 2026 (MAL-2025-41436–41443) | 8 `@nx/*` packages + `nx` core: `@nx/devkit` 20.9.0, 21.5.0; `@nx/eslint` 21.5.0; `@nx/js` 20.9.0, 21.5.0; `@nx/node` 20.9.0, 21.5.0; `@nx/workspace` 20.9.0, 21.5.0; `@nx/enterprise-cloud` 3.2.0; `nx` 20.9.0–20.12.0, 21.5.0–21.8.0 (`@nx/key` withdrawn as FP, MAL-2025-41440) |
| @limebike dependency-confusion — May 27 2026 (MAL-2026-4187–4190) | `@limebike/frontend-core-api`, `@limebike/supreme`, `@limebike/supreme-data-grid`, `@limebike/supreme-date-pickers` — any-version (high-version 85.x packages targeting Lime's internal CI) |
| libhmac crypto-stealer typosquat — May 26 2026 (MAL-2026-4194) | `libhmac` 0.3.0, 0.8.28.0, 0.8.28.1, 1.1.0 (PyPI) — impersonates a legitimate HMAC library |
| polymarket-clob-client npm compromise — May 26 2026 (MAL-2026-4643) | `polymarket-clob-client` 2.1.1 (npm) — official Polymarket CLOB client, single malicious version |
| msc-terminal npm infostealer — May 27 2026 (MAL-2026-4823) | `msc-terminal` — any-version (pure-malware, >=0 range in OSV) |
| Dependency-confusion 99.x batch — May 27 2026 | `@remitee-money-transfer/rmt-base` 99.99.x; `customerdigital-ui-containers-lib` 99.x; `editorial-code`, `editorial-mse-authentication-ui`, `mse-authentication` 99.0.1 — high-version CI shadow attack |
| May 27 2026 npm any-version wildcards | `@not-nemo/crypto-tracker`, `bulletproof-json`, `chai-as-repaired`, `claude-channel-imessage`, `shop-minis`, `skills-detector`, `testing-on-npmjs`, `verify-mycommand` — all OSV >=0 ranges |
| quatres PyPI malware — May 27 2026 (MAL-2026-4829) | `quatres` 3.0.1 — sole survivor of the May 27 bulk PyPI batch; the rest were withdrawn as false positives (see note below) |
| Moika Tech dependency confusion campaign — May 28 2026 (ossf/malicious-packages PR #1279) | 164 npm packages across 5 private scopes (`@car-loans`, `@cloudplatform-single-spa`, `@debit-ib`, `@fb-deposit`, `@mlspace`) published at version 99.99.99 by attacker 'pik-libs' to hijack internal CI pipelines; all any-version wildcards |
| vpmdhaj OpenSearch/CI typosquat cluster — May 28 2026 | 14 npm packages published by threat actor vpmdhaj in a 4-hour window: `@vpmdhaj/devops-tools`, `@vpmdhaj/elastic-helper`, `@vpmdhaj/opensearch-setup`, `@vpmdhaj/search-setup`, `app-config-utility`, `elastic-opensearch-helper`, `env-config-manager`, `opensearch-config-utility`, `opensearch-security-scanner`, `opensearch-setup`, `opensearch-setup-tool`, `search-cluster-setup`, `search-engine-setup`, `vpmdhaj-opensearch-setup` — all any-version wildcards; Bun-compiled stager harvests AWS/Vault/CI credentials |
| Roblox/robase PyPI typosquat cluster — May 29 2026 | 52 packages impersonating Roblox API / database helper libraries (`robase`, `robase-*`, `rblx-*`, `ro-db`, `roboat-*`, `rogiant*`, `rosolver`, `database*`, `bloxy-api`, `core-roblox-utils`, `api-analysis`, `pycolorlib*`, `quicksolving`, …) — each confirmed by an individual OSV MAL-2026-* record |
| oob-moika-tech dependency-confusion npm sub-wave — May 29 2026 | `@databus-service-ui/*`, `@service-suppliers/*`, `@service-user-notifications/set_notifications_not_removable`, `@polka-ui/*`, `@pulse-web-platform-core/scripts-loader`, `@loans/vehicles-api`, `nemo-reporter` — internal-package-name dependency confusion; each confirmed by an individual OSV MAL-2026-* record |
| oob-moika-tech Wave 2 npm dependency-confusion cluster — May 29 2026 | 17 npm packages by actor t-in-one (nath.dr4k3@gmail.com), same C2 oob.moika.tech as May 28 wave: 15 `@t-in-one/*` Angular DI token packages (`add_application`, `form_product_token`, `save_application_hid_to_storage`, `add_app_middleware_token`, `add_application_service_token`, `add_application_tid`, `application_id_storage_key_token`, `get_application_hid`, `only_difference_payload`, `prefill_bundle_data_token`, `prefill_credit_data_token`, `prefill_transformers_data_token`, `restore_application_hid_from_storage`, `safe_local_storage_token`, `send_add_application`) plus `@capibar.chat/ui-kit` and `@sber-ecom-core/sberpay-widget` — all any-version wildcards; OSV MAL-2026-3337, 5031–5046 |
| Mixed npm malware batch — May 29 2026 | `buffer-util-extend` (GHSA-g44v-3gq3-j8p6 / OSV MAL-2026-2920, any-version — executes base64 payload on require/import), `hellowornd` (GHSA-4f9q-ffgq-5w82 / OSV MAL-2026-4839, any-version), `tiny-naturalsort` (GHSA-mqp5-9r9w-8hg4 / OSV MAL-2026-5030, any-version); dependency-confusion pins: `@neon-i18n/core-ui` 99.99.99 (OSV MAL-2026-5027), `sorenson-webfonts` 99.9.1 (OSV MAL-2026-5028) |
| modulebuild3240234t PyPI Roblox infostealer — May 29 2026 | `modulebuild3240234t` 1.0.0, 1.0.1, 2.0.0, 3.0.0 (OSV MAL-2026-5029) — exfiltrates Roblox session data and credentials on import |
| polymarket-data PyPI crypto/credentials infostealer — May 30 2026 (OSV MAL-2026-5086) | `polymarket-data` 2.0.0, 2.0.1 — exfiltrates cryptocurrency data and API keys; establishes persistence; likely typosquat of polymarket-data-fetcher |
| buffer-utilities npm malware — May 30 2026 (OSV MAL-2026-5087) | `buffer-utilities` 1.0.0 — communicates with a domain associated with malicious activity and executes commands associated with malicious behavior; detected by OpenSSF Package Analysis |
| retail-location-strategy-frontend npm malware — May 30 2026 (OSV MAL-2026-5092) | `retail-location-strategy-frontend` 1.1.1, 1.1.2 — communicates with a domain associated with malicious activity; detected by OpenSSF Package Analysis |
| crypto-helper / cryptolock / obfuscation PyPI install-time malware — May 30–31 2026 (OSV MAL-2026-5088/5089/5100) | `crypto-helper` 1.0.0; `cryptolock` 1.0.0, 1.0.1; `obfuscation` 3.23.0, 3.23.2, 3.23.3 — tamper with security settings and download/execute a malicious executable during pip install; VirusTotal IOC evidence for obfuscation; detected by kam193/bad-packages.kam193.eu |
| discord-ban / discord-massban PyPI browser-credential infostealers — May 30–31 2026 (OSV MAL-2026-5091/5099) | `discord-ban` 1.0.0, 1.0.1, 1.0.2; `discord-massban` 0.1.0 — steal credentials, credit cards, and browsing history from web browsers; part of same 2026-05-discord-ban campaign; detected by kam193/bad-packages.kam193.eu |
| neuralforge-ml PyPI env-variable exfiltrator — May 30 2026 (OSV MAL-2026-5090) | `neuralforge-ml` 0.9.9 — stub package imitating an ML library; obfuscated exfiltration of environment variables; detected by kam193/bad-packages.kam193.eu |
| h4xupdate / hell-cipher PyPI malware batch — May 31 2026 (OSV MAL-2026-5093/5094) | `h4xupdate` 0.0.1 — remote-control tool with hardcoded Telegram bot C2, impersonates a legitimate company; `hell-cipher` 1.0.1 — tampers with security settings during install and downloads/executes a malicious executable; both detected by kam193/bad-packages.kam193.eu |
| cscc-glass-house PyPI cloud-credential exfiltrator — May 31 2026 (OSV MAL-2026-5096) | `cscc-glass-house` 1.0.1–1.0.4 — exfiltrates credentials from cloud environments to a hardcoded location; detected by kam193/bad-packages.kam193.eu |
| @challenger6/vm-pattern-library / cms-storehub / js-shared-modules npm malware — May 31 2026 (OSV MAL-2026-5095/5097/5098) | `@challenger6/vm-pattern-library` 99.0.0, `cms-storehub` 1.3.6, and `js-shared-modules` 1.11.7 — all communicate with a domain associated with malicious activity; detected by OpenSSF Package Analysis |
| June 1 2026 npm batch — CMS-dropper cluster, Amazon Inspector postinstall batch, Chai/AWS typosquats | CMS-dropper cluster: `to-cms` (postinstall downloads ChromeSetup.exe; OSV MAL-2026-4693/GHSA-789x-j439-qx3f), `cms-github` (GHSA-3r39-h7xh-jg85), `cms-helpgit` (GHSA-hjw8-jc8q-mvwj), `shopifyto-cms` (GHSA-92q8-c63v-g77x) — all any-version wildcards; Amazon Inspector postinstall batch: `collected-forms-embed-js` (recon + credential exfil; OSV MAL-2026-4175/GHSA-9j37-8wjm-pcxq), `audit-logsss` (shell recon + public IP fetch; OSV MAL-2026-4487/GHSA-gcq4-52q3-v4fm), `chainix` (fake pino-compatible logger; OSV MAL-2026-4817/GHSA-mrx8-p3w9-5cfm) — all any-version wildcards; Chai typosquat: `chai-as-minted` (OSV MAL-2026-5106/GHSA-85px-g4cg-g2g3); AWS/CLI typosquats: `@antoncallahan/aws-user-helper` (OSV MAL-2026-5101/GHSA-v2cq-j5gf-pf5g), `@tmecontinue/cli` (OSV MAL-2026-5105/GHSA-jq5f-g7j2-8f9g); test-scope packages with active OSV records: `@ewfewfewf/testhackerrr` (GHSA-p4gj-2hmg-hj4f), `@osamdefeirrighs/testhackfrrferrr` (GHSA-rrrc-gchv-j329), `@pcldpvkoewpogw/testhacker` (GHSA-xjcm-hjvm-fmhp) |
| @redhat-cloud-services scope account compromise — June 1–2 2026 | 31 `@redhat-cloud-services/*` npm packages (expanded across June 1–2 as additional malicious versions were published): `chrome` 2.3.1–2.3.4; `compliance-client` 4.0.3–4.0.6 (MAL-2026-5133); `config-manager-client` 5.0.4–5.0.7 (MAL-2026-5134); `entitlements-client` 4.0.11–4.0.14 (GHSA-28hc-2275-h287); `eslint-config-redhat-cloud-services` 3.2.1–3.2.4 (GHSA-c3mv-fjj4-2542); `frontend-components` 7.7.2–7.7.5 (GHSA-mrgj-mcjh-5mf2); `frontend-components-advisor-components` 3.8.2–3.8.6 (MAL-2026-5135); `frontend-components-config` 6.11.3–6.11.6 (GHSA-h43w-g623-gfmv); `frontend-components-config-utilities` 4.11.2–4.11.5 (GHSA-cxfw-p322-rfrv); `frontend-components-notifications` 6.9.2–6.9.5 (MAL-2026-5136); `frontend-components-remediations` 4.9.2–4.9.5 (GHSA-4rjr-7qhx-vjwg); `frontend-components-testing` 1.2.1–1.2.4 (GHSA-wgvx-w8g7-vh4h); `frontend-components-translations` 4.4.1–4.4.4 (MAL-2026-5137); `frontend-components-utilities` 7.4.1–7.4.4 (MAL-2026-5138); `hcc-feo-mcp` 0.3.1–0.3.4 (GHSA-vgm5-jmvr-cjgf); `hcc-kessel-mcp` 0.3.1–0.3.4 (MAL-2026-5139); `hcc-pf-mcp` 0.6.1–0.6.4 (MAL-2026-5140); `host-inventory-client` 5.0.3–5.0.6 (MAL-2026-5141); `insights-client` 4.0.4–4.0.7 (MAL-2026-5142); `integrations-client` 6.0.4–6.0.7 (GHSA-8x4g-q845-wpfc); `javascript-clients-shared` 2.0.8–2.0.11 (MAL-2026-5143); `notifications-client` 6.1.4–6.1.7 (MAL-2026-5144); `patch-client` 4.0.4–4.0.7 (MAL-2026-5145); `quickstarts-client` 4.0.11–4.0.14 (GHSA-mj98-cgm5-6xrr); `rbac-client` 9.0.3–9.0.6 (GHSA-2p99-xvqh-j893); `remediations-client` 4.0.4–4.0.7 (MAL-2026-5146); `rule-components` 4.7.2–4.7.5 (GHSA-c4gm-6fh3-76v9); `sources-client` 3.0.10–3.0.13 (GHSA-vp9c-9mjm-2f7w); `topological-inventory-client` 3.0.10–3.0.13 (GHSA-9wp8-557p-2hvf); `tsc-transform-imports` 1.2.2–1.2.6 (MAL-2026-5147); `types` 3.6.1–3.6.4 (GHSA-8xj2-9c64-m64h); `vulnerabilities-client` 2.1.8–2.1.11 (MAL-2026-5148); OSV MAL-2026-5111 through 5119, 5125–5131, 5133–5148; scope in NPM_SUSPECT_SCOPES |
| loading-session npm package compromise — June 1 2026 (GHSA-7vwr-8v2c-gjvr) | `loading-session` any-version wildcard (OSV has >=0 range + specific versions 4.2.1, 4.2.2; per convention, entire package is treated as malicious) |
| jingmeideshishi npm throwaway malware — June 1 2026 (GHSA-pc3j-w4f9-94hj) | `jingmeideshishi` any-version wildcard (pure-malware gibberish-name package; OSV MAL-2026-5110) |
| redteam-qxz7-utils PyPI malware — June 1 2026 (OSV MAL-2026-5120) | `redteam-qxz7-utils` 1.0.0 (PyPI; malicious code detected by kam193/bad-packages.kam193.eu) |
| Amazon Inspector npm malware batch — June 1 2026 | `xarc-webpack-cli` (preinstall hook; GHSA-2xcr-5qfc-fq54 / MAL-2026-4352), `json-to-simple-graphql-schema` (poc.js script; GHSA-2qqv-9mw5-52q2 / MAL-2026-4590), `motion-tool` (fake pino logger; GHSA-hw79-5457-g9c3 / MAL-2026-4615), `randomlogs` (malicious main module; GHSA-6x8j-5cx8-5qv6 / MAL-2026-4657) — all OSV affected.ranges >=0; any-version wildcards |
| Dependency-confusion 9999.x batch — June 1 2026 | `nepsnowplow` 9999.0.0 (MAL-2026-5121; targets Snowplow Analytics CI), `picnic-react-mise-en-place` 9999.0.0 (MAL-2026-5122; targets Picnic internal React packages); detected by OpenSSF Package Analysis |
| @chat-template/auth GHSA full-compromise — June 1 2026 (GHSA-5jx8-qv7v-hv32) | `@chat-template/auth` any-version wildcard (MAL-2026-5124; OSV affected.ranges >=0) |
| imgmatrix-analysis PyPI remote-command executor — June 1 2026 (OSV MAL-2026-5123) | `imgmatrix-analysis` 0.1.0–0.1.9 (PyPI; executes remote commands during import; detected by kam193/bad-packages.kam193.eu) |
| rookie-security-test-pkg npm malware — June 1 2026 (OSV MAL-2026-5132) | `rookie-security-test-pkg` 1.0.0 (npm; communicates with malicious domain and executes malicious commands; detected by OpenSSF Package Analysis) |
| Dep-confusion + PyPI RAT/exfiltrator batch — June 2 2026 | npm: `@aonunited/angular` 99.0.1 (MAL-2026-5150; shadows AON United internal Angular library; communicates with malicious domain), `@att-ebiz/abs-components-bc` 99.9.1 (MAL-2026-5153; shadows AT&T eBusiness ABS Components BC; same detection pattern); PyPI: `parsimonius` 0.10.0–0.12.0 (MAL-2026-5151; typosquat of parsimonious PEG-parser, injects Telegram-bot RAT that exfiltrates env vars; geo-filtered to avoid Russian targets), `quant-backtest-helpers` 1.0.1 (MAL-2026-5152; exfiltrates env vars and cloud tokens to hardcoded ngrok endpoint; targets quant-finance developers), `bt-signal-utils` 1.0.0–1.0.1 (MAL-2026-5160; same campaign as quant-backtest-helpers; exfiltrates env vars and cloud tokens to same ngrok endpoint) |
| @antv/color-util Mini Shai-Hulud supplemental — June 2 2026 (OSV MAL-2026-3862 / GHSA-rh6v-hwr4-6jcp) | `@antv/color-util` any-version wildcard (same campaign as @antv wave; SEMVER >=0 range + specific versions 2.1.6/2.2.6 confirmed by ghsa-malware, amazon-inspector, and google-open-source-security) |
| Scandinavian telecom dep-confusion npm cluster — June 2 2026 | `@customer-threesixty/assets`, `@ownit/core`, `@telenor-se/core`, `@tse-digital/core` — all any-version wildcards; actor debating0166 used inflated version numbers (99.0.x) targeting Telenor SE, Ownit, Customer 360, and TSE Digital internal CI; OSV MAL-2026-5154/5155/5156/5157 |
| oob-moika-tech Wave 3 / EMCD-impersonation dep-confusion cluster — June 2 2026 | `@emcd-vue/auth`, `@emcd-vue/b2b-pay-form`, `@emcd-vue/loans` — all any-version wildcards; attacker registered `@emcd-vue` npm scope impersonating EMCD (emcd.io) cryptocurrency exchange; same C2/campaign infrastructure as May 28–29 oob-moika-tech waves; OSV MAL-2026-5163/5164/5165 |
| Dep-confusion 99.x npm batch — June 2 2026 | `page-info-service` 99.9.1 (MAL-2026-5158), `po-ops-local-dev` 99.9.1 (MAL-2026-5159), `sourceflow-tracker` 99.91.9 (MAL-2026-5166) — detected by OpenSSF Package Analysis communicating with malicious domains; high-version dep-confusion pattern |
| jules-test-utils PyPI host-info exfiltrator — June 2 2026 (OSV MAL-2026-5167) | `jules-test-utils` 0.1.0 (PyPI; single-purpose recon package that exfiltrates basic host information on install or import; detected by kam193) |
| spaysrbdata / spaysdata / spadata PyPI Roblox-cookie infostealer campaign — June 2–3 2026 | `spaysrbdata` 0.1.0–0.5.0 (MAL-2026-5170), `spaysdata` 0.1.0–0.4.5 (MAL-2026-5171), `spadata` 0.1.0–0.1.1 (MAL-2026-5173) — all three packages exfiltrate Roblox session cookies; same campaign (2026-06-spaysrbdata); detected by kam193 |
| vg-interaction-model dep-confusion + chai-parse Chai typosquat — June 2 2026 | `vg-interaction-model` 40.0.1, 40.0.4 (MAL-2026-5168; high-version dep-confusion shadow package detected by OpenSSF Package Analysis — communicates with malicious domain, executes malicious commands; second version 40.0.4 added June 3 2026); `chai-parse` any-version wildcard (MAL-2026-5169; GHSA-confirmed Chai typosquat — any installed version renders host fully compromised; SEMVER >=0 range) |
| internal-tracker PyPI host-info exfiltrator — June 3 2026 (OSV MAL-2026-5176) | `internal-tracker` 0.0.1, 0.0.2, 0.0.5 (PyPI; overrides setup.py install command to exfiltrate basic host info — IP address and username — on install; no other functionality; detected by kam193) |
| fundraiserserv / nodemon-pack / webpack-json npm malware — June 3 2026 | `fundraiserserv` 1.0.0 (MAL-2026-5172; communicates with malicious domain; OpenSSF Package Analysis); `nodemon-pack` any-version wildcard (MAL-2026-5174 / GHSA-pqxq-jw84-3x8f; full-compromise typosquat of nodemon; SEMVER >=0 range); `webpack-json` any-version wildcard (MAL-2026-5175 / GHSA-69hx-wrc9-h5wq; full-compromise typosquat of webpack; SEMVER >=0 range) |
| chai-midpatch / nodemon-webpatch npm full-compromise typosquats — June 3 2026 | `chai-midpatch` any-version wildcard (MAL-2026-5179 / GHSA-qq87-jvv3-6c7r; continues Chai-typosquat campaign, cf. chai-parse; SEMVER >=0 range, any installed version renders host fully compromised); `nodemon-webpatch` any-version wildcard (MAL-2026-5180 / GHSA-q398-93fh-ghmj; continues nodemon-typosquat wave, cf. nodemon-pack) |
| brave-search-mcp-server npm malware — June 3 2026 (OSV MAL-2026-5182) | `brave-search-mcp-server` 1.0.0 — communicates with a domain associated with malicious activity and executes commands associated with malicious behavior; detected by OpenSSF Package Analysis |
| fia-signals / tronlab / tronlabpy3 PyPI malware batch — June 3 2026 | `fia-signals` 0.1.0, 0.1.3 (MAL-2026-5177; host-info exfiltrator, overrides setup.py to exfiltrate IP/username on install; detected by kam193); `tronlab` 0.0.1 (MAL-2026-5178; Tron/TRX private-key exfiltrator, sends stolen keys to mockapi.io/ngrok endpoints, 2025-04-tronix campaign); `tronlabpy3` 0.0.1 (MAL-2026-5181; same campaign as tronlab) |
| hpe-glcp-automation-lib PyPI host-info exfiltrator — June 4 2026 (OSV MAL-2026-5183) | `hpe-glcp-automation-lib` 2.2160.0 — overrides setup.py install command to exfiltrate basic host data (IP, username) on install; impersonates an HPE GLCP automation library; detected by kam193 |
| sf-silly-goose-requests PyPI TruffleHog-based secret exfiltrator — June 4 2026 (OSV MAL-2026-5184) | `sf-silly-goose-requests` 0.1.0, 0.2.0 — uses TruffleHog to scan the victim environment for secrets and exfiltrates discovered credentials to a hardcoded C2 endpoint (13.219.230.105:80/beacon); detected by kam193 |
| June 4 2026 npm full-compromise batch (OSV MAL-2026-5185/5186/5187) | `@jagreehal/workflow` any-version wildcard (GHSA-6w7v-23mf-65g3; embedded malicious code, SEMVER >=0); `autotel-terminal` any-version wildcard (GHSA-cw9v-v9rh-r449; embedded malicious code, SEMVER >=0); `supabase` CLI any-version wildcard (GHSA-x96m-c5fj-q75c; fresh single-source advisory filed June 4 2026 same day as v2.105.0 publish, SEMVER >=0; official Supabase CLI — rotate all credentials if installed) |
| IronWorm supply-chain campaign — June 4 2026 | 37 npm packages in the WeaveDB / Arweave blockchain-database ecosystem, plus `hello244a`; all carry a 976 KB Rust-compiled ELF x86-64 binary executed via preinstall hooks; binary harvests cloud keys, SSH material, npm tokens, and crypto wallet keystores then exfiltrates over HTTP. Core packages: `weavedb-sdk` 0.45.3, `weavedb-base` 0.45.3, `weavedb-client` 0.45.3, `weavedb-node-client` 0.45.3, `weavedb-sdk-node` 0.45.3, `weavedb-tools` 0.45.3, `weavedb-offchain` 0.45.4, `weavedb-contracts` 0.45.2, `wao` 0.41.2/0.41.3, `cwao` 0.5.6, `cwao-tools` 0.3.1, `cwao-units` 0.8.3, `wdb-sdk` 0.1.2, `wdb-cli` 0.1.1, `wdb-core` 0.1.2, `zkjson` 0.8.5, `fpjson-lang` 0.1.7, `arjson` 0.1.4, `hbsig` 0.3.2, `warp-contracts-plugin-deploy-test` 3.0.1, `weavedb-exm-sdk` 0.7.4, `weavedb-exm-sdk-web` 0.7.4, `weavedb-sdk-base` 0.21.1, `weavedb-console` 0.2.1, `weavedb-lite` 0.1.1, `weavedb-warp-contracts-plugin-deploy` 1.0.11, `arnext` 0.1.5, `arnext-arkb` 0.0.2, `create-arnext-app` 0.0.10, `ai3` 0.3.5, `atomic-notes` 0.5.3, `aonote` 0.11.1, `monade` 0.0.7, `roidjs` 0.1.7, `test-ajs` 0.1.19, `test-weavedb-sdk` 1.1.1, `testnpmnmp` 1.0.21; `hello244a` 1.0.4/1.0.1 (ossf-package-analysis). OSV MAL-2026-4476 through MAL-2026-4739 (amazon-inspector); MAL-2026-5188 through MAL-2026-5192 (google-open-source-security, explicitly confirming IronWorm); confirmed by OX Security and JFrog independently |
| IronWorm supplemental packages — June 5 2026 (OSV MAL-2026-3508/3648–3652/4542/5193/5194) | 9 additional npm packages in the IronWorm campaign impersonating widely-used JS utility libraries: `auth-javascript`, `iceberg-javascript`, `microsoft-applicationinsights-common`, `ms-graph-types`, `supabase-javascript` (any-version wildcards; all carry SEMVER >=0 range); `crypto-javascri` (15 pinned versions: 1.0.1–3.0.1); `crypto-javascript` (5 pinned versions: 4.2.5–4.3.6); `javascript-yaml` 4.1.2; `yaml-javascript` 4.1.2 — same Rust-compiled x86-64 ELF preinstall dropper; confirmed by OX Security and JFrog |
| binding.gyp npm worm — June 5 2026 (OSV MAL-2026-5195 through MAL-2026-5267) | 73 npm packages across multiple publishers infected by a binding.gyp-based self-propagating worm. Initial discovery: `ai-sdk-ollama` 0.13.1/1.1.1/2.2.1/3.8.5. Clusters: `@ethlete/*` scope (9 packages: `cdk`, `cli`, `components`, `contentful`, `core`, `dsp`, `query`, `theming`, `types`); `@forjacms/*` scope (4 packages: `analytics`, `client`, `sections`, `sections-react`); `@vapi-ai/server-sdk` 0.11.1/0.11.2/1.2.1/1.2.2; `autotel` + 22 sub-packages; `awaitly` + 5 sub-packages; `executable-stories-*` framework (9 packages + 4 eslint plugins); `node-env-resolver-*` (5 packages); Cloudflare Workers tools (`create-cf-token`, `create-wrangler-deploy`, `wrangler-deploy`); standalone packages (`@contaazul/n8n-nodes-contaazul`, `creditcard.js`, `dbmux`, `discord-search`, `effect-analyzer`, `github-archiver`, `mountly`, `mountly-tailwind`). All have specific-version entries (no any-version wildcards). Sources: StepSecurity + Endor Labs (two independent vendors). |
| ulid-os npm full-compromise typosquat — June 5 2026 (OSV MAL-2026-5268 / GHSA-fxhm-35h8-7jc7) | `ulid-os` any-version wildcard — GHSA-confirmed embedded malicious code; any installed version renders the host fully compromised; SEMVER >=0 range |
| utils-mf npm WhatsApp-bot + exfiltration package — June 5 2026 (OSV MAL-2026-4699 / GHSA-4c54-hwv9-c5xm) | `utils-mf` 11.2.4–11.2.6, 11.4.1, 11.9.8–11.9.9, 12.0.1–12.0.2, 12.1.0–12.1.1 (10 versions) — ships a 15.7 MB obfuscator.io blob that opens a WhatsApp socket on require(), exfiltrates chat/contact/env state to the attacker's GitHub/GitLab repos on a 30-second timer, and silently self-updates from the npm registry at runtime; confirmed by amazon-inspector |
| react-ui-polyfills remote-eval backdoor — June 5 2026 (OSV MAL-2026-4784 / GHSA-v7mj-pmr3-7x4p) | `react-ui-polyfills` any-version wildcard — fake React polyfills; exported getPlugin() fetches attacker-controlled JSON from a mutable jsonkeeper.com URL and passes the .cookie field to eval(); SEMVER >=0 range + specific versions 1.0.0/1.2.7 confirmed by amazon-inspector and GHSA |
| glyphr / reactvora npm full-compromise pair — June 5 2026 | `glyphr` any-version wildcard (OSV MAL-2026-5269 / GHSA-c988-j68q-h8h4); `reactvora` any-version wildcard (OSV MAL-2026-5270 / GHSA-x4gw-cjrp-c89f) — both GHSA-confirmed CWE-506 embedded malicious code; SEMVER >=0 range |
| goodoldtoulas / goodoltoulas PyPI install-time droppers — June 5 2026 (OSV MAL-2026-5271/5272) | `goodoldtoulas` 0.1.0; `goodoltoulas` 0.1.0 — both override setup.py install command to download and execute a remote Windows executable during pip install; detected by kam193; classified PROBABLY_PENTEST |
| anthropy PyPI reverse-shell infostealer — June 5 2026 (OSV MAL-2026-5273) | `anthropy` 0.0.1–0.0.6 — starts a reverse shell on import; categorized MALICIOUS by kam193; 6 consecutive versions published before takedown |
| puppeteer maintainer-account compromise — May 29 2026 (GHSA-8r2f-2qg4-cv9v) | `puppeteer` 25.0.1 — Google's 25M+ downloads/week headless Chrome library; single malicious version; any compromised system should be considered fully compromised and credentials rotated |
| Mini Shai-Hulud additional packages — May 2026 (GHSA-cqpw-mfqj-f2j7) | `@beproduct/nestjs-auth` 0.1.2–0.1.19 (18 versions); `@tallyui/storage-sqlite` 0.2.1–0.2.3 — same Shai-Hulud postinstall bundle as @tanstack/* packages |
| @antv wave supplemental non-@antv npm packages — May 19 2026 | 15 packages compromised in the same 317-package @antv campaign but outside the @antv/ scope: `@lint-md/{cli,core,parser}`, `ast-plugin`, `canvas-nest.js`, `fixed-round`, `jest-date-mock`, `jest-less-loader`, `limit-size`, `miz`, `onfire.js`, `relationship.js`, `slice.js`, `word-width`, `xmorse` — exact version pairs per OSV MAL-2026-4123 through 4159 |
| Multi-campaign dependency confusion batch — May 29–30 2026 | ~80 npm packages from 12+ independent dependency-confusion campaigns: `@clearpool/{comms,streaming,table}` (crypto exchange); `axis-{abc-search-account,abc-search-address,notification}` (Axis Communications); `@breezeai-frontend/*`, `@breeze-ai/*` (BreezeAI); `@allybank/ally-sdk`, `@allyfinancial/allyfinancial-api`, `ally-{antivirus,badges,ccapi,eagw-identity,json-threat-protect}` (Ally Financial); `@citi-icg-158830/*` (Citigroup ICG); `apexomni`, `apexpro`, `apexomni-node`, `apexpro-node` (ApexOmni/ApexPro crypto); `@cplace-*`, `@rsi-community/*`, `@lir-portal/*`, `@tc-core/*`, `@timelycare/*`, `@trp-individual-investor-adv-disc/*`, plus misc packages (`proton-pack`, `deepl-sync`, `reactive-cdk-app`, `power-apps`, `codex-devcontainer-install`, `gcp-api-enabler`, etc.) — all any-version wildcards |
| ethers.js / EVM toolchain typosquat cluster — May 29–30 2026 | 12 npm packages targeting Ethereum/EVM developers: `ethers-abstract-signer` (GHSA-2f7m-g9qw-8288), `ethers-signing-key`, `ethers-contract` (GHSA-gxfh-j6jv-hc58), `ethers-errors`, `ethers-hash`, `ethers-hdnode`, `evmchain-cli`, `evmchain-config`, `foundry-config`, `hardhat-evmchain`, `viem-multichain`, `web3-config-loader` — all any-version wildcards |
| chai testing-library typosquat cluster — May 29–30 2026 | `chai-as-tuned` (GHSA-2f37-mh3q-7394), `chai-bundle` (GHSA-q36r-56hw-2r46), `chai-extensions-extras`, `chai-use-test` — fake Chai extensions, any-version wildcards |
| Tailwind CSS plugin typosquat cluster — May 29–30 2026 | `tailwind-clamps-line` (GHSA-29g5-vw2p-x29p), `tailwind-effect`, `tailwind-smooth-slider`, `tailwindcss-basic-animation`, `tailwind-typography-cssstyle` — fake Tailwind CSS plugins, any-version wildcards |
| zod-to-js Zod-ecosystem typosquat — May 29 2026 (GHSA-8cm2-vv7w-4c27) | `zod-to-js` 13.4.3, 13.4.4 — Zod-to-JS bridge library typosquat |
| May 26 2026 pure-malware typosquat batch (17 packages, GHSA-confirmed) | Web3/DeFi: `web3-prices`, `web3.prc`, `int-node`, `@izumiswap/sdk`; JSON utilities: `jsonlogbundler`, `fastjsonlog`, `jsonbson`; Solidity/Hardhat: `solidity-coverage-plus`, `hardhat-gas-analytics`; document libraries: `pdf-lib-enhanced`, `xlsx-enhanced`; misc: `corelia`, `license-checker-plus`, `lynx-keeper`, `lynx-keeper-cli`, `zest-product`, `tailwind-style-typography` — all any-version (GHSA affected.ranges >=0) |
| crates.io dep-confusion batch — April 2026 (OSV MAL-2026-3101..3129) | 5 crates published at inflated 99.x versions to hijack internal CI dependency resolution: `amzn-consolas-client` 99.0.1, `amzn-codewhisperer-streaming-client` 99.0.1, `semantic-search-client` 99.0.1, `lsh` 99.0.1/99.1.0, `supertag` 99.1.1 — all detected by OpenSSF Package Analysis as communicating with malicious domains |
| crates.io — RustSec malicious advisories | 65 crates removed from crates.io and tagged `categories = ["malicious"]` in `rustsec/advisory-db`. Includes `rustdecimal` (2022 typosquat of `rust_decimal`), the 2023 `amaperf` typosquat cluster (`xrvrv`, `oncecell`, `serd`, `lazystatic`, `if-cfg`, `envlogger`, `postgress`, `postgresderive`, `tauri-winrt-notifications`, `windows-service-rs`, `monero-rpc-rs`, `acceptxmr-rs`, …), the 2026 Polymarket credential-stealer campaign (`polymarket-clients-sdk`, `polymarket-client-sdks`, `polymarkets-client-sdk`, `polymarkets-rs-clob-client`, `clob-sdk`, `rpc-check`), the timeapi.io impersonation cluster (`time_calibrator`, `time_calibrators`, `dnp3times`, `time-sync`, `chrono_anchor`, `tracings`, `tracing-check`, `tracing_checks`, `tracing-ethers`), build.rs droppers (`mysten-metrics`, `sui-execution-cut`, `pretty-changelog-logger`, `logtrace`, `replit_ruspty`, `finch_cli_rust`, `safe-agent-rs`, `microsoftsystem64`, …), and `exploration` (June 2 2026 remote-execute dropper, RUSTSEC-2026-0155). All entries are any-version wildcards (`patched = []` in RustSec). |

Per Corgea research, the `@uipath/*` and `@mistralai/*` payloads contain a
bug that renders the malware non-functional. Installed versions should still
be removed and credentials rotated, but the realised impact differs from the
working `@tanstack/*` payloads.

> **Withdrawn false positives (May 27 2026 bulk batch).** A large batch of
> packages initially flagged from the May 27 2026 bulk OSV disclosures were
> subsequently withdrawn as false positives by the ossf/malicious-packages
> project ([PR #1276](https://github.com/ossf/malicious-packages/pull/1276),
> [PR #1278](https://github.com/ossf/malicious-packages/pull/1278)) — including
> the `fastapi` / `strawberry-graphql` / `notebook-intelligence` PyPI reports,
> the `@tailwind-core` and `@onerjs` npm typosquat clusters, the
> Baileys/WhatsApp, Claude Code/openclaw, and local-mcp/lokal-mcp campaigns,
> `@tarojs/cli`, `@nx/key`, and the bulk `edison-tools` / `heims` / `openirf` /
> `ranno` PyPI batch (~145 entries total). These have been removed. Every
> entry retained in the lists above has an active (non-withdrawn) OSV `MAL-*`
> record, or independent authoritative corroboration, as of 2026-05-29.

## Contributing

New advisory? Open an issue or PR adding entries to `NPM_BAD` / `PYPI_BAD`
/ `CRATES_BAD` in `check_compromised_packages.py`. Please include:

- The advisory URL (GHSA, CVE, OSV, or a primary security-vendor writeup)
- Exact package names and version strings

## Sources

- [Aikido — npm debug and chalk packages compromised (2025-09-08)](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [StepSecurity — 20+ popular npm packages compromised: chalk, debug, strip-ANSI, color-convert, wrap-ANSI](https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi)
- [Wiz — widespread npm supply chain attack: chalk and debug](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk)
- [Upwind — npm supply chain attack: debug, chalk, and 16 other packages](https://www.upwind.io/feed/npm-supply-chain-attack-massive-compromise-of-debug-chalk-and-16-other-packages)
- [Bleeping Computer — hackers hijack npm packages with 2 billion weekly downloads](https://www.bleepingcomputer.com/news/security/hackers-hijack-npm-packages-with-2-billion-weekly-downloads-in-supply-chain-attack/)
- [Semgrep — chalk, debug and color on npm compromised (2025-09-08)](https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/)
- [OX Security — 19 npm packages compromised](https://www.ox.security/blog/npm-packages-compromised/)
- [GHSA-2v46-p5h4-248w — chalk 5.6.1 malware](https://github.com/advisories/GHSA-2v46-p5h4-248w)
- [GHSA-4x49-vf9v-38px — debug 4.4.2 malware](https://github.com/advisories/GHSA-4x49-vf9v-38px)
- [GHSA-qrmh-qg46-72pp — color 5.0.1 malware](https://github.com/advisories/GHSA-qrmh-qg46-72pp)
- [GHSA-5fvm-p68v-5wmh — color-name 2.0.1 malware](https://github.com/advisories/GHSA-5fvm-p68v-5wmh)
- [GHSA-pxx3-g568-hxr4 — color-convert 3.1.1 malware](https://github.com/advisories/GHSA-pxx3-g568-hxr4)
- [GHSA-286p-vc9p-p5qv — color-string 2.1.1 malware](https://github.com/advisories/GHSA-286p-vc9p-p5qv)
- [GHSA-6jp5-hh4c-8c5h — error-ex 1.3.3 malware](https://github.com/advisories/GHSA-6jp5-hh4c-8c5h)
- [GHSA-jvhh-2m83-6w29 — ansi-regex 6.2.1 malware](https://github.com/advisories/GHSA-jvhh-2m83-6w29)
- [GHSA-vfjc-p7x3-q864 — strip-ansi 7.1.1 malware](https://github.com/advisories/GHSA-vfjc-p7x3-q864)
- [GHSA-p5rr-crjh-x7gr — ansi-styles 6.2.2 malware](https://github.com/advisories/GHSA-p5rr-crjh-x7gr)
- [GHSA-2rv4-jp6r-xgq7 — wrap-ansi 9.0.1 malware](https://github.com/advisories/GHSA-2rv4-jp6r-xgq7)
- [GHSA-53mq-f4w3-f7qv — backslash 0.2.1 malware](https://github.com/advisories/GHSA-53mq-f4w3-f7qv)
- [GHSA-frh7-2f84-v9mw — is-arrayish 0.3.3 malware](https://github.com/advisories/GHSA-frh7-2f84-v9mw)
- [GHSA-9g9j-rggx-7fmg — simple-swizzle 0.2.3 malware](https://github.com/advisories/GHSA-9g9j-rggx-7fmg)
- [GHSA-pj3j-3w3f-j752 — supports-color 10.2.1 malware](https://github.com/advisories/GHSA-pj3j-3w3f-j752)
- [GHSA-9xjj-cmqc-578p — slice-ansi 7.1.1 malware](https://github.com/advisories/GHSA-9xjj-cmqc-578p)
- [Snyk — embedded malicious code in tinycolor and ngx-bootstrap (2025-09-15)](https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/)
- [GHSA-6m4g-vm7c-f8w6 — ngx-bootstrap malware (18.1.4, 19.0.3–19.0.4, 20.0.3–20.0.6)](https://github.com/advisories/GHSA-6m4g-vm7c-f8w6)
- [OSV MAL-2025-47141 — @ctrl/tinycolor malware (4.1.1, 4.1.2)](https://deps.dev/advisory/osv/MAL-2025-47141)
- [valor-software/ngx-bootstrap#6776 — maintainer postmortem](https://github.com/valor-software/ngx-bootstrap/issues/6776)
- [Endor Labs — tinycolor and CrowdStrike packages compromised](https://www.endorlabs.com/learn/npm-malware-outbreak-tinycolor-and-crowdstrike-packages-compromised)
- [Socket — malicious dYdX packages (npm + PyPI)](https://socket.dev/blog/malicious-dydx-packages-published-to-npm-and-pypi)
- [The Hacker News — dYdX wallet stealer and RAT](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)
- [PYSEC-2026-1 — dydx-v4-client](https://github.com/pypa/advisory-database/blob/main/vulns/dydx-v4-client/PYSEC-2026-1.yaml)
- [GHSA-5mg7-485q-xm76 — litellm malicious versions](https://github.com/advisories/GHSA-5mg7-485q-xm76)
- [Datadog — LiteLLM and Telnyx TeamPCP campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Snyk — poisoned security scanner backdooring LiteLLM](https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/)
- [GHSA-955r-262c-33jc — telnyx malicious versions](https://github.com/team-telnyx/telnyx-python/security/advisories/GHSA-955r-262c-33jc)
- [Akamai — Telnyx SDK PyPI compromise](https://www.akamai.com/blog/security-research/telnyx-sdk-pypi-2026-teampcp-supply-chain-attacks)
- [StepSecurity — elementary-data PyPI compromise](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection)
- [Snyk — elementary-data steals cloud credentials](https://snyk.io/blog/malicious-release-of-elementary-data-pypi-package-steals-cloud-credentials-from-data-engineers/)
- [Bleeping Computer — elementary-data 1.1M download package hacked](https://www.bleepingcomputer.com/news/security/pypi-package-with-11m-monthly-downloads-hacked-to-push-infostealer/)
- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [Snyk — TanStack npm packages hit by Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Wiz — Mini Shai-Hulud strikes again](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Aikido — Mini Shai-Hulud is back](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised)
- [Corgea — Mini Shai-Hulud supply-chain worm](https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud)
- [The Hacker News — Mini Shai-Hulud worm coverage](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)
- [Snyk — Mini Shai-Hulud hits AntV (300+ packages)](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/)
- [SafeDep — Mini Shai-Hulud 314 npm packages compromised](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/)
- [StepSecurity — node-ipc supply chain attack](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- [The Hacker News — node-ipc stealer backdoor](https://thehackernews.com/2026/05/stealer-backdoor-found-in-3-node-ipc.html)
- [Microsoft Security Blog — axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- [Huntress — axios supply chain compromise](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [CISA — Supply chain compromise impacts axios npm package](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)
- [The Hacker News — Bitwarden CLI compromised](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html)
- [Palo Alto Unit 42 — Bitwarden CLI impersonation attack](https://www.paloaltonetworks.com/blog/cloud-security/bitwardencli-supply-chain-attack/)
- [GHSA-w37p-236h-pfx3 — pytorch-lightning compromise](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3)
- [GHSA-54pg-9963-v8vg — intercom-client 7.0.4 compromise](https://github.com/advisories/GHSA-54pg-9963-v8vg)
- [StepSecurity — intercom-client Shai-Hulud hijack](https://www.stepsecurity.io/blog/shai-hulud-worm-pivots-to-multi-cloud-intercom-client-hijacked)
- [Socket — intercom-client npm supply chain attack](https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack)
- [The Hacker News — TrapDoor supply chain attack](https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html)
- [Socket — TrapDoor crypto-stealer](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
- [GHSA-jp5r-76w9-2rvh — ts-stream-compose](https://github.com/advisories/GHSA-jp5r-76w9-2rvh)
- [GHSA-66j8-7w8q-vvf5 — ts-result-pipe](https://github.com/advisories/GHSA-66j8-7w8q-vvf5)
- [GHSA-xqpr-hv2v-6pfj — ts-typeguard-utils](https://github.com/advisories/GHSA-xqpr-hv2v-6pfj)
- [GHSA-qgfv-9wmq-m4f7 — ts-config-mapper](https://github.com/advisories/GHSA-qgfv-9wmq-m4f7)
- [GHSA-f6hr-rvf9-ch6p — ts-iter-utils](https://github.com/advisories/GHSA-f6hr-rvf9-ch6p)
- [GHSA-vxrv-934h-xj6q — ts-schema-config](https://github.com/advisories/GHSA-vxrv-934h-xj6q)
- [GHSA-pvrm-mpcj-2mcp — @gbrlxvii/ts-project-lint](https://github.com/advisories/GHSA-pvrm-mpcj-2mcp)
- [GHSA-362c-qm74-42gg — @gbrlxvii/ts-form-utils](https://github.com/advisories/GHSA-362c-qm74-42gg)
- [GHSA-59j3-wvx3-w9hx — @gbrlxvii/ts-env-validator](https://github.com/advisories/GHSA-59j3-wvx3-w9hx)
- [GHSA-4xqv-4874-rxx6 — auth0-aspnetcore-utils](https://github.com/advisories/GHSA-4xqv-4874-rxx6)
- [GHSA-g8jx-g4j9-hh3w — auth0-internal-collector](https://github.com/advisories/GHSA-g8jx-g4j9-hh3w)
- [GHSA-cwjp-2mq2-6xp6 — auth0-android-helper-utils](https://github.com/advisories/GHSA-cwjp-2mq2-6xp6)
- [GHSA-xm89-4mqj-hfrq — auth0-net-sdk-utils](https://github.com/advisories/GHSA-xm89-4mqj-hfrq)
- [GHSA-c8ph-73mc-f5p8 — auth0-sample-dus-utils](https://github.com/advisories/GHSA-c8ph-73mc-f5p8)
- [GHSA-jfp3-8vwj-7g9v — auth0-common-telemetry](https://github.com/advisories/GHSA-jfp3-8vwj-7g9v)
- [GHSA-2qjx-pgq9-vx24 — webservices.rest](https://github.com/advisories/GHSA-2qjx-pgq9-vx24)
- [GHSA-v62r-4vqp-f32g — webservices.rest-utils](https://github.com/advisories/GHSA-v62r-4vqp-f32g)
- [GHSA-7v58-43rg-wjwq — vite-plugin-env-compat-1.5](https://github.com/advisories/GHSA-7v58-43rg-wjwq)
- [GHSA-2rh6-x7fc-2fr4 — vite-plugin-env-compat-plus](https://github.com/advisories/GHSA-2rh6-x7fc-2fr4)
- [GHSA-fc78-r45j-m7f5 — fivem-monitor](https://github.com/advisories/GHSA-fc78-r45j-m7f5)
- [GHSA-6pxr-857g-mr97 — jules-standard](https://github.com/advisories/GHSA-6pxr-857g-mr97)
- [GHSA-qcrh-87jf-mm39 — internallib_v95](https://github.com/advisories/GHSA-qcrh-87jf-mm39)
- [GHSA-w6gc-fhv9-53hq — chai-as-redeploy](https://github.com/advisories/GHSA-w6gc-fhv9-53hq)
- [GHSA-rj44-v8w3-c5q5 — expo-config-plugin-typescript](https://github.com/advisories/GHSA-rj44-v8w3-c5q5)
- [GHSA-gqvh-j8hx-425w — unique-string-64](https://github.com/advisories/GHSA-gqvh-j8hx-425w)
- [OSV MAL-2026-4345 — eo-terminal](https://osv.dev/vulnerability/MAL-2026-4345)
- [OSV MAL-2026-4346 — logger-draft](https://osv.dev/vulnerability/MAL-2026-4346)
- [ossf/malicious-packages PR #1270 — eo-terminal, logger-draft (toskypi campaign)](https://github.com/ossf/malicious-packages/pull/1270)
- [OSV MAL-2026-4347 — @devcarron/clob](https://osv.dev/vulnerability/MAL-2026-4347)
- [OSV MAL-2026-4348 — api-rs-node](https://osv.dev/vulnerability/MAL-2026-4348)
- [OSV MAL-2026-4349 — clob.api](https://osv.dev/vulnerability/MAL-2026-4349)
- [OSV MAL-2026-4350 — clobprice.api](https://osv.dev/vulnerability/MAL-2026-4350)
- [ossf/malicious-packages PR #1271 — CLOB IPFS dropper campaign](https://github.com/ossf/malicious-packages/pull/1271)
- [OSV MAL-2026-2827 — js-logger-pack DPRK npm stealer](https://osv.dev/vulnerability/MAL-2026-2827)
- [JFrog — js-logger-pack turns HuggingFace into malware CDN](https://research.jfrog.com/post/hugging-face-exfil/)
- [OX Security — North Korean-linked npm infostealer RAT (terminal-logger-utils)](https://www.ox.security/blog/north-korean-npm-infostealer-rat/)
- [SafeDep — js-logger-pack multi-platform WebSocket stealer](https://safedep.io/malicious-js-logger-pack-npm-stealer/)
- [CybersecurityNews — HuggingFace npm supply chain attack](https://cybersecuritynews.com/malicious-npm-package-turns-hugging-face/)
- [Bleeping Computer — leaked Shai-Hulud malware fuels npm infostealer campaign (2026-05-26)](https://www.bleepingcomputer.com/news/security/leaked-shai-hulud-malware-fuels-new-npm-infostealer-campaign/)
- [OX Security — new actors deploy Shai-Hulud clones (deadcode09284814)](https://www.ox.security/blog/new-actors-deploy-shai-hulud-clones-teampcp-copycats-are-here/)
- [SecurityWeek — first Shai-Hulud worm clones emerge](https://www.securityweek.com/first-shai-hulud-worm-clones-emerge/)
- [The Hacker News — four malicious npm packages deliver infostealers and Phantom Bot DDoS](https://thehackernews.com/2026/05/four-malicious-npm-packages-deliver.html)
- [Socket — TrapDoor crates.io Sui/Move build.rs dropper cluster](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)
- [The Block — TrapDoor crates.io Sui/Move packages (independent corroboration)](https://www.theblock.co/post/402458/researchers-flag-trapdoor-malware-campaign-targeting-crypto-developer-environments-including-aptos-sui-and-solana)
- [OSV MAL-2025-41436 through 41443 — @nx/* and nx supply-chain compromise](https://osv.dev/vulnerability/MAL-2025-41436)
- [OSV MAL-2026-4187 — @limebike/frontend-core-api](https://osv.dev/vulnerability/MAL-2026-4187)
- [OSV MAL-2026-4188 — @limebike/supreme](https://osv.dev/vulnerability/MAL-2026-4188)
- [OSV MAL-2026-4189 — @limebike/supreme-data-grid](https://osv.dev/vulnerability/MAL-2026-4189)
- [OSV MAL-2026-4190 — @limebike/supreme-date-pickers](https://osv.dev/vulnerability/MAL-2026-4190)
- [OSV MAL-2026-4643 — polymarket-clob-client](https://osv.dev/vulnerability/MAL-2026-4643)
- [OSV MAL-2026-4823 — msc-terminal](https://osv.dev/vulnerability/MAL-2026-4823)
- [OSV MAL-2026-4194 — libhmac](https://osv.dev/vulnerability/MAL-2026-4194)
- [OSV MAL-2026-4829 — quatres 3.0.1 (PyPI)](https://osv.dev/vulnerability/MAL-2026-4829)
- [OSV MAL-2026-2543 — robase (Roblox/robase PyPI cluster, May 29 2026; ~52 MAL-2026-* records)](https://osv.dev/vulnerability/MAL-2026-2543)
- [OSV MAL-2026-4834 — @polka-ui/config (oob-moika-tech dependency-confusion npm sub-wave, May 29 2026)](https://osv.dev/vulnerability/MAL-2026-4834)
- [OSV MAL-2026-4435 — @service-suppliers/fetch_suppliers_action_saga](https://osv.dev/vulnerability/MAL-2026-4435)
- [OSV MAL-2026-4836 — nemo-reporter](https://osv.dev/vulnerability/MAL-2026-4836)
- [StepSecurity — pgserve compromised on npm (CanisterSprawl)](https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials)
- [Socket — Namastex npm packages hit with CanisterWorm](https://socket.dev/blog/namastex-npm-packages-compromised-canisterworm)
- [Maintainer issue — pgserve 1.1.11–1.1.13 malicious postinstall](https://github.com/namastexlabs/pgserve/issues/25)
- [The Hacker News — self-propagating supply chain worm hijacks npm (CanisterSprawl)](https://thehackernews.com/2026/04/self-propagating-supply-chain-worm.html)
- [SafeDep — @fairwords npm credential worm](https://safedep.io/malicious-fairwords-npm-credential-worm/)
- [InfoWorld — malicious pgserve and automagik developer tools found in npm](https://www.infoworld.com/article/4162198/malicious-pgserve-automagik-developer-tools-found-in-npm-registry.html)
- [StepSecurity — @velora-dex/sdk compromised: macOS backdoor via launchctl](https://www.stepsecurity.io/blog/velora-dex-sdk-compromised-on-npm-malicious-version-drops-macos-backdoor-via-launchctl-persistence)
- [SafeDep — @velora-dex/sdk delivers Go RAT via npm](https://safedep.io/malicious-velora-dex-sdk-npm-compromised-rat/)
- [SafeDep — node-env-resolve npm RAT](https://safedep.io/malicious-npm-node-env-resolve-rat/)
- [SafeDep — dom-utils-lite npm SSH backdoor via Supabase](https://safedep.io/malicious-dom-utils-lite-npm-ssh-backdoor/)
- [Xygeni — DevTap npm typosquatting attack (user0001 cluster)](https://xygeni.io/blog/devtap-npm-typosquatting-attack-2/)
- [JFrog — xinference PyPI package compromised by TeamPCP](https://research.jfrog.com/post/xinference-compromise/)
- [Mend.io — TeamPCP Part 4: malicious xinference on PyPI](https://www.mend.io/blog/malicious-xinference-pypi-teampcp-part-4/)
- [OX Security — xinference allegedly hacked by TeamPCP](https://www.ox.security/blog/xinference-allegedly-hacked-by-teampcp-malicious-package-in-pypi/)
- [rustsec/advisory-db](https://github.com/rustsec/advisory-db) — canonical RustSec advisories (filter for `categories = ["malicious"]`)
- [Veracode (Phylum) — Rust malware staged on crates.io](https://www.veracode.com/blog/rust-malware-staged-on-crates-io/) (amaperf 2023 cluster)
- [Socket — 5 malicious Rust crates posed as time utilities](https://socket.dev/blog/5-malicious-rust-crates-posed-as-time-utilities-to-exfiltrate-env-files) (timeapi.io campaign)
- [crates.io blog — security incidents](https://blog.rust-lang.org/inside-rust/) — primary source for Polymarket and Mysten takedowns
- [OSV MAL-2026-4424 — @remitee-money-transfer/rmt-base dependency-confusion](https://osv.dev/vulnerability/MAL-2026-4424)
- [OSV MAL-2026-4833 — bulletproof-json](https://osv.dev/vulnerability/MAL-2026-4833)
- [OSV MAL-2026-4512 — chai-as-repaired](https://osv.dev/vulnerability/MAL-2026-4512)
- [OSV MAL-2026-4523 — claude-channel-imessage](https://osv.dev/vulnerability/MAL-2026-4523)
- [GHSA-g3vg-qhhh-pfv7 — web3-prices](https://github.com/advisories/GHSA-g3vg-qhhh-pfv7)
- [GHSA-r4j3-79hx-xpr6 — web3.prc](https://github.com/advisories/GHSA-r4j3-79hx-xpr6)
- [GHSA-r4ww-65gv-rhv8 — int-node](https://github.com/advisories/GHSA-r4ww-65gv-rhv8)
- [GHSA-q782-j24w-vv68 — @izumiswap/sdk](https://github.com/advisories/GHSA-q782-j24w-vv68)
- [GHSA-hhf2-gfcc-vw45 — jsonlogbundler](https://github.com/advisories/GHSA-hhf2-gfcc-vw45)
- [GHSA-82gw-34fc-qfwj — fastjsonlog](https://github.com/advisories/GHSA-82gw-34fc-qfwj)
- [GHSA-44rg-m26f-r36f — jsonbson](https://github.com/advisories/GHSA-44rg-m26f-r36f)
- [GHSA-fg63-2vqh-93xf — corelia](https://github.com/advisories/GHSA-fg63-2vqh-93xf)
- [GHSA-9qcm-qgjc-h848 — pdf-lib-enhanced](https://github.com/advisories/GHSA-9qcm-qgjc-h848)
- [GHSA-j5gx-8qjw-gp5q — xlsx-enhanced](https://github.com/advisories/GHSA-j5gx-8qjw-gp5q)
- [GHSA-j3fh-3pm4-rw5h — solidity-coverage-plus](https://github.com/advisories/GHSA-j3fh-3pm4-rw5h)
- [GHSA-73xx-w222-rg6v — license-checker-plus](https://github.com/advisories/GHSA-73xx-w222-rg6v)
- [GHSA-7pxc-2jp3-w7c8 — hardhat-gas-analytics](https://github.com/advisories/GHSA-7pxc-2jp3-w7c8)
- [GHSA-x7hr-g7qr-7j7p — lynx-keeper](https://github.com/advisories/GHSA-x7hr-g7qr-7j7p)
- [GHSA-3p5r-gmr8-v7mr — lynx-keeper-cli](https://github.com/advisories/GHSA-3p5r-gmr8-v7mr)
- [GHSA-qm6m-33hv-fvwv — zest-product](https://github.com/advisories/GHSA-qm6m-33hv-fvwv)
- [GHSA-pv74-wmjg-4gp8 — tailwind-style-typography](https://github.com/advisories/GHSA-pv74-wmjg-4gp8)
- [ossf/malicious-packages PR #1279 — Moika Tech dependency confusion (164 npm packages, May 28 2026)](https://github.com/ossf/malicious-packages/pull/1279)
- [Microsoft Security Blog — vpmdhaj typosquatted npm packages steal cloud and CI/CD secrets (2026-05-28)](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)
- [GBHackers — typosquatted npm packages steal cloud and CI/CD secrets](https://gbhackers.com/typosquatted-npm-packages/)
- [OSV MAL-2026-2920 — buffer-util-extend](https://osv.dev/vulnerability/MAL-2026-2920)
- [GHSA-g44v-3gq3-j8p6 — buffer-util-extend malware](https://github.com/advisories/GHSA-g44v-3gq3-j8p6)
- [OSV MAL-2026-4839 — hellowornd](https://osv.dev/vulnerability/MAL-2026-4839)
- [GHSA-4f9q-ffgq-5w82 — hellowornd malware](https://github.com/advisories/GHSA-4f9q-ffgq-5w82)
- [OSV MAL-2026-5027 — @neon-i18n/core-ui dependency confusion](https://osv.dev/vulnerability/MAL-2026-5027)
- [OSV MAL-2026-5028 — sorenson-webfonts dependency confusion](https://osv.dev/vulnerability/MAL-2026-5028)
- [OSV MAL-2026-5029 — modulebuild3240234t (PyPI Roblox infostealer)](https://osv.dev/vulnerability/MAL-2026-5029)
- [OSV MAL-2026-5086 — polymarket-data (PyPI crypto/credentials infostealer)](https://osv.dev/vulnerability/MAL-2026-5086)
- [OSV MAL-2026-5030 — tiny-naturalsort](https://osv.dev/vulnerability/MAL-2026-5030)
- [GHSA-mqp5-9r9w-8hg4 — tiny-naturalsort malware](https://github.com/advisories/GHSA-mqp5-9r9w-8hg4)
- [OSV MAL-2026-3337 — @t-in-one/save_application_hid_to_storage (oob-moika-tech Wave 2)](https://osv.dev/vulnerability/MAL-2026-3337)
- [OSV MAL-2026-5031 — @capibar.chat/ui-kit (oob-moika-tech Wave 2)](https://osv.dev/vulnerability/MAL-2026-5031)
- [OSV MAL-2026-5032 — @sber-ecom-core/sberpay-widget (oob-moika-tech Wave 2)](https://osv.dev/vulnerability/MAL-2026-5032)
- [OSV MAL-2026-5033 through 5046 — @t-in-one/* Angular DI token packages (oob-moika-tech Wave 2)](https://osv.dev/vulnerability/MAL-2026-5033)
- [SafeDep — oob-moika-tech dependency confusion campaign](https://safedep.io/oob-moika-tech-dependency-confusion-campaign/)
- [GHSA-8r2f-2qg4-cv9v — puppeteer 25.0.1 malware](https://github.com/advisories/GHSA-8r2f-2qg4-cv9v)
- [OSV MAL-2026-5077 — puppeteer maintainer-account compromise](https://osv.dev/vulnerability/MAL-2026-5077)
- [GHSA-cqpw-mfqj-f2j7 — @beproduct/nestjs-auth malware (Mini Shai-Hulud)](https://github.com/advisories/GHSA-cqpw-mfqj-f2j7)
- [OSV MAL-2026-3433 — @beproduct/nestjs-auth](https://osv.dev/vulnerability/MAL-2026-3433)
- [OSV MAL-2026-3604 — @tallyui/storage-sqlite](https://osv.dev/vulnerability/MAL-2026-3604)
- [OSV MAL-2026-4123 — @lint-md/cli (@antv wave supplemental)](https://osv.dev/vulnerability/MAL-2026-4123)
- [Socket — AntV packages compromised (atool wave)](https://socket.dev/blog/antv-packages-compromised)
- [GHSA-fr5f-hf7f-p9w9 — @clearpool/comms dependency confusion](https://github.com/advisories/GHSA-fr5f-hf7f-p9w9)
- [GHSA-2892-cpv4-xqr4 — @allybank/ally-sdk dependency confusion](https://github.com/advisories/GHSA-2892-cpv4-xqr4)
- [GHSA-gw7h-mv77-3wv8 — @citi-icg-158830/elemental-ui-react dependency confusion](https://github.com/advisories/GHSA-gw7h-mv77-3wv8)
- [GHSA-m6v2-w5cf-f85x — apexomni typosquat](https://github.com/advisories/GHSA-m6v2-w5cf-f85x)
- [GHSA-fmm7-x566-j93x — @cplace-workflow-fe/cf-workflow dependency confusion](https://github.com/advisories/GHSA-fmm7-x566-j93x)
- [GHSA-j83r-w4f8-v7m9 — @rsi-community/hub-schema dependency confusion](https://github.com/advisories/GHSA-j83r-w4f8-v7m9)
- [GHSA-pvc4-pwx8-4c4g — @lir-portal/web-components dependency confusion](https://github.com/advisories/GHSA-pvc4-pwx8-4c4g)
- [GHSA-h3x2-x2gh-2hcm — @timelycare/api dependency confusion](https://github.com/advisories/GHSA-h3x2-x2gh-2hcm)
- [GHSA-qvrg-265v-cqvc — deepl-sync typosquat](https://github.com/advisories/GHSA-qvrg-265v-cqvc)
- [GHSA-gj36-855r-fpmf — proton-pack typosquat](https://github.com/advisories/GHSA-gj36-855r-fpmf)
- [GHSA-frcf-f9wx-gq64 — codex-devcontainer-install malware](https://github.com/advisories/GHSA-frcf-f9wx-gq64)
- [GHSA-9vx3-fc8v-7w96 — customerdigital-service-lib dependency confusion](https://github.com/advisories/GHSA-9vx3-fc8v-7w96)
- [GHSA-cx3x-gvpc-g35w — private-next-instrumentation-client malware](https://github.com/advisories/GHSA-cx3x-gvpc-g35w)
- [GHSA-2f7m-g9qw-8288 — ethers-abstract-signer typosquat](https://github.com/advisories/GHSA-2f7m-g9qw-8288)
- [GHSA-gxfh-j6jv-hc58 — ethers-contract typosquat](https://github.com/advisories/GHSA-gxfh-j6jv-hc58)
- [GHSA-2f37-mh3q-7394 — chai-as-tuned typosquat](https://github.com/advisories/GHSA-2f37-mh3q-7394)
- [GHSA-q36r-56hw-2r46 — chai-bundle typosquat](https://github.com/advisories/GHSA-q36r-56hw-2r46)
- [GHSA-29g5-vw2p-x29p — tailwind-clamps-line typosquat](https://github.com/advisories/GHSA-29g5-vw2p-x29p)
- [GHSA-8cm2-vv7w-4c27 — zod-to-js typosquat](https://github.com/advisories/GHSA-8cm2-vv7w-4c27)
- [OSV MAL-2026-5087 — buffer-utilities npm malware](https://osv.dev/vulnerability/MAL-2026-5087)
- [OSV MAL-2026-5088 — crypto-helper PyPI install-time malware](https://osv.dev/vulnerability/MAL-2026-5088)
- [OSV MAL-2026-5089 — cryptolock PyPI install-time malware](https://osv.dev/vulnerability/MAL-2026-5089)
- [OSV MAL-2026-5091 — discord-ban PyPI browser-credential infostealer](https://osv.dev/vulnerability/MAL-2026-5091)
- [OSV MAL-2026-5090 — neuralforge-ml PyPI env-variable exfiltrator](https://osv.dev/vulnerability/MAL-2026-5090)
- [OSV MAL-2026-5093 — h4xupdate PyPI Telegram bot C2 malware](https://osv.dev/vulnerability/MAL-2026-5093)
- [OSV MAL-2026-5094 — hell-cipher PyPI install-time malicious executable](https://osv.dev/vulnerability/MAL-2026-5094)
- [OSV MAL-2026-5095 — @challenger6/vm-pattern-library npm malware](https://osv.dev/vulnerability/MAL-2026-5095)
- [OSV MAL-2026-5096 — cscc-glass-house PyPI cloud-credential exfiltrator](https://osv.dev/vulnerability/MAL-2026-5096)
- [OSV MAL-2026-5097 — cms-storehub npm malware](https://osv.dev/vulnerability/MAL-2026-5097)
- [OSV MAL-2026-5098 — js-shared-modules npm malware](https://osv.dev/vulnerability/MAL-2026-5098)
- [OSV MAL-2026-5099 — discord-massban PyPI browser-credential infostealer](https://osv.dev/vulnerability/MAL-2026-5099)
- [OSV MAL-2026-5100 — obfuscation PyPI install-time malware](https://osv.dev/vulnerability/MAL-2026-5100)
- [OSV MAL-2026-3101 — amzn-consolas-client crates.io dep-confusion](https://osv.dev/vulnerability/MAL-2026-3101)
- [OSV MAL-2026-3102 — semantic-search-client crates.io dep-confusion](https://osv.dev/vulnerability/MAL-2026-3102)
- [OSV MAL-2026-3103 — amzn-codewhisperer-streaming-client crates.io dep-confusion](https://osv.dev/vulnerability/MAL-2026-3103)
- [OSV MAL-2026-3126 — lsh crates.io dep-confusion](https://osv.dev/vulnerability/MAL-2026-3126)
- [OSV MAL-2026-3129 — supertag crates.io dep-confusion](https://osv.dev/vulnerability/MAL-2026-3129)
- [OSV MAL-2026-4175 / GHSA-9j37-8wjm-pcxq — collected-forms-embed-js postinstall recon + exfiltration](https://osv.dev/vulnerability/MAL-2026-4175)
- [OSV MAL-2026-4487 / GHSA-gcq4-52q3-v4fm — audit-logsss postinstall recon](https://osv.dev/vulnerability/MAL-2026-4487)
- [OSV MAL-2026-4693 / GHSA-789x-j439-qx3f — to-cms ChromeSetup.exe dropper](https://osv.dev/vulnerability/MAL-2026-4693)
- [OSV MAL-2026-4817 / GHSA-mrx8-p3w9-5cfm — chainix fake pino-compatible logger malware](https://osv.dev/vulnerability/MAL-2026-4817)
- [GHSA-v2cq-j5gf-pf5g / OSV MAL-2026-5101 — @antoncallahan/aws-user-helper malware](https://github.com/advisories/GHSA-v2cq-j5gf-pf5g)
- [GHSA-p4gj-2hmg-hj4f / OSV MAL-2026-5102 — @ewfewfewf/testhackerrr malware](https://github.com/advisories/GHSA-p4gj-2hmg-hj4f)
- [GHSA-rrrc-gchv-j329 / OSV MAL-2026-5103 — @osamdefeirrighs/testhackfrrferrr malware](https://github.com/advisories/GHSA-rrrc-gchv-j329)
- [GHSA-xjcm-hjvm-fmhp / OSV MAL-2026-5104 — @pcldpvkoewpogw/testhacker malware](https://github.com/advisories/GHSA-xjcm-hjvm-fmhp)
- [GHSA-jq5f-g7j2-8f9g / OSV MAL-2026-5105 — @tmecontinue/cli malware](https://github.com/advisories/GHSA-jq5f-g7j2-8f9g)
- [GHSA-85px-g4cg-g2g3 / OSV MAL-2026-5106 — chai-as-minted malware](https://github.com/advisories/GHSA-85px-g4cg-g2g3)
- [GHSA-3r39-h7xh-jg85 / OSV MAL-2026-5107 — cms-github malware](https://github.com/advisories/GHSA-3r39-h7xh-jg85)
- [GHSA-hjw8-jc8q-mvwj / OSV MAL-2026-5108 — cms-helpgit malware](https://github.com/advisories/GHSA-hjw8-jc8q-mvwj)
- [GHSA-92q8-c63v-g77x / OSV MAL-2026-5109 — shopifyto-cms malware](https://github.com/advisories/GHSA-92q8-c63v-g77x)
- [GHSA-942v-f47r-w9c3 / OSV MAL-2026-5111 — @redhat-cloud-services/chrome malware](https://github.com/advisories/GHSA-942v-f47r-w9c3)
- [GHSA-c3mv-fjj4-2542 / OSV MAL-2026-5112 — @redhat-cloud-services/eslint-config-redhat-cloud-services malware](https://github.com/advisories/GHSA-c3mv-fjj4-2542)
- [GHSA-mrgj-mcjh-5mf2 / OSV MAL-2026-5113 — @redhat-cloud-services/frontend-components malware](https://github.com/advisories/GHSA-mrgj-mcjh-5mf2)
- [GHSA-cxfw-p322-rfrv / OSV MAL-2026-5114 — @redhat-cloud-services/frontend-components-config-utilities malware](https://github.com/advisories/GHSA-cxfw-p322-rfrv)
- [GHSA-mj98-cgm5-6xrr / OSV MAL-2026-5115 — @redhat-cloud-services/quickstarts-client malware](https://github.com/advisories/GHSA-mj98-cgm5-6xrr)
- [GHSA-2p99-xvqh-j893 / OSV MAL-2026-5116 — @redhat-cloud-services/rbac-client malware](https://github.com/advisories/GHSA-2p99-xvqh-j893)
- [GHSA-c4gm-6fh3-76v9 / OSV MAL-2026-5117 — @redhat-cloud-services/rule-components malware](https://github.com/advisories/GHSA-c4gm-6fh3-76v9)
- [GHSA-9wp8-557p-2hvf / OSV MAL-2026-5118 — @redhat-cloud-services/topological-inventory-client malware](https://github.com/advisories/GHSA-9wp8-557p-2hvf)
- [GHSA-8xj2-9c64-m64h / OSV MAL-2026-5119 — @redhat-cloud-services/types malware](https://github.com/advisories/GHSA-8xj2-9c64-m64h)
- [GHSA-7vwr-8v2c-gjvr / OSV MAL-2026-4600 — loading-session npm malware](https://github.com/advisories/GHSA-7vwr-8v2c-gjvr)
- [GHSA-pc3j-w4f9-94hj / OSV MAL-2026-5110 — jingmeideshishi npm malware](https://github.com/advisories/GHSA-pc3j-w4f9-94hj)
- [OSV MAL-2026-5120 — redteam-qxz7-utils PyPI malware](https://osv.dev/vulnerability/MAL-2026-5120)
- [bad-packages.kam193.eu — redteam-qxz7-utils](https://bad-packages.kam193.eu/pypi/package/redteam-qxz7-utils)
- [GHSA-2xcr-5qfc-fq54 / OSV MAL-2026-4352 — xarc-webpack-cli malware](https://github.com/advisories/GHSA-2xcr-5qfc-fq54)
- [GHSA-2qqv-9mw5-52q2 / OSV MAL-2026-4590 — json-to-simple-graphql-schema malware](https://github.com/advisories/GHSA-2qqv-9mw5-52q2)
- [GHSA-hw79-5457-g9c3 / OSV MAL-2026-4615 — motion-tool malware](https://github.com/advisories/GHSA-hw79-5457-g9c3)
- [GHSA-6x8j-5cx8-5qv6 / OSV MAL-2026-4657 — randomlogs malware](https://github.com/advisories/GHSA-6x8j-5cx8-5qv6)
- [OSV MAL-2026-5121 — nepsnowplow dep-confusion](https://osv.dev/vulnerability/MAL-2026-5121)
- [OSV MAL-2026-5122 — picnic-react-mise-en-place dep-confusion](https://osv.dev/vulnerability/MAL-2026-5122)
- [GHSA-5jx8-qv7v-hv32 / OSV MAL-2026-5124 — @chat-template/auth malware](https://github.com/advisories/GHSA-5jx8-qv7v-hv32)
- [OSV MAL-2026-5123 — imgmatrix-analysis PyPI malware](https://osv.dev/vulnerability/MAL-2026-5123)
- [bad-packages.kam193.eu — imgmatrix-analysis](https://bad-packages.kam193.eu/pypi/package/imgmatrix-analysis)
- [OSV MAL-2026-5132 — rookie-security-test-pkg npm malware](https://osv.dev/vulnerability/MAL-2026-5132)
- [GHSA-28hc-2275-h287 / OSV MAL-2026-5125 — @redhat-cloud-services/entitlements-client malware](https://github.com/advisories/GHSA-28hc-2275-h287)
- [GHSA-h43w-g623-gfmv / OSV MAL-2026-5126 — @redhat-cloud-services/frontend-components-config malware](https://github.com/advisories/GHSA-h43w-g623-gfmv)
- [GHSA-4rjr-7qhx-vjwg / OSV MAL-2026-5127 — @redhat-cloud-services/frontend-components-remediations malware](https://github.com/advisories/GHSA-4rjr-7qhx-vjwg)
- [GHSA-wgvx-w8g7-vh4h / OSV MAL-2026-5128 — @redhat-cloud-services/frontend-components-testing malware](https://github.com/advisories/GHSA-wgvx-w8g7-vh4h)
- [GHSA-vgm5-jmvr-cjgf / OSV MAL-2026-5129 — @redhat-cloud-services/hcc-feo-mcp malware](https://github.com/advisories/GHSA-vgm5-jmvr-cjgf)
- [GHSA-8x4g-q845-wpfc / OSV MAL-2026-5130 — @redhat-cloud-services/integrations-client malware](https://github.com/advisories/GHSA-8x4g-q845-wpfc)
- [GHSA-vp9c-9mjm-2f7w / OSV MAL-2026-5131 — @redhat-cloud-services/sources-client malware](https://github.com/advisories/GHSA-vp9c-9mjm-2f7w)
- [OSV MAL-2026-5133 — @redhat-cloud-services/compliance-client malware](https://osv.dev/vulnerability/MAL-2026-5133)
- [OSV MAL-2026-5134 — @redhat-cloud-services/config-manager-client malware](https://osv.dev/vulnerability/MAL-2026-5134)
- [OSV MAL-2026-5135 — @redhat-cloud-services/frontend-components-advisor-components malware](https://osv.dev/vulnerability/MAL-2026-5135)
- [OSV MAL-2026-5136 — @redhat-cloud-services/frontend-components-notifications malware](https://osv.dev/vulnerability/MAL-2026-5136)
- [OSV MAL-2026-5137 — @redhat-cloud-services/frontend-components-translations malware](https://osv.dev/vulnerability/MAL-2026-5137)
- [OSV MAL-2026-5138 — @redhat-cloud-services/frontend-components-utilities malware](https://osv.dev/vulnerability/MAL-2026-5138)
- [OSV MAL-2026-5139 — @redhat-cloud-services/hcc-kessel-mcp malware](https://osv.dev/vulnerability/MAL-2026-5139)
- [OSV MAL-2026-5140 — @redhat-cloud-services/hcc-pf-mcp malware](https://osv.dev/vulnerability/MAL-2026-5140)
- [OSV MAL-2026-5141 — @redhat-cloud-services/host-inventory-client malware](https://osv.dev/vulnerability/MAL-2026-5141)
- [OSV MAL-2026-5142 — @redhat-cloud-services/insights-client malware](https://osv.dev/vulnerability/MAL-2026-5142)
- [OSV MAL-2026-5143 — @redhat-cloud-services/javascript-clients-shared malware](https://osv.dev/vulnerability/MAL-2026-5143)
- [OSV MAL-2026-5144 — @redhat-cloud-services/notifications-client malware](https://osv.dev/vulnerability/MAL-2026-5144)
- [OSV MAL-2026-5145 — @redhat-cloud-services/patch-client malware](https://osv.dev/vulnerability/MAL-2026-5145)
- [OSV MAL-2026-5146 — @redhat-cloud-services/remediations-client malware](https://osv.dev/vulnerability/MAL-2026-5146)
- [OSV MAL-2026-5147 — @redhat-cloud-services/tsc-transform-imports malware](https://osv.dev/vulnerability/MAL-2026-5147)
- [OSV MAL-2026-5148 — @redhat-cloud-services/vulnerabilities-client malware](https://osv.dev/vulnerability/MAL-2026-5148)
- [OSV MAL-2026-5150 — @aonunited/angular dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5150)
- [OSV MAL-2026-5151 — parsimonius Telegram-bot RAT PyPI typosquat (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5151)
- [bad-packages.kam193.eu — parsimonius](https://bad-packages.kam193.eu/pypi/package/parsimonius)
- [OSV MAL-2026-5152 — quant-backtest-helpers env/cloud-token exfiltrator (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5152)
- [bad-packages.kam193.eu — quant-backtest-helpers](https://bad-packages.kam193.eu/pypi/package/quant-backtest-helpers)
- [OSV MAL-2026-5153 — @att-ebiz/abs-components-bc dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5153)
- [OSV MAL-2026-5160 — bt-signal-utils env/cloud-token exfiltrator (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5160)
- [bad-packages.kam193.eu — bt-signal-utils](https://bad-packages.kam193.eu/pypi/package/bt-signal-utils)
- [OSV MAL-2026-3862 — @antv/color-util Mini Shai-Hulud supplemental (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-3862)
- [GHSA-rh6v-hwr4-6jcp — @antv/color-util malware](https://github.com/advisories/GHSA-rh6v-hwr4-6jcp)
- [OSV MAL-2026-5154 — @customer-threesixty/assets Scandinavian telecom dep-confusion (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5154)
- [OSV MAL-2026-5155 — @ownit/core Scandinavian telecom dep-confusion (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5155)
- [OSV MAL-2026-5156 — @telenor-se/core Scandinavian telecom dep-confusion (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5156)
- [OSV MAL-2026-5157 — @tse-digital/core Scandinavian telecom dep-confusion (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5157)
- [OSV MAL-2026-5158 — page-info-service dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5158)
- [OSV MAL-2026-5159 — po-ops-local-dev dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5159)
- [OSV MAL-2026-5163 — @emcd-vue/auth oob-moika-tech Wave 3 (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5163)
- [OSV MAL-2026-5164 — @emcd-vue/b2b-pay-form oob-moika-tech Wave 3 (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5164)
- [OSV MAL-2026-5165 — @emcd-vue/loans oob-moika-tech Wave 3 (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5165)
- [OSV MAL-2026-5166 — sourceflow-tracker dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5166)
- [OSV MAL-2026-5167 — jules-test-utils PyPI host-info exfiltrator (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5167)
- [bad-packages.kam193.eu — jules-test-utils](https://bad-packages.kam193.eu/pypi/package/jules-test-utils)
- [OSV MAL-2026-5170 — spaysrbdata PyPI Roblox-cookie infostealer (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5170)
- [bad-packages.kam193.eu — spaysrbdata](https://bad-packages.kam193.eu/pypi/package/spaysrbdata)
- [OSV MAL-2026-5171 — spaysdata PyPI Roblox-cookie infostealer (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5171)
- [bad-packages.kam193.eu — spaysdata](https://bad-packages.kam193.eu/pypi/package/spaysdata)
- [OSV MAL-2026-5168 — vg-interaction-model dep-confusion npm malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5168)
- [OSV MAL-2026-5169 — chai-parse Chai typosquat any-version malware (June 2 2026)](https://osv.dev/vulnerability/MAL-2026-5169)
- [OSV MAL-2026-5172 — fundraiserserv npm malware (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5172)
- [OSV MAL-2026-5173 — spadata PyPI Roblox-cookie infostealer (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5173)
- [bad-packages.kam193.eu — spadata](https://bad-packages.kam193.eu/pypi/package/spadata)
- [OSV MAL-2026-5174 — nodemon-pack npm full-compromise typosquat (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5174)
- [GHSA-pqxq-jw84-3x8f — nodemon-pack (June 3 2026)](https://github.com/advisories/GHSA-pqxq-jw84-3x8f)
- [OSV MAL-2026-5175 — webpack-json npm full-compromise typosquat (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5175)
- [GHSA-69hx-wrc9-h5wq — webpack-json (June 3 2026)](https://github.com/advisories/GHSA-69hx-wrc9-h5wq)
- [OSV MAL-2026-5176 — internal-tracker PyPI host-info exfiltrator (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5176)
- [bad-packages.kam193.eu — internal-tracker](https://bad-packages.kam193.eu/pypi/package/internal-tracker)
- [OSV MAL-2026-5177 — fia-signals PyPI host-info exfiltrator (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5177)
- [bad-packages.kam193.eu — fia-signals](https://bad-packages.kam193.eu/pypi/package/fia-signals)
- [OSV MAL-2026-5178 — tronlab PyPI TRX private-key exfiltrator (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5178)
- [bad-packages.kam193.eu — tronlab](https://bad-packages.kam193.eu/pypi/package/tronlab)
- [OSV MAL-2026-5179 — chai-midpatch npm full-compromise typosquat (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5179)
- [GHSA-qq87-jvv3-6c7r — chai-midpatch (June 3 2026)](https://github.com/advisories/GHSA-qq87-jvv3-6c7r)
- [OSV MAL-2026-5180 — nodemon-webpatch npm full-compromise typosquat (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5180)
- [GHSA-q398-93fh-ghmj — nodemon-webpatch (June 3 2026)](https://github.com/advisories/GHSA-q398-93fh-ghmj)
- [OSV MAL-2026-5181 — tronlabpy3 PyPI TRX private-key exfiltrator (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5181)
- [bad-packages.kam193.eu — tronlabpy3](https://bad-packages.kam193.eu/pypi/package/tronlabpy3)
- [RUSTSEC-2026-0155 — exploration crates.io remote-execute dropper (June 2 2026)](https://rustsec.org/advisories/RUSTSEC-2026-0155.html)
- [OSV MAL-2026-5182 — brave-search-mcp-server npm malware (June 3 2026)](https://osv.dev/vulnerability/MAL-2026-5182)
- [OSV MAL-2026-5183 — hpe-glcp-automation-lib PyPI host-info exfiltrator (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5183)
- [OSV MAL-2026-5184 — sf-silly-goose-requests PyPI TruffleHog-based secret exfiltrator (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5184)
- [bad-packages.kam193.eu — sf-silly-goose-requests](https://bad-packages.kam193.eu/pypi/package/sf-silly-goose-requests)
- [OSV MAL-2026-5185 — @jagreehal/workflow npm malware (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5185)
- [GHSA-6w7v-23mf-65g3 — @jagreehal/workflow (June 4 2026)](https://github.com/advisories/GHSA-6w7v-23mf-65g3)
- [OSV MAL-2026-5186 — autotel-terminal npm malware (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5186)
- [GHSA-cw9v-v9rh-r449 — autotel-terminal (June 4 2026)](https://github.com/advisories/GHSA-cw9v-v9rh-r449)
- [OSV MAL-2026-5187 — supabase CLI npm malware (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5187)
- [GHSA-x96m-c5fj-q75c — supabase (June 4 2026)](https://github.com/advisories/GHSA-x96m-c5fj-q75c)
- [OX Security — IronWorm supply-chain malware hits npm (WeaveDB ecosystem, June 4 2026)](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/)
- [JFrog — Iron Worm: Shai-Hulud's rustier cousin (WeaveDB IronWorm campaign)](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)
- [OSV MAL-2026-4476 — ai3 IronWorm](https://osv.dev/vulnerability/MAL-2026-4476)
- [OSV MAL-2026-4723 — weavedb-sdk IronWorm](https://osv.dev/vulnerability/MAL-2026-4723)
- [OSV MAL-2026-4711 — wao IronWorm](https://osv.dev/vulnerability/MAL-2026-4711)
- [OSV MAL-2026-5188 — hello244a npm malware (June 4 2026)](https://osv.dev/vulnerability/MAL-2026-5188)
- [OSV MAL-2026-5189 — arjson IronWorm (google-open-source-security)](https://osv.dev/vulnerability/MAL-2026-5189)
- [OSV MAL-2026-5192 — weavedb-contracts IronWorm (google-open-source-security)](https://osv.dev/vulnerability/MAL-2026-5192)
- [OSV MAL-2026-3508 — crypto-javascri IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3508)
- [OSV MAL-2026-3648 — auth-javascript IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3648)
- [OSV MAL-2026-3649 — iceberg-javascript IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3649)
- [OSV MAL-2026-3650 — microsoft-applicationinsights-common IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3650)
- [OSV MAL-2026-3651 — ms-graph-types IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3651)
- [OSV MAL-2026-3652 — supabase-javascript IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-3652)
- [OSV MAL-2026-4542 — crypto-javascript IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-4542)
- [OSV MAL-2026-5193 — javascript-yaml IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5193)
- [OSV MAL-2026-5194 — yaml-javascript IronWorm supplemental (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5194)
- [StepSecurity — binding.gyp npm supply chain attack spreads like a worm (June 5 2026)](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm)
- [Endor Labs — Malicious payload in ai-sdk-ollama npm package (June 5 2026)](https://www.endorlabs.com/learn/malicious-payload-in-ai-sdk-ollama-npm-package)
- [OSV MAL-2026-5195 — @contaazul/n8n-nodes-contaazul (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5195)
- [OSV MAL-2026-5196 — @ethlete/cdk (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5196)
- [OSV MAL-2026-5200 — @ethlete/core (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5200)
- [OSV MAL-2026-5205 — @forjacms/analytics (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5205)
- [OSV MAL-2026-5209 — @vapi-ai/server-sdk (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5209)
- [OSV MAL-2026-5210 — ai-sdk-ollama (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5210)
- [OSV MAL-2026-5211 — autotel (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5211)
- [OSV MAL-2026-5223 — autotel-mcp (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5223)
- [OSV MAL-2026-5234 — awaitly (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5234)
- [OSV MAL-2026-5250 — executable-stories-cypress (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5250)
- [OSV MAL-2026-5262 — node-env-resolver (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5262)
- [OSV MAL-2026-5267 — wrangler-deploy (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5267)
- [OSV MAL-2026-5268 — ulid-os npm full-compromise typosquat (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5268)
- [GHSA-fxhm-35h8-7jc7 — ulid-os malware](https://github.com/advisories/GHSA-fxhm-35h8-7jc7)
- [OSV MAL-2026-4699 — utils-mf npm WhatsApp-bot + data-exfiltration package (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-4699)
- [GHSA-4c54-hwv9-c5xm — utils-mf malware](https://github.com/advisories/GHSA-4c54-hwv9-c5xm)
- [OSV MAL-2026-4784 — react-ui-polyfills remote-eval backdoor (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-4784)
- [GHSA-v7mj-pmr3-7x4p — react-ui-polyfills malware](https://github.com/advisories/GHSA-v7mj-pmr3-7x4p)
- [OSV MAL-2026-5269 — glyphr npm full-compromise (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5269)
- [GHSA-c988-j68q-h8h4 — glyphr malware](https://github.com/advisories/GHSA-c988-j68q-h8h4)
- [OSV MAL-2026-5270 — reactvora npm full-compromise (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5270)
- [GHSA-x4gw-cjrp-c89f — reactvora malware](https://github.com/advisories/GHSA-x4gw-cjrp-c89f)
- [OSV MAL-2026-5271 — goodoldtoulas PyPI install-time dropper (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5271)
- [OSV MAL-2026-5272 — goodoltoulas PyPI install-time dropper (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5272)
- [bad-packages.kam193.eu — goodoltoulas](https://bad-packages.kam193.eu/pypi/package/goodoltoulas)
- [OSV MAL-2026-5273 — anthropy PyPI reverse-shell infostealer (June 5 2026)](https://osv.dev/vulnerability/MAL-2026-5273)
- [bad-packages.kam193.eu — anthropy](https://bad-packages.kam193.eu/pypi/package/anthropy)

## License

MIT — see [LICENSE](LICENSE).

Author: Jascha Wanger / Tarnover, LLC
