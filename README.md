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
`@mlspace/`, `@vpmdhaj/`, `@t-in-one/`) where the version doesn't exactly match the malicious list —
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
| crypto-helper / cryptolock PyPI install-time malware — May 30 2026 (OSV MAL-2026-5088/5089) | `crypto-helper` 1.0.0; `cryptolock` 1.0.0, 1.0.1 — tamper with security settings and download/execute a malicious executable during pip install; detected by kam193/bad-packages.kam193.eu |
| discord-ban PyPI browser-credential infostealer — May 30 2026 (OSV MAL-2026-5091) | `discord-ban` 1.0.0, 1.0.1, 1.0.2 — steals credentials, credit cards, and browsing history from web browsers; detected by kam193/bad-packages.kam193.eu |
| neuralforge-ml PyPI env-variable exfiltrator — May 30 2026 (OSV MAL-2026-5090) | `neuralforge-ml` 0.9.9 — stub package imitating an ML library; obfuscated exfiltration of environment variables; detected by kam193/bad-packages.kam193.eu |
| puppeteer maintainer-account compromise — May 29 2026 (GHSA-8r2f-2qg4-cv9v) | `puppeteer` 25.0.1 — Google's 25M+ downloads/week headless Chrome library; single malicious version; any compromised system should be considered fully compromised and credentials rotated |
| Mini Shai-Hulud additional packages — May 2026 (GHSA-cqpw-mfqj-f2j7) | `@beproduct/nestjs-auth` 0.1.2–0.1.19 (18 versions); `@tallyui/storage-sqlite` 0.2.1–0.2.3 — same Shai-Hulud postinstall bundle as @tanstack/* packages |
| @antv wave supplemental non-@antv npm packages — May 19 2026 | 15 packages compromised in the same 317-package @antv campaign but outside the @antv/ scope: `@lint-md/{cli,core,parser}`, `ast-plugin`, `canvas-nest.js`, `fixed-round`, `jest-date-mock`, `jest-less-loader`, `limit-size`, `miz`, `onfire.js`, `relationship.js`, `slice.js`, `word-width`, `xmorse` — exact version pairs per OSV MAL-2026-4123 through 4159 |
| Multi-campaign dependency confusion batch — May 29–30 2026 | ~80 npm packages from 12+ independent dependency-confusion campaigns: `@clearpool/{comms,streaming,table}` (crypto exchange); `axis-{abc-search-account,abc-search-address,notification}` (Axis Communications); `@breezeai-frontend/*`, `@breeze-ai/*` (BreezeAI); `@allybank/ally-sdk`, `@allyfinancial/allyfinancial-api`, `ally-{antivirus,badges,ccapi,eagw-identity,json-threat-protect}` (Ally Financial); `@citi-icg-158830/*` (Citigroup ICG); `apexomni`, `apexpro`, `apexomni-node`, `apexpro-node` (ApexOmni/ApexPro crypto); `@cplace-*`, `@rsi-community/*`, `@lir-portal/*`, `@tc-core/*`, `@timelycare/*`, `@trp-individual-investor-adv-disc/*`, plus misc packages (`proton-pack`, `deepl-sync`, `reactive-cdk-app`, `power-apps`, `codex-devcontainer-install`, `gcp-api-enabler`, etc.) — all any-version wildcards |
| ethers.js / EVM toolchain typosquat cluster — May 29–30 2026 | 12 npm packages targeting Ethereum/EVM developers: `ethers-abstract-signer` (GHSA-2f7m-g9qw-8288), `ethers-signing-key`, `ethers-contract` (GHSA-gxfh-j6jv-hc58), `ethers-errors`, `ethers-hash`, `ethers-hdnode`, `evmchain-cli`, `evmchain-config`, `foundry-config`, `hardhat-evmchain`, `viem-multichain`, `web3-config-loader` — all any-version wildcards |
| chai testing-library typosquat cluster — May 29–30 2026 | `chai-as-tuned` (GHSA-2f37-mh3q-7394), `chai-bundle` (GHSA-q36r-56hw-2r46), `chai-extensions-extras`, `chai-use-test` — fake Chai extensions, any-version wildcards |
| Tailwind CSS plugin typosquat cluster — May 29–30 2026 | `tailwind-clamps-line` (GHSA-29g5-vw2p-x29p), `tailwind-effect`, `tailwind-smooth-slider`, `tailwindcss-basic-animation`, `tailwind-typography-cssstyle` — fake Tailwind CSS plugins, any-version wildcards |
| zod-to-js Zod-ecosystem typosquat — May 29 2026 (GHSA-8cm2-vv7w-4c27) | `zod-to-js` 13.4.3, 13.4.4 — Zod-to-JS bridge library typosquat |
| May 26 2026 pure-malware typosquat batch (17 packages, GHSA-confirmed) | Web3/DeFi: `web3-prices`, `web3.prc`, `int-node`, `@izumiswap/sdk`; JSON utilities: `jsonlogbundler`, `fastjsonlog`, `jsonbson`; Solidity/Hardhat: `solidity-coverage-plus`, `hardhat-gas-analytics`; document libraries: `pdf-lib-enhanced`, `xlsx-enhanced`; misc: `corelia`, `license-checker-plus`, `lynx-keeper`, `lynx-keeper-cli`, `zest-product`, `tailwind-style-typography` — all any-version (GHSA affected.ranges >=0) |
| crates.io — RustSec malicious advisories | 64 crates removed from crates.io and tagged `categories = ["malicious"]` in `rustsec/advisory-db`. Includes `rustdecimal` (2022 typosquat of `rust_decimal`), the 2023 `amaperf` typosquat cluster (`xrvrv`, `oncecell`, `serd`, `lazystatic`, `if-cfg`, `envlogger`, `postgress`, `postgresderive`, `tauri-winrt-notifications`, `windows-service-rs`, `monero-rpc-rs`, `acceptxmr-rs`, …), the 2026 Polymarket credential-stealer campaign (`polymarket-clients-sdk`, `polymarket-client-sdks`, `polymarkets-client-sdk`, `polymarkets-rs-clob-client`, `clob-sdk`, `rpc-check`), the timeapi.io impersonation cluster (`time_calibrator`, `time_calibrators`, `dnp3times`, `time-sync`, `chrono_anchor`, `tracings`, `tracing-check`, `tracing_checks`, `tracing-ethers`), and build.rs droppers (`mysten-metrics`, `sui-execution-cut`, `pretty-changelog-logger`, `logtrace`, `replit_ruspty`, `finch_cli_rust`, `safe-agent-rs`, `microsoftsystem64`, …). All entries are any-version wildcards (`patched = []` in RustSec). |

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

## License

MIT — see [LICENSE](LICENSE).

Author: Jascha Wanger / Tarnover, LLC
