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
the same day version 2.105.0 was published), and the binding.gyp npm worm campaign
June 5 2026 (73 packages across multiple publishers: ai-sdk-ollama, @ethlete/* scope,
@forjacms/* scope, @vapi-ai/server-sdk, autotel/awaitly/executable-stories/
node-env-resolver ecosystems, Cloudflare Workers tools, and miscellaneous packages;
OSV MAL-2026-5195 through MAL-2026-5267; StepSecurity + Endor Labs disclosure),
and the ulid-os npm full-compromise typosquat June 5 2026
(OSV MAL-2026-5268 / GHSA-fxhm-35h8-7jc7), the utils-mf npm WhatsApp-bot
credential-exfiltration package June 5 2026 (OSV MAL-2026-4699 /
GHSA-4c54-hwv9-c5xm; 10 specific versions), the react-ui-polyfills remote-eval
backdoor npm package June 5 2026 (OSV MAL-2026-4784 / GHSA-v7mj-pmr3-7x4p),
and the June 5 2026 GHSA full-compromise npm pair glyphr
(OSV MAL-2026-5269 / GHSA-c988-j68q-h8h4) and reactvora
(OSV MAL-2026-5270 / GHSA-x4gw-cjrp-c89f), the goodoldtoulas / goodoltoulas
PyPI install-time droppers June 5 2026 (OSV MAL-2026-5271/5272), and the
anthropy PyPI reverse-shell infostealer June 5 2026 (OSV MAL-2026-5273), and
the Woodpecker PyPI infostealer campaign June 6 2026 (twelve legitimate scientific /
systems packages: dynamo-release, napari-ufish, nucbox, pantheon-toolsets,
spateo-release, uprobe, bramin, executor-http, mrbios, okite, synago, ufish;
obfuscated Bun-runtime JS payload exfiltrating credentials and crypto wallet data;
OSV MAL-2026-5274 through MAL-2026-5285), and the dep-confusion 99.x npm batch
extension June 6 2026 (unifi-portal 99.0.0; OSV MAL-2026-5289), and the
clip-logger PyPI clipboard-stealing crypto campaign June 7 2026 (clip-logger
8 versions, bittensor-burn-watch 16 versions; OSV MAL-2026-5292/5293), the
Woodpecker PyPI campaign additional packages June 7 2026 (cmd2func 0.2.2/0.2.3,
magique-ai 0.4.5; OSV MAL-2026-5290/5294), four more Woodpecker packages June 7 2026
(coolbox 0.4.1/0.4.2, magique 0.6.8/0.6.9, executor-engine 0.3.4/0.3.5,
pantheon-agents 0.6.1/0.6.2; OSV MAL-2026-5295/5296/5298/5299),
sequoia-engineering npm malware June 7 2026 (OSV MAL-2026-5291), and
consumerweb-authflow npm malware June 7 2026 (OSV MAL-2026-5297), and
additional Woodpecker PyPI infostealer campaign packages June 8–9 2026
(funcdesc, mflux-streamlit, nhmpy, rlask, rsquests, tlask, dreamgen, mem8,
orchestr8-platform, dstill; OSV MAL-2026-5300 through MAL-2026-5305, 5313,
5319, 5321, 5345), and a bioinformatics supply-chain compromise June 8–9 2026
targeting phenotype-analysis packages (embiggen, ensmallen, gpsea,
phenopacket-store-toolkit, ppkt2synergy, pyphetools; OSV MAL-2026-5314 through
MAL-2026-5316, 5322 through 5324), and the MCP-namespace PyPI typosquat cluster
June 8–9 2026 (instructor-mcp, langchain-core-mcp, openai-mcp, ray-mcp-server,
tiktoken-mcp; OSV MAL-2026-5317/5318/5320/5325/5326), and the Solana ecosystem
PyPI typosquat cluster June 9 2026 (solana-cli-py, solana-web3, solana-web3-py,
spl-token-py; OSV MAL-2026-5336 through MAL-2026-5339), and the Bittensor/crypto
clipboard-stealer extension campaign June 8–27 2026 (bittensor-burn-monitor 7
versions, bt-burn-watch, bittensor-burn-alert, bittensor-burn, bittensor-burn-message,
bittensor-emission-tracker, trongap, trongapy, spaysdatarbx, spaysrbx,
tao-subnet-metrics; OSV MAL-2026-5311/5312/5329/5330/5331/5334/5457/5489/
5680/5681/5683), and the @langgraphjs/toolkit npm any-version wildcard malware
(OSV MAL-2026-2509; SEMVER >=0 range), and June 8 2026 npm dep-confusion batches
(@listings/energy-labels + @zimmo/last_search 99.0.x; @bancolonbia/menu-filter-
widget-web 0.0.1; @demica/{core,resources,shared} 99.99.x;
@doaction/* 15 packages 9.9.9/99.99.99; @0xlr/* 7 packages 999.0.0;
@klapp-*/@easy-entry/@shell-* 12 packages 99.x; @nstrlabs/* 6 packages 99.x;
@oplus/* 3 packages 99.99.99; @orion-design-system/* 3 packages 9999.x;
@solana-labs/* 6 typosquat packages; @403name/* 3 packages;
@onum-releases/* 6 packages; OSV MAL-2026-5327/5328/5344/5349 through 5383/
5385 through 5391/5408 through 5429/5522 through 5525/5547 through 5549/
5786 through 5788/6122 through 6127), and the @mastra npm scope compromise
June 20–27 2026 (89 packages across the @mastra/* namespace, injecting a
credential-exfiltration payload into the Mastra AI agent framework; OSV
MAL-2026-5939 through 5964, 5996 through 6057, 6072 through 6074), and the
easyaillm LLM-utility PyPI typosquat cluster June 18–23 2026 (easyaillm,
easyaillm2, easyllmai, ezllmgen, llmgenerator, llamagenerator, generatellm,
fastgptmini, gptminifast, llmfree; OSV MAL-2026-5756/5765/5766/5769 through
5771/5773/5776/5795/5796), and dep-confusion PyPI batches June 8–27 2026
(nerfstudio-gs 99.0.x, requests-toolbelt-plus 99.9.x, icinga 99.x,
datacamp-light 99.0.0; OSV MAL-2026-5333/5519/5532/5868), and the
AI/LLM toolkit impersonation campaign June 29–30 2026 (anthropic-toolkit
21 versions, ai-sdk-helpers/ollama-helpers/openai-agents-helpers any-version;
OSV MAL-2026-6673/5565/6581/6582), the ts-einkle/ts-ankle TypeScript exploit
cluster June 29 2026 (ts-einkle, ts-einkle-slot, ts-ankle; OSV MAL-2026-6524/
6525/6548), the @thone33 credential-injector scope June 29 2026 (@thone33/
analytics-injector, @thone33/core-utils; OSV MAL-2026-6563/6564), the
@epic-common/observability-node dep-confusion June 29 2026 (OSV MAL-2026-6562),
the Gartner GX dep-confusion cluster June 29 2026 (gx-npm-feature-flags,
gx-npm-lib, gx-npm-ui; OSV MAL-2026-6466/6480/6481), the large dep-confusion
wave June 29 2026 (79 packages across scopes targeting Deel, Postman, Rakuten,
Experian, LexisNexis, Sixt, Gallup, PlanetLabs and others; OSV MAL-2026-6594
through MAL-2026-6672), 25 additional targeted dep-confusion packages June 29 2026
(ing-web-v5, eslint-plugin-totara, @ataslkit/profilecard, @shoobx/types,
@source-row/source-container, @serasa/core, @citi-icg-171632/*, @cloudways-lab/*,
@webd-infra/*, @webda-features/*, uipath-sugar-sell and others; OSV MAL-2026-2822/
2846/2855/2856/2857/2858/2952/2956/2978/4171/4172/4256/4257/4389/4425/4432/4826/
4827/5431/5432/5433/5453/5454/5455/5456), and the miscellaneous npm malware batch
June 29 2026 (55 packages: path-internal-util, http-uploader-dev, react-json-chalk,
tailwind-form, react-pinojs, node-denv, chain-chai-test, ssr-auth-sync, quirky-token,
swift-parse-stream, uol-simple-api-futebol, stackus, clx-cookie-signature, routecraft,
hunsterx-package, hardhat-test-log, base58-core, @vpms/design-system,
unsafe-malicious-package, velocityfix, wellnpm, @appupdate/cdn-sync, chai-as-assured,
crossmint-wallets-sdk, @uisp/utils, date-uuid, eslint-commit-parser, express-mocha-test,
longzy-basic-ui, pkg-fallback (npm), react-wp-viewer, rebrandly-domains-digger/
rebrandly-domains-search-client, yandex-geobase, @ibrahim1337/baksen,
checkmarx-claude-cache, int_sezzle_sfra, layerd-unit-codec-parser, lessload, loadutils,
pino-debugging, poly-kelly, stake-math, yastatic-s3, clob-client-math, endpointmap,
envfile-sync, envfile-sync-cli, ledgerflow-deploy-utils, maplibre-gl-vue3, vkzmn;
OSV MAL-2026-3312/4580/4792/5487/5488/5734/5908/5934/6066/6068/6087/6098/6141/6229/
6337/6369/6445/6467/6486/6487/6501/6524/6525/6531/6532/6545/6548/6562/6563/6564/6565/
6566/6567/6568/6569/6570/6571/6572/6573/6574/6575/6576/6577/6578/6579/6580/6581/6582/
6583/6584/6585/6586/6587/6588/6589/6590/6591/6592/6594 through 6672/6673), and the
PyPI malware batch June 29 2026 (sqligen, inlifegram, pdf-converter-pro any-version;
django-bkvision 1.2.0; OSV MAL-2026-6515/6516/6541/6593), the Polymarket typosquat
cluster June 30 – July 1 2026 (polymarket-clob-maths, polymarket-trading-developer-tools,
polymarket-risk-manager, polymarket-toolkit, polymarket-trading-developer-tool;
OSV MAL-2026-6691/6692/6712/6713/6714), the TypeScript / ESLint / CLOB typosquat
cluster June 30 – July 1 2026 (ts-lint-builders-v2.1, ts-linting-builder, ts-bn-proto,
ts-elinter, ts-eslint-helper, ts-clob-math-v2; OSV MAL-2026-6677/6678/6695/6719/6720/6721),
frontend framework typosquats July 1 2026 (date-fns-lite, svgson-lite, vega-lite-next,
vue-demi-fix, electron-orbit, svgcraft-core; OSV MAL-2026-6702/6707/6709/6715/6722/6723),
Hardhat/Solidity typosquats July 1 2026 (hardhat-compile-ethers, hardhat-plugin-solidity;
OSV MAL-2026-6705/6706), a 16-package GHSA full-compromise batch July 1 2026
(rs-biginteger, terminal-prettier, agent-starter-pack, brock-loader, brock-react-alerts,
confluent-kafka-javascript, nbmolviz-js, postcss-property-rollup, quoting, setup-cicd,
procwire, console-fmt-cli, decimal-format-core, log-taker1, thirdwb, thirdwebb;
OSV MAL-2026-6675/6676/6679/6680/6681/6682/6683/6684/6685/6686/6687/6688/6689/6690/6693/6694),
miscellaneous npm malware June 30 – July 1 2026 (pp-react-v5, triage-bot, sypoi1,
ripshakti, ripshakti1, ecto-corsair-flag-7kq3mz, module-index-cache, zyncmap,
vitest-agent, base65-85x, test-pkg-pnpm, test-pkg-x0, test-pkg-yarn;
OSV MAL-2026-3509/6346/6405/6674/6699/6700/6701/6704/6708/6710/6716/6717/6718),
dependency-confusion packages June 30 – July 1 2026
(@businessapp-microsites/apis, @sudoughnym/enviro-demo, @andes-tools/colors,
cursed-modules; OSV MAL-2026-6696/6697/6698/6703), and Woodpecker campaign update
July 1 2026 (magique-ai 0.4.4 added to existing 0.4.5 entry;
OSV MAL-2026-5294) and new PyPI malware twrap-tool (OSV MAL-2026-6711) and
starlette-healthcheck (OSV MAL-2026-6724).

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
Date:      2026-07-04
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
    # lightning: same campaign (2026-04-compr-lightning) and same maintainer compromise as
    # pytorch-lightning above; `lightning` is the renamed unified package published by
    # Lightning AI alongside `pytorch-lightning`. Both packages had versions 2.6.2 and 2.6.3
    # removed from PyPI after the attack. Specific versions only (no >=0 range in OSV record).
    # OSV MAL-2026-3201 (kam193); confirmed by Aikido aikido.dev/blog/pytorch-lightning-pypi-compromise-mini-shai-hulud
    # and Socket socket.dev/blog/lightning-pypi-package-compromised
    "lightning": {"2.6.2", "2.6.3"},
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
    # goodoldtoulas / goodoltoulas PyPI install-time droppers (June 5 2026)
    # Both overrides setup.py install command to download and execute a remote Windows
    # executable during pip install. Classified PROBABLY_PENTEST by kam193; active
    # OSV records, single version each published before takedown.
    # OSV MAL-2026-5271 / https://bad-packages.kam193.eu/pypi/package/goodoldtoulas
    "goodoldtoulas": {"0.1.0"},
    # OSV MAL-2026-5272 / https://bad-packages.kam193.eu/pypi/package/goodoltoulas
    "goodoltoulas": {"0.1.0"},
    # anthropy PyPI reverse-shell infostealer (June 5 2026)
    # On import the package starts a reverse shell. Categorized MALICIOUS (clearly
    # malicious intent) by kam193. Six consecutive versions published before takedown.
    # OSV MAL-2026-5273 / https://bad-packages.kam193.eu/pypi/package/anthropy
    "anthropy": {"0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"},
    # clip-logger PyPI clipboard-stealing crypto campaign (June 7 2026)
    # Both packages periodically monitor the clipboard for content matching patterns
    # consistent with cryptocurrency secret phrases (BIP-39 mnemonics), then
    # exfiltrate any match to a hardcoded remote endpoint. Early versions of
    # clip-logger documented this behaviour explicitly in the README.
    # Targeted data are likely cryptocurrency recovery phrases / private keys.
    # Detected and reported by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5293 (clip-logger), MAL-2026-5292 (bittensor-burn-watch)
    "clip-logger": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4",
        "1.1.0", "1.1.1", "1.1.2",
    },
    "bittensor-burn-watch": {
        "1.2.0", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7",
        "1.2.9", "1.2.10", "1.2.11", "1.2.12",
        "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4",
    },
    # Woodpecker PyPI infostealer campaign (June 6 2026)
    # Twelve legitimate scientific / systems packages had specific versions compromised.
    # Each ships a heavily obfuscated JavaScript payload executed via Bun runtime on
    # Python startup. The payload collects API keys, PyPI/npm/GitHub credentials,
    # cryptocurrency wallet keystores, and password-manager data, then exfiltrates
    # via GitHub. It also attempts persistence and self-propagation by republishing
    # infected copies using stolen registry credentials. Described by kam193 as
    # related to the Mini Shai Hulud worm campaign.
    # Primary source: OSV (kam193/bad-packages.eu); exact versions only (no >=0 range).
    # OSV MAL-2026-5274 (dynamo-release)
    "dynamo-release": {"1.5.4"},
    # OSV MAL-2026-5275 / https://bad-packages.kam193.eu/pypi/package/napari-ufish
    "napari-ufish": {"0.0.2", "0.0.3"},
    # OSV MAL-2026-5276 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "nucbox": {"0.1.2", "0.1.3"},
    # OSV MAL-2026-5277
    "pantheon-toolsets": {"0.5.5", "0.5.6"},
    # OSV MAL-2026-5278
    "spateo-release": {"1.1.2"},
    # OSV MAL-2026-5279
    "uprobe": {"0.1.3", "0.1.4"},
    # Six additional Woodpecker packages confirmed June 6 2026 (same campaign)
    # OSV MAL-2026-5280
    "bramin": {"0.0.3", "0.0.4"},
    # OSV MAL-2026-5281
    "executor-http": {"0.1.3", "0.1.4"},
    # OSV MAL-2026-5282
    "mrbios": {"0.1.1", "0.1.2"},
    # OSV MAL-2026-5283
    "okite": {"0.0.7", "0.0.8"},
    # OSV MAL-2026-5284
    "synago": {"0.1.1", "0.1.2"},
    # OSV MAL-2026-5285
    "ufish": {"0.1.2", "0.1.3"},
    # Two additional Woodpecker campaign packages confirmed June 7 2026 (same campaign)
    # cmd2func: versions 0.2.2 and 0.2.3 were compromised with the same obfuscated
    #   Bun-runtime JS infostealer payload as the rest of the Woodpecker cluster.
    #   OSV MAL-2026-5290 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "cmd2func": {"0.2.2", "0.2.3"},
    # magique-ai: versions 0.4.4 and 0.4.5 were compromised with the same Woodpecker payload.
    #   OSV MAL-2026-5294 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "magique-ai": {"0.4.4", "0.4.5"},
    # Four additional Woodpecker campaign packages confirmed June 7 2026 (same campaign)
    # OSV MAL-2026-5295 / https://bad-packages.kam193.eu/pypi/campaign/2026-06-compr-woodpecker
    "coolbox": {"0.4.1", "0.4.2"},
    # OSV MAL-2026-5296
    "magique": {"0.6.8", "0.6.9"},
    # OSV MAL-2026-5298
    "executor-engine": {"0.3.4", "0.3.5"},
    # OSV MAL-2026-5299
    "pantheon-agents": {"0.6.1", "0.6.2"},
    # Woodpecker PyPI infostealer campaign continuation (June 8–9 2026)
    # Same campaign actor; additional legitimate Python packages compromised
    # with the Bun-runtime JS credential-exfiltration payload targeting API
    # keys, registry credentials, crypto wallet keystores, and password-manager
    # data, then exfiltrates via GitHub.
    # OSV MAL-2026-5300 (funcdesc), 5301 (mflux-streamlit), 5302 (nhmpy),
    # 5303 (rlask), 5304 (rsquests), 5305 (tlask), 5313 (dreamgen),
    # 5319 (mem8), 5321 (orchestr8-platform), 5345 (dstill)
    "funcdesc": {"0.2.2", "0.2.3"},
    "mflux-streamlit": {"0.0.3", "0.0.4"},
    "nhmpy": {"2.4.6", "2.4.7"},
    "rlask": {"3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7"},
    "rsquests": {"2.34.2", "2.34.3"},
    "tlask": {"3.1.3", "3.1.4"},
    "dreamgen": {"1.8.1"},
    "mem8": {"6.0.1"},
    "orchestr8-platform": {"3.3.2"},
    "dstill": {"0.3.0"},
    # Bioinformatics supply-chain compromise (June 8–9 2026)
    # Six legitimate phenotype-analysis and bioinformatics packages compromised
    # with a malicious payload using the same attacker technique as the
    # Woodpecker campaign. All published as specific versions before takedown.
    # OSV MAL-2026-5314 (embiggen), 5315 (ensmallen), 5316 (gpsea),
    # 5322 (phenopacket-store-toolkit), 5323 (ppkt2synergy), 5324 (pyphetools)
    "embiggen": {"0.11.97"},
    "ensmallen": {"0.8.101"},
    "gpsea": {"0.9.14"},
    "phenopacket-store-toolkit": {"0.1.7"},
    "ppkt2synergy": {"0.1.1"},
    "pyphetools": {"0.9.120"},
    # MCP-namespace PyPI typosquat cluster (June 8–9 2026)
    # Five packages impersonating popular ML libraries with an "-mcp" or
    # "-mcp-server" suffix; they silently exfiltrate environment variables
    # and credentials on import. Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-5317 (instructor-mcp), 5318 (langchain-core-mcp),
    # 5320 (openai-mcp), 5325 (ray-mcp-server), 5326 (tiktoken-mcp)
    "instructor-mcp": {"1.15.2", "1.15.3"},
    "langchain-core-mcp": {"1.4.2", "1.4.3"},
    "openai-mcp": {"2.41.1", "2.41.2"},
    "ray-mcp-server": {"0.2.1"},
    "tiktoken-mcp": {"0.13.1", "0.13.2"},
    # Solana ecosystem PyPI typosquat cluster (June 9 2026)
    # Four packages masquerading as official Solana Python SDK tooling; each
    # publishes version 1.0.0 with an install-time credential/wallet exfiltrator.
    # OSV MAL-2026-5336 (solana-cli-py), 5337 (solana-web3),
    # 5338 (solana-web3-py), 5339 (spl-token-py)
    "solana-cli-py": {"1.0.0"},
    "solana-web3": {"1.0.0"},
    "solana-web3-py": {"1.0.0"},
    "spl-token-py": {"1.0.0"},
    # Bittensor/crypto clipboard-stealer extension (June 8–27 2026)
    # Related to the clip-logger / bittensor-burn-watch campaign already tracked.
    # Multiple packages continuously published exfiltrating clipboard and env data,
    # targeting BIP-39 mnemonics, crypto wallet seeds, and Bittensor keys.
    # OSV MAL-2026-5311 (bittensor-burn-monitor), 5312 (bt-burn-watch),
    # 5329 (spaysdatarbx), 5330 (bittensor-burn-alert), 5331 (bittensor-burn),
    # 5334 (spaysrbx), 5457 (tao-subnet-metrics), 5489 (bittensor-emission-tracker),
    # 5680 (bittensor-burn-message), 5681 (trongap), 5683 (trongapy)
    "bt-burn-watch": {"1.4.0"},
    "bittensor-burn-monitor": {
        "1.5.0", "1.5.3", "1.5.5",
        "1.6.0", "1.6.3", "1.6.5",
        "1.7.0",
    },
    "spaysdatarbx": {"0.1.3", "0.1.5"},
    "bittensor-burn-alert": {"1.7.3", "1.7.4", "1.7.5"},
    "bittensor-burn": {"1.8.0", "1.8.1"},
    "spaysrbx": {"0.3.0"},
    "tao-subnet-metrics": {"1.0.1"},
    "bittensor-emission-tracker": {"1.0.1"},
    "bittensor-burn-message": {"1.0.1"},
    "trongap": {"0.0.1"},
    "trongapy": {"0.0.1"},
    # easyaillm LLM-utility PyPI typosquat cluster (June 18–23 2026)
    # Ten look-alike packages mimicking popular LLM utilities exfiltrating
    # environment variables and API keys on import. Linked by shared
    # version-numbering scheme (2.x series) and identical payload structure.
    # OSV MAL-2026-5756 (easyaillm), 5765 (easyaillm2), 5766 (easyllmai),
    # 5769 (ezllmgen), 5770 (llmgenerator), 5771 (llamagenerator),
    # 5773 (generatellm), 5776 (fastgptmini), 5795 (gptminifast), 5796 (llmfree)
    "easyaillm": {"2.0.15", "2.0.16"},
    "easyaillm2": {"2.0.16", "2.0.17", "2.0.18", "2.0.67", "2.0.68"},
    "easyllmai": {"2.1", "2.21"},
    "ezllmgen": {"2.21"},
    "llmgenerator": {"2.21"},
    "llamagenerator": {"2.22"},
    "generatellm": {"2.21", "2.22", "2.23"},
    "fastgptmini": {"2.21", "2.22", "2.23", "2.24", "2.25", "2.26"},
    "gptminifast": {"2.21"},
    "llmfree": {"2.21"},
    # Dep-confusion PyPI batches (June 8–27 2026)
    # Packages published at inflated version numbers targeting private CI
    # pipelines; no legitimate public release history at these versions.
    # OSV MAL-2026-5333 (nerfstudio-gs), 5519 (requests-toolbelt-plus),
    # 5532 (icinga), 5868 (datacamp-light)
    "nerfstudio-gs": {"99.0.0", "99.0.1", "99.0.2", "99.0.3"},
    "requests-toolbelt-plus": {"99.9.9", "99.9.10", "100.0.0"},
    "icinga": {"99.1.0", "99.2.0"},
    "datacamp-light": {"99.0.0"},
    # Malicious install-time infostealer / credential-grabber batch (June 27–28 2026)
    # discord-token-generator: token-harvesting tool with C2 exfiltration.
    # fsociety-tools: reverse-shell / credential-stealer named after Mr. Robot persona.
    # tdata-grabber: Telegram session-data exfiltrator targeting .tdata directories.
    # skillspector: env-var and credential exfiltrator using split versioning (0.0.x / 2.3.x).
    # pkg-fallback: generic name dep-confusion dropper, any version.
    # OSV MAL-2026-6549 (discord-token-generator), MAL-2026-6558 (fsociety-tools),
    # MAL-2026-6560 (tdata-grabber), MAL-2026-6561 (skillspector), MAL-2026-6557 (pkg-fallback)
    "discord-token-generator": {"1.0.0", "1.0.1", "1.0.2", "1.0.3"},
    "fsociety-tools": {"1.0.0", "1.0.1", "1.0.2"},
    "tdata-grabber": {"1.0.0"},
    "skillspector": {"0.0.1", "0.0.2", "0.0.3", "0.0.4", "2.3.7", "2.3.8", "2.3.9", "2.3.10"},
    "pkg-fallback": set(),
    # Miscellaneous PyPI malware batch (June 29 2026)
    # sqligen: SQL-helper package with obfuscated credential-exfiltration postinstall;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6515.
    # inlifegram: Instagram-API wrapper with data-exfiltration payload;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6516.
    # pdf-converter-pro: PDF conversion tool with malicious postinstall dropper;
    #   any version is malicious (ranges: introduced 0). OSV MAL-2026-6541.
    # django-bkvision: Django vision module with malicious install-time payload;
    #   only version 1.2.0 was published. OSV MAL-2026-6593.
    "sqligen": set(),
    "inlifegram": set(),
    "pdf-converter-pro": set(),
    "django-bkvision": {"1.2.0"},
    # twrap-tool PyPI malware (July 1 2026)
    # Install-time credential-exfiltration dropper; single version published before takedown.
    # OSV MAL-2026-6711.
    "twrap-tool": {"1.0.0"},
    # starlette-healthcheck PyPI malware (July 1 2026)
    # Typosquat of starlette-healthcheck ASGI extension; three consecutive malicious versions.
    # OSV MAL-2026-6724.
    "starlette-healthcheck": {"1.2.0", "1.3.0", "1.3.1"},
    # dt-validator PyPI remote-code-executor (July 2 2026)
    # Contains a function to execute remote code; single version 0.3.0 published before takedown.
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-6728
    "dt-validator": {"0.3.0"},
    # Unreal Engine / Epic Games dep-confusion PyPI cluster (July 2 2026)
    # Four packages published at version 99999.0.0 impersonating Unreal Engine and Epic
    # Games internal Python tooling; installing or importing exfiltrates host information.
    # All detected by kam193 / bad-packages.kam193.eu. No >=0 range in OSV records — pin version.
    # OSV MAL-2026-6733 (epic-build-scripts), MAL-2026-6734 (horde-python-client),
    # MAL-2026-6735 (ue-python-tools), MAL-2026-6736 (unreal-mladapter)
    "epic-build-scripts": {"99999.0.0"},
    "horde-python-client": {"99999.0.0"},
    "ue-python-tools": {"99999.0.0"},
    "unreal-mladapter": {"99999.0.0"},
    # haproxy-config-client / ipa-user-collector PyPI downloader campaign (July 4 2026)
    # Both packages use obfuscated install-time code to download a malicious executable
    # (VirusTotal hash d47a2d1b96df84b10263a99866b865421b334448432d1b447b82c76253bcbe86).
    # Detected by kam193 / bad-packages.kam193.eu.
    # OSV MAL-2026-6748 (haproxy-config-client), MAL-2026-6749 (ipa-user-collector)
    "haproxy-config-client": {"8.5.3"},
    "ipa-user-collector": {"8.5.3"},
    # procwire PyPI campaign (July 4 2026)
    # Multi-package campaign sharing a common VirusTotal-confirmed dropper payload.
    # procwire: the trigger package; 4 malicious versions published. OSV MAL-2026-6750.
    # bytekit: same campaign; 2 malicious versions. OSV MAL-2026-6751.
    # confighub: depends on malicious procwire; 2 versions. OSV MAL-2026-6752.
    # schemavault: same campaign payload; 2 malicious versions. OSV MAL-2026-6753.
    # All detected by kam193 / bad-packages.kam193.eu.
    "procwire": {"5.2.3", "5.2.5", "5.2.6", "5.2.7"},
    "bytekit": {"3.4.1", "3.4.2"},
    "confighub": {"7.0.1", "7.0.2"},
    "schemavault": {"4.1.0", "4.1.1"},
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
    # OSV MAL-2026-5114 / GHSA-cxfw-p322-rfrv (frontend-components-config-utilities; updated: 4.11.3, 4.11.5)
    # OSV MAL-2026-5115 / GHSA-mj98-cgm5-6xrr (quickstarts-client)
    # OSV MAL-2026-5116 / GHSA-2p99-xvqh-j893 (rbac-client; updated: 9.0.4, 9.0.6)
    # OSV MAL-2026-5117 / GHSA-c4gm-6fh3-76v9 (rule-components)
    # OSV MAL-2026-5118 / GHSA-9wp8-557p-2hvf (topological-inventory-client; updated: 3.0.11, 3.0.13)
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
    # IronWorm supply-chain campaign (June 4 2026) — WeaveDB / Arweave ecosystem
    # A Rust-compiled 976 KB ELF x86-64 binary (sha256
    # 36abd242ddaa27f0160c539377a0e92cf781c1695137850acc87e3892b436d36) is shipped
    # inside npm tarballs and executed automatically via preinstall hooks on
    # `npm install`. The binary harvests developer credentials: cloud provider keys,
    # SSH key material, npm auth tokens, and crypto wallet keystores, then exfiltrates
    # them over HTTP. Targets the WeaveDB decentralised-database ecosystem and related
    # Arweave / blockchain developer tooling. JFrog calls it "Shai-Hulud's rustier
    # cousin"; OX Security confirmed the campaign independently with identical version lists.
    # Two independent vendor writeups agree on the full version list:
    #   OX Security ox.security/blog/ironworm-supply-chain-malware-hits-npm/
    #   JFrog       research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    # OSV MAL-2026-4476 (ai3), 4480 (aonote), 4482 (arnext), 4483 (arnext-arkb),
    # 4486 (atomic-notes), 4538 (create-arnext-app), 4544 (cwao), 4545 (cwao-tools),
    # 4546 (cwao-units), 4566 (fpjson-lang), 4613 (monade), 4663 (roidjs),
    # 4689 (test-ajs), 4690 (test-weavedb-sdk), 4691 (testnpmnmp), 4711 (wao),
    # 4712 (warp-contracts-plugin-deploy-test), 4713 (wdb-cli), 4714 (wdb-sdk),
    # 4715 (weavedb-base), 4716 (weavedb-client), 4717 (weavedb-console),
    # 4718 (weavedb-exm-sdk), 4719 (weavedb-exm-sdk-web), 4720 (weavedb-lite),
    # 4721 (weavedb-node-client), 4722 (weavedb-offchain), 4723 (weavedb-sdk),
    # 4724 (weavedb-sdk-base), 4725 (weavedb-sdk-node), 4726 (weavedb-tools),
    # 4727 (weavedb-warp-contracts-plugin-deploy), 4739 (zkjson),
    # 5189 (arjson), 5190 (hbsig), 5191 (wdb-core), 5192 (weavedb-contracts)
    "ai3": {"0.3.5"},
    "aonote": {"0.11.1"},
    "arnext": {"0.1.5"},
    "arnext-arkb": {"0.0.2"},
    "atomic-notes": {"0.5.3"},
    "create-arnext-app": {"0.0.10"},
    "cwao": {"0.5.6"},
    "cwao-tools": {"0.3.1"},
    "cwao-units": {"0.8.3"},
    "fpjson-lang": {"0.1.7"},
    "monade": {"0.0.7"},
    "roidjs": {"0.1.7"},
    "test-ajs": {"0.1.19"},
    "test-weavedb-sdk": {"1.1.1"},
    "testnpmnmp": {"1.0.21"},
    "wao": {"0.41.2", "0.41.3", "0.41.4"},
    "warp-contracts-plugin-deploy-test": {"3.0.1"},
    "wdb-cli": {"0.1.1"},
    "wdb-sdk": {"0.1.2"},
    "weavedb-base": {"0.45.3"},
    "weavedb-client": {"0.45.3"},
    "weavedb-console": {"0.2.1"},
    "weavedb-exm-sdk": {"0.7.4"},
    "weavedb-exm-sdk-web": {"0.7.4"},
    "weavedb-lite": {"0.1.1"},
    "weavedb-node-client": {"0.45.3"},
    "weavedb-offchain": {"0.45.4"},
    "weavedb-sdk": {"0.45.3"},
    "weavedb-sdk-base": {"0.21.1"},
    "weavedb-sdk-node": {"0.45.3"},
    "weavedb-tools": {"0.45.3"},
    "weavedb-warp-contracts-plugin-deploy": {"1.0.11"},
    "zkjson": {"0.8.5"},
    "arjson": {"0.1.4"},
    "hbsig": {"0.3.2"},
    "wdb-core": {"0.1.2"},
    "weavedb-contracts": {"0.45.2"},
    # hello244a npm malware (June 4 2026)
    # Communicates with a domain associated with malicious activity and executes
    # commands associated with malicious behavior; detected by OpenSSF Package Analysis.
    # OSV MAL-2026-5188
    "hello244a": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # IronWorm supplemental packages (June 5 2026)
    # Additional npm packages in the IronWorm campaign carrying the same Rust-compiled
    # x86-64 ELF preinstall dropper that exfiltrates cloud keys, SSH material, npm tokens,
    # and crypto wallet keystores. These impersonate widely-used JavaScript utility libraries
    # (js-yaml, crypto-js, Microsoft Application Insights, Supabase client, etc.).
    # Two independent vendors confirm the same package list and campaign attribution:
    #   OX Security ox.security/blog/ironworm-supply-chain-malware-hits-npm/
    #   JFrog       research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
    # auth-javascript:                   OSV MAL-2026-3648 (SEMVER >=0 — any version)
    # iceberg-javascript:                OSV MAL-2026-3649 (SEMVER >=0 — any version)
    # microsoft-applicationinsights-common: OSV MAL-2026-3650 (SEMVER >=0 — any version)
    # ms-graph-types:                    OSV MAL-2026-3651 (SEMVER >=0 — any version)
    # supabase-javascript:               OSV MAL-2026-3652 (SEMVER >=0 — any version)
    # crypto-javascri:                   OSV MAL-2026-3508 (15 specific versions; no >=0 range)
    # crypto-javascript:                 OSV MAL-2026-4542 (5 specific versions; no >=0 range)
    # javascript-yaml:                   OSV MAL-2026-5193 (1 specific version; no >=0 range)
    # yaml-javascript:                   OSV MAL-2026-5194 (1 specific version; no >=0 range)
    "auth-javascript": set(),
    "iceberg-javascript": set(),
    "microsoft-applicationinsights-common": set(),
    "ms-graph-types": set(),
    "supabase-javascript": set(),
    "crypto-javascri": {
        "1.0.1", "1.2.1", "1.2.6", "1.2.8", "1.2.10", "1.2.11", "1.2.12",
        "1.3.6", "1.3.7", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "3.0.1",
    },
    "crypto-javascript": {"4.2.5", "4.2.10", "4.3.1", "4.3.4", "4.3.6"},
    "javascript-yaml": {"4.1.2"},
    "yaml-javascript": {"4.1.2"},
    # binding.gyp npm worm campaign (June 5 2026) — multiple publisher accounts compromised
    # A worm-style attack exploiting binding.gyp (native Node.js build files) to spread
    # across packages during npm install. Initial discovery: ai-sdk-ollama. The worm
    # spread to packages from many independent publishers: autotel, awaitly,
    # executable-stories, node-env-resolver, @ethlete, @forjacms, @vapi-ai, and others.
    # These are legitimate packages where specific versions were infected; pin exact
    # versions (not empty-set wildcards). Two independent sources agree on version lists:
    #   StepSecurity stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
    #   Endor Labs   endorlabs.com/learn/malicious-payload-in-ai-sdk-ollama-npm-package
    #   OSV MAL-2026-5195 through MAL-2026-5267
    # ai-sdk-ollama — initial discovery (OSV MAL-2026-5210)
    "ai-sdk-ollama": {"0.13.1", "1.1.1", "2.2.1", "3.8.5"},
    # @contaazul/n8n-nodes-contaazul (OSV MAL-2026-5195)
    "@contaazul/n8n-nodes-contaazul": {"0.3.26"},
    # @ethlete Angular component library scope — account compromise
    # OSV MAL-2026-5196 (@ethlete/cdk), 5197 (cli), 5198 (components),
    # 5199 (contentful), 5200 (core), 5201 (dsp), 5202 (query), 5203 (theming), 5204 (types)
    "@ethlete/cdk": {"4.71.2"},
    "@ethlete/cli": {"2.0.1"},
    "@ethlete/components": {"3.3.1"},
    "@ethlete/contentful": {"3.9.1"},
    "@ethlete/core": {"4.31.1"},
    "@ethlete/dsp": {"0.3.1"},
    "@ethlete/query": {"5.43.2"},
    "@ethlete/theming": {"2.7.1"},
    "@ethlete/types": {"1.11.4"},
    # @forjacms CMS scope compromise
    # OSV MAL-2026-5205 (analytics), 5206 (client), 5207 (sections), 5208 (sections-react)
    "@forjacms/analytics": {"1.8.4", "1.8.5"},
    "@forjacms/client": {"1.8.4", "1.8.5"},
    "@forjacms/sections": {"1.8.4", "1.8.5"},
    "@forjacms/sections-react": {"1.8.4", "1.8.5"},
    # @vapi-ai voice API SDK compromise (OSV MAL-2026-5209)
    "@vapi-ai/server-sdk": {"0.11.1", "0.11.2", "1.2.1", "1.2.2"},
    # autotel OpenTelemetry wrapper ecosystem
    # OSV MAL-2026-5211 (autotel), 5212 (adapters), 5213 (audit), 5214 (aws),
    # 5215 (backends), 5216 (cli), 5217 (cloudflare), 5218 (devtools), 5219 (drizzle),
    # 5220 (edge), 5221 (eventcatalog), 5222 (hono), 5223 (mcp), 5224 (mcp-instrumentation),
    # 5225 (mongoose), 5226 (pact), 5227 (playwright), 5228 (plugins), 5229 (sentry),
    # 5230 (subscribers), 5231 (tanstack), 5232 (vitest), 5233 (web)
    "autotel": {"2.26.4", "3.4.3"},
    "autotel-adapters": {"0.3.5"},
    "autotel-audit": {"0.1.15"},
    "autotel-aws": {"0.13.10"},
    "autotel-backends": {"2.12.26"},
    "autotel-cli": {"0.8.14"},
    "autotel-cloudflare": {"2.18.16"},
    "autotel-devtools": {"0.1.1", "1.0.4", "2.1.1", "3.0.2", "4.0.1", "5.1.1", "6.1.2", "6.2.0"},
    "autotel-drizzle": {"0.0.27"},
    "autotel-edge": {"3.16.13"},
    "autotel-eventcatalog": {"1.0.1", "2.0.1", "3.0.1", "4.0.2", "5.0.1"},
    "autotel-hono": {"0.4.26"},
    "autotel-mcp": {
        "0.1.14", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1",
        "9.0.1", "10.0.1", "11.0.1", "13.0.1", "14.0.1", "15.0.2", "16.0.1",
        "17.0.2", "18.0.1", "19.0.1", "20.0.1", "21.1.1", "22.0.1", "23.0.1",
        "24.0.1", "25.0.1", "26.0.2", "27.0.1", "28.0.3", "29.0.1",
    },
    "autotel-mcp-instrumentation": {
        "29.0.2", "30.0.5", "31.0.1", "32.0.1", "33.0.2", "34.0.1",
    },
    "autotel-mongoose": {"0.0.3", "1.0.2", "2.0.5", "3.0.1", "4.0.1", "5.0.2", "6.0.1"},
    "autotel-pact": {"0.2.2", "1.0.3"},
    "autotel-playwright": {"0.4.32"},
    "autotel-plugins": {"0.19.26"},
    "autotel-sentry": {"0.5.13"},
    "autotel-subscribers": {
        "4.1.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1", "9.0.1", "10.0.1", "11.0.1",
        "12.0.1", "13.0.1", "14.1.1", "15.0.1", "16.0.2", "17.0.1", "18.0.3",
        "19.0.1", "20.0.1", "21.0.1", "22.0.2", "23.0.2", "24.0.1", "25.0.1",
        "26.0.1", "27.0.2", "28.0.2", "29.0.6", "30.0.4", "31.1.4",
    },
    "autotel-tanstack": {"1.13.27"},
    "autotel-vitest": {"0.4.26"},
    "autotel-web": {"1.12.2"},
    # awaitly async library ecosystem
    # OSV MAL-2026-5234 (awaitly), 5235 (analyze), 5236 (libsql),
    # 5237 (mongo), 5238 (postgres), 5239 (visualizer)
    "awaitly": {"1.33.3"},
    "awaitly-analyze": {"0.24.2", "1.1.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1"},
    "awaitly-libsql": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.1.1", "19.0.1", "20.0.1", "21.0.1", "22.0.1",
    },
    "awaitly-mongo": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.1.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.0.1", "19.1.1", "20.0.1", "21.0.1",
        "22.0.1", "23.0.1",
    },
    "awaitly-postgres": {
        "0.1.1", "1.0.1", "2.0.1", "3.0.2", "4.0.1", "5.0.1", "6.0.1", "7.0.1",
        "8.0.1", "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1",
        "15.0.1", "16.0.1", "17.0.1", "18.0.1", "19.1.1", "20.0.1", "21.0.1",
        "22.0.1", "23.0.1",
    },
    "awaitly-visualizer": {
        "1.0.1", "2.0.2", "3.0.1", "4.0.1", "5.0.1", "6.0.1", "7.0.1", "8.0.1",
        "9.0.1", "10.0.1", "11.0.1", "12.0.1", "13.0.1", "14.0.1", "15.0.1",
        "16.0.1", "17.0.1", "18.1.1", "19.0.1", "20.0.2", "21.0.1", "22.0.2",
    },
    # executable-stories testing framework + awaitly eslint ecosystem
    # OSV MAL-2026-5246 (eslint-plugin-awaitly), 5247 (eslint-plugin-executable-stories-jest),
    # 5248 (eslint-plugin-executable-stories-playwright), 5249 (eslint-plugin-executable-stories-vitest),
    # 5250 (executable-stories-cypress), 5251 (demo), 5252 (formatters), 5253 (init),
    # 5254 (jest), 5255 (mcp), 5256 (playwright), 5257 (react), 5258 (vitest)
    "eslint-plugin-awaitly": {"0.17.1", "1.0.1"},
    "eslint-plugin-executable-stories-jest": {"1.2.1", "2.1.8"},
    "eslint-plugin-executable-stories-playwright": {"1.2.1", "2.1.8"},
    "eslint-plugin-executable-stories-vitest": {"1.2.1", "2.1.8"},
    "executable-stories-cypress": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.2"},
    "executable-stories-demo": {"0.1.11"},
    "executable-stories-formatters": {"0.11.2"},
    "executable-stories-init": {"0.1.2"},
    "executable-stories-jest": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.2"},
    "executable-stories-mcp": {"0.3.3"},
    "executable-stories-playwright": {"3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.4.3"},
    "executable-stories-react": {"0.1.7"},
    "executable-stories-vitest": {"2.0.1", "3.1.1", "4.0.1", "5.0.1", "6.1.1", "7.0.3", "8.3.3"},
    # node-env-resolver environment variable library ecosystem
    # OSV MAL-2026-5262 (node-env-resolver), 5263 (aws), 5264 (dotenvx), 5265 (nextjs), 5266 (vite)
    "node-env-resolver": {"6.5.1"},
    "node-env-resolver-aws": {"9.1.2", "10.0.1", "11.0.1", "12.0.1"},
    "node-env-resolver-dotenvx": {"1.0.1", "2.0.1"},
    "node-env-resolver-nextjs": {"7.4.2"},
    "node-env-resolver-vite": {"2.4.2"},
    # Cloudflare Workers deployment tools
    # OSV MAL-2026-5240 (create-cf-token), 5241 (create-wrangler-deploy), 5267 (wrangler-deploy)
    "create-cf-token": {"1.1.2", "1.1.3"},
    "create-wrangler-deploy": {"0.1.1"},
    "wrangler-deploy": {"1.5.5"},
    # Miscellaneous packages from the binding.gyp worm campaign
    # OSV MAL-2026-5242 (creditcard.js), 5243 (dbmux), 5244 (discord-search),
    # 5245 (effect-analyzer), 5259 (github-archiver), 5260 (mountly), 5261 (mountly-tailwind)
    "creditcard.js": {"2.1.8", "3.0.60"},
    "dbmux": {"1.0.5"},
    "discord-search": {"0.1.1", "0.1.2"},
    "effect-analyzer": {"0.3.1"},
    "github-archiver": {"1.5.4", "1.5.5"},
    "mountly": {"0.2.2"},
    "mountly-tailwind": {"0.1.3"},
    # ulid-os npm full-compromise typosquat (June 5 2026)
    # GHSA-confirmed any-version malware: "Any computer that has this package installed or
    # running should be considered fully compromised." OSV affected.ranges >=0 — use
    # the empty-set wildcard so any re-uploaded version is caught.
    # OSV MAL-2026-5268 / GHSA-fxhm-35h8-7jc7
    "ulid-os": set(),
    # utils-mf npm WhatsApp-bot + data-exfiltration + silent self-updater (June 5 2026)
    # Ships a 15.7 MB obfuscator.io blob padded with invisible Unicode whitespace to
    # conceal its contents.  On require() it: (1) opens a WhatsApp socket that prompts
    # on stdin for a pairing-code phone number and persists credential state in ./sessions/;
    # (2) runs a 30-second setInterval that PUTs accumulated chat/contact/env state to the
    # attacker's GitHub and GitLab repos; (3) fetches the latest tarball from the npm
    # registry and silently overwrites node_modules/utils-mf/ at runtime to enable
    # remote payload updates without a reinstall.  First published May 21 2026; GHSA alias
    # confirmed June 5 2026 by amazon-inspector.  No >=0 range in OSV — pin exact versions.
    # OSV MAL-2026-4699 / GHSA-4c54-hwv9-c5xm
    "utils-mf": {
        "11.2.4", "11.2.5", "11.2.6", "11.4.1",
        "11.9.8", "11.9.9", "12.0.1", "12.0.2", "12.1.0", "12.1.1",
    },
    # react-ui-polyfills remote-eval backdoor (June 5 2026)
    # Advertises itself as React polyfills / UI compatibility helpers but ships no React
    # or polyfill code.  The exported getPlugin() function fetches JSON from a mutable
    # jsonkeeper.com paste URL and passes the returned .cookie field directly to eval(),
    # executing attacker-controlled JavaScript in the consumer's process.  First published
    # May 26 2026; GHSA alias confirmed June 5 2026.  OSV has both specific versions (1.0.0,
    # 1.2.7) and a >=0 SEMVER range — per convention the whole package is malicious; use
    # the empty-set wildcard.
    # OSV MAL-2026-4784 / GHSA-v7mj-pmr3-7x4p
    "react-ui-polyfills": set(),
    # June 5 2026 GHSA full-compromise npm pair
    # glyphr: GHSA-confirmed any-version; CWE-506 embedded malicious code.
    #   OSV MAL-2026-5269 / GHSA-c988-j68q-h8h4
    # reactvora: GHSA-confirmed any-version; CWE-506 embedded malicious code.
    #   OSV MAL-2026-5270 / GHSA-x4gw-cjrp-c89f
    "glyphr": set(),
    "reactvora": set(),
    # Dep-confusion 99.x npm batch (June 6 2026)
    # Four packages published at version 99.0.0 detected by OpenSSF Package Analysis
    # communicating with a domain associated with malicious activity. High-version
    # shadow pattern typical of dependency-confusion attacks targeting private CI pipelines.
    # OSV MAL-2026-5286 (encrypted-archive), MAL-2026-5287 (uhd-setup),
    # MAL-2026-5288 (uisp-connector), MAL-2026-5289 (unifi-portal)
    "encrypted-archive": {"99.0.0"},
    "uhd-setup": {"99.0.0"},
    "uisp-connector": {"99.0.0"},
    "unifi-portal": {"99.0.0"},
    # sequoia-engineering npm malware (June 7 2026)
    # Communicates with a domain associated with malicious activity;
    # detected by OpenSSF Package Analysis. Single version published.
    # OSV MAL-2026-5291
    "sequoia-engineering": {"2.2.2"},
    # consumerweb-authflow npm malware (June 7 2026)
    # Communicates with a domain associated with malicious activity;
    # detected by OpenSSF Package Analysis. Two versions published.
    # OSV MAL-2026-5297
    "consumerweb-authflow": {"4.1.1", "4.1.3"},
    # @langgraphjs/toolkit npm any-version wildcard (MAL-2026-2509)
    # Pure-malware typosquat of LangGraph's JavaScript toolkit; OSV record
    # contains SEMVER >=0 range (any-version) plus specific versions 1.2.10/1.2.11.
    # Per convention the entire package is treated as malicious.
    "@langgraphjs/toolkit": set(),
    # @listings/energy-labels + @zimmo/last_search dep-confusion (June 8 2026)
    # Both packages published at high version 99.0.x; no legitimate public history.
    # OSV MAL-2026-5327 (@listings/energy-labels), 5328 (@zimmo/last_search)
    "@listings/energy-labels": {"99.0.0", "99.0.1"},
    "@zimmo/last_search": {"99.0.0", "99.0.1"},
    # @bancolonbia/menu-filter-widget-web dep-confusion (June 8 2026)
    # Published at version 0.0.1 with malicious payload; targets BanColombia
    # internal CI. OSV MAL-2026-5344.
    "@bancolonbia/menu-filter-widget-web": {"0.0.1"},
    # @demica/* dep-confusion cluster (June 8 2026)
    # Three packages targeting Demica trade-finance internal CI; published at
    # inflated 99.99.x versions. OSV MAL-2026-5349/5350/5351.
    "@demica/core": {"99.99.99", "99.99.100"},
    "@demica/resources": {"99.99.100"},
    "@demica/shared": {"99.99.100"},
    # @doaction/* dep-confusion cluster (June 8 2026)
    # Fifteen packages targeting internal DoAction/banking CI infrastructure.
    # Published at high versions (9.9.9 / 99.99.99); some with no specific
    # versions recorded (OSV >=0 range). OSV MAL-2026-5369 through 5383.
    "@doaction/auth": {"99.99.99"},
    "@doaction/eventemitter": {"9.9.9"},
    "@doaction/example": set(),
    "@doaction/examples": {"99.99.99"},
    "@doaction/http": {"9.9.9", "99.99.99"},
    "@doaction/mapstore": {"9.9.9", "99.99.99"},
    "@doaction/pay": {"9.9.9", "99.99.99"},
    "@doaction/rrweb-sdk": {"9.9.9", "99.99.99"},
    "@doaction/shared": {"9.9.9", "99.99.99"},
    "@doaction/signalhub": {"9.9.9"},
    "@doaction/storage": {"9.9.9", "99.99.99"},
    "@doaction/sudo-prompt": set(),
    "@doaction/systeminformation": {"9.9.9"},
    "@doaction/types": {"9.9.9", "99.99.99"},
    "@doaction/wasm-loader": {"9.9.9", "99.99.99"},
    # @0xlr/* dep-confusion cluster (June 8 2026)
    # Seven packages targeting a startup's internal CI; all published at 999.0.0.
    # OSV MAL-2026-5385 through 5391.
    "@0xlr/clerk-auth": {"999.0.0"},
    "@0xlr/prisma-client-js": {"999.0.0"},
    "@0xlr/sentry-web": {"999.0.0"},
    "@0xlr/stripe-checkout-js": {"999.0.0"},
    "@0xlr/stripe-frontend": {"999.0.0"},
    "@0xlr/supabase-db": {"999.0.0"},
    "@0xlr/vercel-analytics": {"999.0.0"},
    # @klapp-* / @easy-entry / @shell-* dep-confusion cluster (June 8 2026)
    # Twelve packages targeting Klapp banking-app and related internal pipelines;
    # published at 99.x versions. OSV MAL-2026-5408 through 5417, 5428/5429.
    "@easy-entry/landing-routes": {"99.9.5"},
    "@easy-entry/outside-registration-fop-navigator": {"99.9.5"},
    "@easy-entry/routes": {"99.9.5"},
    "@klapp-about/routes": {"99.0.0", "99.0.1", "99.0.2"},
    "@klapp-kyc/routes": {"99.0.0", "99.0.1"},
    "@klapp-login-platform/native-sdk": {"99.0.0", "99.0.2"},
    "@klapp-login-platform/oidc": {"99.0.0", "99.0.2"},
    "@klapp-login-platform/routes": {"99.0.0", "99.0.2"},
    "@klapp-otp/routes": {"99.0.0", "99.0.1"},
    "@klapp-sca/routes": {"99.0.0", "99.0.1"},
    "@shell-cabinet/routes": {"99.9.5"},
    "@shell-landing/routes": {"99.9.5"},
    # @nstrlabs/* dep-confusion cluster (June 8 2026)
    # Six packages targeting NstrLabs internal CI; published at 99.0.x.
    # OSV MAL-2026-5418 through 5423.
    "@nstrlabs/api-client": {"99.0.0", "99.0.1"},
    "@nstrlabs/auth": {"99.0.0", "99.0.1"},
    "@nstrlabs/ixel": {"99.0.0", "99.0.1"},
    "@nstrlabs/sdk": {"99.0.0", "99.0.1"},
    "@nstrlabs/shared-components": {"99.0.0", "99.0.1"},
    "@nstrlabs/utils": {"99.0.0", "99.0.1"},
    # @oplus/* dep-confusion cluster (June 8 2026)
    # Three packages targeting OnePlus/OPPO internal obus SDK pipeline;
    # published at 99.99.99. OSV MAL-2026-5424/5425/5426.
    "@oplus/obus-core": {"99.99.99"},
    "@oplus/obus-web-sdk": {"99.99.99"},
    "@oplus/obus-web-sdk-plugin-recovery": {"99.99.99"},
    # @orion-design-system/* dep-confusion cluster (June 11 2026)
    # Three packages targeting Orion design-system internal CI; published at
    # inflated 9999.x versions. OSV MAL-2026-5522/5523/5524.
    "@orion-design-system/components": {"9999.0.0", "9999.0.1", "9999.0.2", "9999.0.3"},
    "@orion-design-system/foundation": {
        "9999.0.0", "9999.0.1", "9999.0.2", "9999.0.3", "9999.0.4",
    },
    "@orion-design-system/store": {"9999.0.0", "9999.0.1", "9999.0.2"},
    # @solana-labs/* npm typosquat cluster (June 8–22 2026)
    # Six packages impersonating official @solana-labs tooling; each publishes
    # multiple versions carrying a credential/wallet exfiltrator payload.
    # Note: the legitimate @solana-labs/web3.js uses the exact name with a
    # period — these all use alternate spellings or names. The real package is
    # published by Anza and is not in this list.
    # OSV MAL-2026-5362 (etherjs), 5363 (web3-js), 5525 (web3.js),
    # 5786 (ancor), 5787 (spl-toke), 5788 (web3js)
    "@solana-labs/etherjs": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3-js": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3.js": {
        "1.0.0", "1.0.6", "1.0.7", "1.0.8", "1.0.10", "1.98.112",
    },
    "@solana-labs/ancor": {
        "1.0.0", "1.0.1", "1.0.7", "1.0.8", "1.0.9", "1.0.11",
    },
    "@solana-labs/spl-toke": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    "@solana-labs/web3js": {
        "1.0.0", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.10",
    },
    # @403name/* npm typosquat cluster (June 12 2026)
    # Three packages impersonating popular native-build and crypto tooling;
    # each publishes versions 1.0.0 and 1.0.1 with malicious payloads.
    # OSV MAL-2026-5547 (electron-buidler), 5548 (ether-js), 5549 (fsevent)
    "@403name/electron-buidler": {"1.0.0", "1.0.1"},
    "@403name/ether-js": {"1.0.0", "1.0.1"},
    "@403name/fsevent": {"1.0.0", "1.0.1"},
    # @onum-releases/* dep-confusion cluster (June 22 2026)
    # Six packages impersonating NstrLabs (@nstrlabs) internal packages under a
    # new attacker scope; published at versions 1.0.1 through 1.0.3.
    # OSV MAL-2026-6122 through 6127.
    "@onum-releases/api-client": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/auth": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/ixel": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/sdk": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/shared-components": {"1.0.1", "1.0.2", "1.0.3"},
    "@onum-releases/utils": {"1.0.1", "1.0.2"},
    # @mastra/* npm scope compromise (June 20–27 2026)
    # 89 packages across the @mastra namespace were compromised; the attacker
    # published specific malicious versions of the Mastra AI agent framework
    # injecting a credential-exfiltration payload. The @mastra scope is also
    # added to NPM_SUSPECT_SCOPES to catch any additional undisclosed packages.
    # OSV MAL-2026-5939 through 5964, 5996 through 6057, 6072 through 6074.
    "@mastra/ai-sdk": {"1.4.6"},
    "@mastra/auth": {"1.0.3"},
    "@mastra/braintrust": {"1.1.4"},
    "@mastra/clickhouse": {"1.10.1"},
    "@mastra/datadog": {"1.2.5"},
    "@mastra/duckdb": {"1.4.3"},
    "@mastra/dynamodb": {"1.0.9"},
    "@mastra/editor": {"0.11.3"},
    "@mastra/evals": {"1.3.1"},
    "@mastra/fastembed": {"1.1.3"},
    "@mastra/fastify": {"1.3.31"},
    "@mastra/hono": {"1.4.26"},
    "@mastra/inngest": {"1.5.2"},
    "@mastra/langfuse": {"1.3.6"},
    "@mastra/langsmith": {"1.2.4"},
    "@mastra/libsql": {"1.13.1"},
    "@mastra/mcp": {"1.10.1"},
    "@mastra/mcp-docs-server": {"1.1.47"},
    "@mastra/mongodb": {"1.9.3"},
    "@mastra/otel-bridge": {"1.2.3"},
    "@mastra/pg": {"1.13.1"},
    "@mastra/posthog": {"1.0.29"},
    "@mastra/rag": {"2.2.2"},
    "@mastra/s3": {"0.5.3"},
    "@mastra/schema-compat": {"1.2.12"},
    "@mastra/sentry": {"1.1.4"},
    "@mastra/agent-browser": {"0.3.2"},
    "@mastra/agent-builder": {"1.0.42"},
    "@mastra/arize": {"1.2.3"},
    "@mastra/auth-auth0": {"1.0.2"},
    "@mastra/auth-better-auth": {"1.0.4"},
    "@mastra/auth-clerk": {"1.0.3"},
    "@mastra/auth-supabase": {"1.0.2"},
    "@mastra/auth-workos": {"1.5.3"},
    "@mastra/blaxel": {"0.4.2"},
    "@mastra/chroma": {"1.0.2"},
    "@mastra/claude": {"1.0.3"},
    "@mastra/client-js": {"1.24.1"},
    "@mastra/cloudflare": {"1.4.2"},
    "@mastra/cloudflare-d1": {"1.0.7"},
    "@mastra/convex": {"1.2.2"},
    "@mastra/core": {"1.42.1"},
    "@mastra/couchbase": {"1.0.4"},
    "@mastra/cursor": {"0.2.1"},
    "@mastra/daytona": {"0.4.2"},
    "@mastra/deployer": {"1.42.1"},
    "@mastra/deployer-cloudflare": {"1.1.44"},
    "@mastra/deployer-netlify": {"1.1.20"},
    "@mastra/deployer-vercel": {"1.1.38"},
    "@mastra/docker": {"0.3.1"},
    "@mastra/dsql": {"1.0.3"},
    "@mastra/e2b": {"0.3.4"},
    "@mastra/express": {"1.3.31"},
    "@mastra/gcs": {"0.2.3"},
    "@mastra/google-cloud-pubsub": {"1.0.6"},
    "@mastra/koa": {"1.5.14"},
    "@mastra/longmemeval": {"1.0.50"},
    "@mastra/mcp-registry-registry": {"1.0.2"},
    "@mastra/memory": {"1.20.4"},
    "@mastra/mssql": {"1.3.2"},
    "@mastra/nestjs": {"0.1.15"},
    "@mastra/otel-exporter": {"1.2.3"},
    "@mastra/pinecone": {"1.0.2"},
    "@mastra/playground-ui": {"33.0.1"},
    "@mastra/qdrant": {"1.0.3"},
    "@mastra/s3vectors": {"1.0.7"},
    "@mastra/server": {"2.1.1"},
    "@mastra/stagehand": {"0.2.5"},
    "@mastra/tavily": {"1.0.3"},
    "@mastra/temporal": {"0.1.14"},
    "@mastra/turbopuffer": {"1.0.3"},
    "@mastra/upstash": {"1.1.3"},
    "@mastra/vectorize": {"1.0.3"},
    "@mastra/voice-aws-nova-sonic": {"0.1.4"},
    "@mastra/voice-deepgram": {"0.12.2"},
    "@mastra/voice-elevenlabs": {"0.12.2"},
    "@mastra/voice-google": {"0.12.3"},
    "@mastra/voice-google-gemini-live": {"0.12.2"},
    "@mastra/voice-openai": {"0.12.3"},
    "@mastra/voice-openai-realtime": {"0.12.6"},
    "@mastra/github-signals": {"0.1.2"},
    "@mastra/mem0": {"0.1.14"},
    "@mastra/node-audio": {"0.1.8"},
    "@mastra/node-speaker": {"0.1.1"},
    "@mastra/react": {"1.0.1"},
    "@mastra/voice-playai": {"0.12.2"},
    "@mastra/loggers": {"1.1.3"},
    "@mastra/observability": {"1.14.2"},
    "@mastra/redis": {"1.1.3"},
    # Gartner gx-npm dep-confusion cluster (June 25 2026)
    # Three internal Gartner npm packages published at 99.99.99 via dependency confusion;
    # no legitimate public release history. GHSA-hhw7-23r7-qwj7 / GHSA-wcmr-4783-pq3p /
    # GHSA-5jpv-9x2f-72jj. OSV MAL-2026-6466, MAL-2026-6480, MAL-2026-6481.
    "gx-npm-feature-flags": set(),
    "gx-npm-lib": set(),
    "gx-npm-ui": set(),
    # @vpms/design-system dep-confusion (June 25 2026)
    # Private-scope package published at inflated versions (0.1.3, 1.0.x, 1.1.2) via
    # dependency confusion. GHSA-43r2-9cx9-pv7f. OSV MAL-2026-6467.
    "@vpms/design-system": set(),
    # Crossmint wallets-sdk typosquat cluster (June 25–27 2026)
    # crossmint-wallets-sdk: flat typosquat of the legitimate @crossmint/wallets-sdk.
    # @epsteinlovekids483/crossmint-wallets-sdk-pentest: attacker-controlled scope
    # with multiple pentest-labeled versions impersonating Crossmint.
    # GHSA-7rfm-v32j-2583, GHSA-x7jg-w433-8q2r. OSV MAL-2026-6545, MAL-2026-6522.
    "crossmint-wallets-sdk": set(),
    "@epsteinlovekids483/crossmint-wallets-sdk-pentest": set(),
    # ts-einkle / ts-ankle cluster (June 26–27 2026)
    # Three related typosquat packages with credential-exfiltration payloads.
    # GHSA-mjcv-m7fg-mg8j (ts-einkle), GHSA-8cxx-rp6g-mcr9 (ts-einkle-slot),
    # GHSA-992p-988h-h55j (ts-ankle). OSV MAL-2026-6524, MAL-2026-6525, MAL-2026-6548.
    "ts-einkle": set(),
    "ts-einkle-slot": set(),
    "ts-ankle": set(),
    # react-dynammic-table-component typosquat (June 26 2026)
    # Version 1.2.7 only; typosquat of react-dynamic-table-component with injected
    # postinstall payload. OSV MAL-2026-6534.
    "react-dynammic-table-component": {"1.2.7"},
    # Miscellaneous malware batch (June 27–29 2026)
    # claude-cup: pure-malware typosquat impersonating Claude CLI tooling.
    # chai-as-persisted: Chai test-framework plugin typosquat with infostealer payload.
    # ryan-pdf-js: dep-confusion dropper at 99.9.1.
    # @k18n/creatormarketplace-admin-language: dep-confusion at 99.0.0.
    # anthropic-internal-tools: fake Anthropic internal package, credential exfiltrator.
    # livekit-agents: npm typosquat of @livekit/agents with malicious postinstall.
    # lc-chatbot: chatbot malware package, version 0.9.0-rc.0.
    # react-editable-calendar: malicious React calendar component.
    # polymarket-clob-math: Polymarket CLOB typosquat with crypto-stealer payload.
    # OSV MAL-2026-5789 (claude-cup), MAL-2026-6544 (chai-as-persisted),
    # MAL-2026-6546 (ryan-pdf-js), MAL-2026-6550 (@k18n/creatormarketplace-admin-language),
    # MAL-2026-6551 (anthropic-internal-tools), MAL-2026-6555 (livekit-agents),
    # MAL-2026-6559 (lc-chatbot), MAL-2026-6547 (react-editable-calendar),
    # MAL-2026-6556 (polymarket-clob-math).
    "claude-cup": set(),
    "chai-as-persisted": set(),
    "ryan-pdf-js": set(),
    "@k18n/creatormarketplace-admin-language": set(),
    "anthropic-internal-tools": set(),
    "livekit-agents": set(),
    "lc-chatbot": {"0.9.0-rc.0"},
    "react-editable-calendar": set(),
    "polymarket-clob-math": set(),
    # insomnia m4gester test-malware cluster (June 28 2026)
    # Three packages under the "m4gester" identity published as Insomnia plugin/util
    # stubs with credential-exfiltration postinstall scripts.
    # OSV MAL-2026-6552 (insomnia-plugin-poc-m4gester),
    # MAL-2026-6553 (insomnia-plugin-poc-m4gester2),
    # MAL-2026-6554 (insomnia-test-util-m4gester).
    "insomnia-plugin-poc-m4gester": set(),
    "insomnia-plugin-poc-m4gester2": set(),
    "insomnia-test-util-m4gester": set(),
    # AI/LLM toolkit impersonation campaign (June 29–30 2026)
    # Packages impersonating popular AI SDK toolkits with postinstall credential-exfiltration
    # payloads. All are pure-malware typosquats with no legitimate use.
    # anthropic-toolkit: fake Anthropic developer toolkit; 21 specific versions published.
    #   OSV MAL-2026-6673.
    # ai-sdk-helpers: fake AI SDK helper library; any version is malicious
    #   (ranges: introduced 0). OSV MAL-2026-5565.
    # ollama-helpers: fake Ollama integration library; any version is malicious.
    #   OSV MAL-2026-6581.
    # openai-agents-helpers: fake OpenAI Agents SDK helper; any version is malicious.
    #   OSV MAL-2026-6582.
    "anthropic-toolkit": {
        "0.1.0", "0.1.1", "0.2.0", "0.2.1", "0.3.0", "0.3.1", "0.4.0", "0.4.1",
        "0.5.0", "0.5.1", "0.6.0", "0.7.0", "0.8.0", "0.9.0", "1.0.0", "1.0.1",
        "1.1.0", "1.1.1", "1.2.0", "1.2.1", "1.3.0",
    },
    "ai-sdk-helpers": set(),
    "ollama-helpers": set(),
    "openai-agents-helpers": set(),
    # ts-einkle/ts-ankle TypeScript runtime exploit cluster (June 29 2026)
    # Packages mimicking TypeScript utility libraries with postinstall exfiltration.
    # All have SEMVER ranges: introduced 0 (any version is malicious).
    # OSV MAL-2026-6524 (ts-einkle), MAL-2026-6525 (ts-einkle-slot), MAL-2026-6548 (ts-ankle).
    "ts-einkle": set(),
    "ts-einkle-slot": set(),
    "ts-ankle": set(),
    # @thone33 attacker-scope credential injector (June 29 2026)
    # Two packages published under the @thone33 scope with postinstall analytics/core
    # facades hiding credential-exfiltration payloads.
    # OSV MAL-2026-6563 (@thone33/analytics-injector), MAL-2026-6564 (@thone33/core-utils).
    "@thone33/analytics-injector": set(),
    "@thone33/core-utils": set(),
    # @epic-common/observability-node backdoor (June 29 2026)
    # Dependency-confusion or typosquat targeting the Epic Games common library scope.
    # OSV MAL-2026-6562.
    "@epic-common/observability-node": set(),
    # Targeted dep-confusion packages (June 29 2026)
    # Company-specific packages published at inflated version numbers (99.x / 9999.x)
    # to hijack internal dependency resolution in CI/CD pipelines.
    # All have SEMVER ranges: introduced 0 and are pure-malware with no legitimate releases.
    # OSV MAL-2026-2822 (ing-web-v5), MAL-2026-2846 (eslint-plugin-totara),
    # MAL-2026-2855 (react-resource-router-next), MAL-2026-2856 (@ataslkit/profilecard),
    # MAL-2026-2857 (@shoobx/types), MAL-2026-2858 (@source-row/source-container),
    # MAL-2026-2952 (@settle-sea/supporting-documents), MAL-2026-2956 (@serasa/core),
    # MAL-2026-2978 (@oec-settlement/react-router),
    # MAL-2026-4171 (@mc-xp/mc-monolith-js-src-package),
    # MAL-2026-4172 (@piewasm/pie-web-npm-package),
    # MAL-2026-4256 (@citi-icg-171632/citicms-repo-component),
    # MAL-2026-4257 (@cloudways-lab/unified-design-system),
    # MAL-2026-4389 (@flipbit2-bb/test-auth-state),
    # MAL-2026-4425 (@riskine-frontend/design-elements),
    # MAL-2026-4432 (@sec-loans-ui/utils), MAL-2026-4826 (wm-mapper),
    # MAL-2026-4827 (unleash-js),
    # MAL-2026-5431 (@webd-infra/query-designer-domain),
    # MAL-2026-5432 (@webda-features/dashboard), MAL-2026-5433 (@webda-infra/search),
    # MAL-2026-5453 (tivo-codelib-a), MAL-2026-5454 (ui-ng-components),
    # MAL-2026-5455 (uipath-sugar-sell), MAL-2026-5456 (via-city-tools-m-particle).
    "ing-web-v5": set(),
    "eslint-plugin-totara": set(),
    "react-resource-router-next": set(),
    "@ataslkit/profilecard": set(),
    "@shoobx/types": set(),
    "@source-row/source-container": set(),
    "@settle-sea/supporting-documents": set(),
    "@serasa/core": set(),
    "@oec-settlement/react-router": set(),
    "@mc-xp/mc-monolith-js-src-package": set(),
    "@piewasm/pie-web-npm-package": set(),
    "@citi-icg-171632/citicms-repo-component": set(),
    "@cloudways-lab/unified-design-system": set(),
    "@flipbit2-bb/test-auth-state": set(),
    "@riskine-frontend/design-elements": set(),
    "@sec-loans-ui/utils": set(),
    "wm-mapper": set(),
    "unleash-js": set(),
    "@webd-infra/query-designer-domain": set(),
    "@webda-features/dashboard": set(),
    "@webda-infra/search": set(),
    "tivo-codelib-a": set(),
    "ui-ng-components": set(),
    "uipath-sugar-sell": set(),
    "via-city-tools-m-particle": set(),
    # Gartner GX dependency-confusion cluster (June 29 2026)
    # Three packages mirroring internal Gartner GX npm packages at 99.99.99.
    # OSV MAL-2026-6466 (gx-npm-feature-flags), MAL-2026-6480 (gx-npm-lib),
    # MAL-2026-6481 (gx-npm-ui). Related to @gartnerx/gx-npm-messenger-util (see below).
    "gx-npm-feature-flags": set(),
    "gx-npm-lib": set(),
    "gx-npm-ui": set(),
    # Large dep-confusion wave (June 29 2026)
    # 79 packages published across diverse scopes and namespaces, all with
    # SEMVER ranges: introduced 0 (any version is malicious), targeting companies
    # ranging from Deel to Postman to Rakuten. Detected by OpenSSF Package Analysis.
    # OSV MAL-2026-6594 through MAL-2026-6672.
    "vkzmn": set(),
    "@digitalcnzz/commonmodule": set(),
    "@digitalcnzz/embedded-sdk": set(),
    "@longzy/react-native-polyfill": set(),
    "@sailing-package/core": set(),
    "@alerts/components": set(),
    "@anna-money/anna-web-lib": set(),
    "@appsource/utils": set(),
    "@bapiweb-ux/bapi-header": set(),
    "@bc-workspace/utils": set(),
    "@bodata/angular-client": set(),
    "@bscom/styling": set(),
    "@concerns/i18n": set(),
    "@content-editor/common": set(),
    "@contenteditor-shared/content-editor-common": set(),
    "@contentprod-authoring/block-manager": set(),
    "@cseo-hr/trpweb-shared": set(),
    "@cxp-shared/string-utilities": set(),
    "@ddh-libs/analytics": set(),
    "@deel-core/client-payroll-onboarding-types": set(),
    "@deel-ui/animation": set(),
    "@digitalpharmacist/http-error-util": set(),
    "@druidsoft/botframework-directlinejs": set(),
    "@e50/utils": set(),
    "@experian-shared/services": set(),
    "@fed-sofia/jetify": set(),
    "@finantix/webcomponents": set(),
    "@flipbit2-bb/scope-test": set(),
    "@gallup/pc-utils": set(),
    "@gartnerx/gx-npm-messenger-util": set(),
    "@gm-rvg/root-config": set(),
    "@grappi/automations": set(),
    "@hg-aka-prml/tapas-common": set(),
    "@huobi-ui/activity-components": set(),
    "@img-hls/vtt.js": set(),
    "@lexisnexisrisk/insider-threat-platform": set(),
    "@live-backstage-im/communication-chat": set(),
    "@mcconnect/mcc-common-lib": set(),
    "@meego-progressive/cdk": set(),
    "@ms-ows/logging": set(),
    "@multformats/multiaddr": set(),
    "@orbis-lr-sdk/orbis-lr-sdk": set(),
    "@partner-apps/ui": set(),
    "@planetlabs/admin-ng": set(),
    "@postidigital-feature/oneaccount-orgadmin-front": set(),
    "@postman-app-monolith/renderer": set(),
    "@rakuten-rewards/messaging-sdk": set(),
    "@rakuten-rewards/messaging-sdk-js": set(),
    "@react-thee/rapier": set(),
    "@reference-web/pmp-i18n": set(),
    "@report-portal/service-ui": set(),
    "@rmlibrary/formatting": set(),
    "@sentryx-libraries/auth-interceptor": set(),
    "@services-lib/application-http-client": set(),
    "@shopbop/api-models": set(),
    "@sixt-payment/form-react": set(),
    "@sumoinc/trashpanda": set(),
    "@tbe-ui/ides": set(),
    "@webda-infra-ui/static-images": set(),
    "alpine-csp": set(),
    "app-hotmart-blog-headless": set(),
    "auth-state-service": set(),
    "authmatrix": set(),
    "authsessionbridge": set(),
    "bundrix": set(),
    "cdocs-data": set(),
    "cdocs-markdoc": set(),
    "clx-cookieparser": set(),
    "cmp-api-stub": set(),
    "gel-bootstrap": set(),
    "hrb-cas-auth-js": set(),
    "ltididp1": set(),
    "magwien.sys": set(),
    "player-core-ui": set(),
    "player-theming": set(),
    "pvd3": set(),
    "rc-icon": set(),
    "wac-atl-context": set(),
    "ulid-xyz": set(),
    # Miscellaneous npm malware batch (June 29 2026)
    # Individual packages with varying payloads (infostealers, env-var exfiltrators,
    # dep-confusion droppers, crypto-math typosquats). All have active OSV MAL records
    # with no withdrawal. All entries are wildcard (any version malicious) unless noted.
    # OSV MAL-2026-3312 (path-internal-util), MAL-2026-4580 (http-uploader-dev),
    # MAL-2026-4792 (react-json-chalk), MAL-2026-5487 (tailwind-form),
    # MAL-2026-5488 (react-pinojs), MAL-2026-5734 (node-denv),
    # MAL-2026-5908 (chain-chai-test), MAL-2026-5934 (ssr-auth-sync),
    # MAL-2026-6066 (quirky-token), MAL-2026-6068 (swift-parse-stream),
    # MAL-2026-6087 (uol-simple-api-futebol), MAL-2026-6098 (stackus),
    # MAL-2026-6141 (clx-cookie-signature), MAL-2026-6229 (routecraft),
    # MAL-2026-6337 (hunsterx-package), MAL-2026-6369 (hardhat-test-log),
    # MAL-2026-6445 (base58-core), MAL-2026-6467 (@vpms/design-system),
    # MAL-2026-6486 (unsafe-malicious-package), MAL-2026-6487 (velocityfix),
    # MAL-2026-6501 (wellnpm), MAL-2026-6531 (@appupdate/cdn-sync),
    # MAL-2026-6532 (chai-as-assured), MAL-2026-6545 (crossmint-wallets-sdk),
    # MAL-2026-6565 (@uisp/utils), MAL-2026-6566 (date-uuid),
    # MAL-2026-6567 (eslint-commit-parser), MAL-2026-6568 (express-mocha-test),
    # MAL-2026-6569 (longzy-basic-ui), MAL-2026-6570 (pkg-fallback npm),
    # MAL-2026-6571 (react-wp-viewer), MAL-2026-6572 (rebrandly-domains-digger),
    # MAL-2026-6573 (rebrandly-domains-search-client), MAL-2026-6574 (yandex-geobase),
    # MAL-2026-6575 (@ibrahim1337/baksen), MAL-2026-6576 (checkmarx-claude-cache),
    # MAL-2026-6577 (int_sezzle_sfra), MAL-2026-6578 (layerd-unit-codec-parser),
    # MAL-2026-6579 (lessload), MAL-2026-6580 (loadutils),
    # MAL-2026-6583 (pino-debugging), MAL-2026-6584 (poly-kelly),
    # MAL-2026-6585 (stake-math), MAL-2026-6586 (yastatic-s3),
    # MAL-2026-6587 (clob-client-math), MAL-2026-6588 (endpointmap),
    # MAL-2026-6589 (envfile-sync), MAL-2026-6590 (envfile-sync-cli),
    # MAL-2026-6591 (ledgerflow-deploy-utils), MAL-2026-6592 (maplibre-gl-vue3).
    "path-internal-util": set(),
    "http-uploader-dev": set(),
    "react-json-chalk": set(),
    "tailwind-form": set(),
    "react-pinojs": set(),
    "node-denv": set(),
    "chain-chai-test": set(),
    "ssr-auth-sync": set(),
    "quirky-token": set(),
    "swift-parse-stream": set(),
    "uol-simple-api-futebol": set(),
    "stackus": set(),
    "clx-cookie-signature": set(),
    "routecraft": set(),
    "hunsterx-package": set(),
    "hardhat-test-log": set(),
    "base58-core": set(),
    "@vpms/design-system": set(),
    "unsafe-malicious-package": set(),
    "velocityfix": set(),
    "wellnpm": set(),
    "@appupdate/cdn-sync": set(),
    "chai-as-assured": set(),
    "crossmint-wallets-sdk": set(),
    "@uisp/utils": set(),
    "date-uuid": set(),
    "eslint-commit-parser": set(),
    "express-mocha-test": set(),
    "longzy-basic-ui": set(),
    "pkg-fallback": set(),
    "react-wp-viewer": set(),
    "rebrandly-domains-digger": set(),
    "rebrandly-domains-search-client": set(),
    "yandex-geobase": set(),
    "@ibrahim1337/baksen": set(),
    "checkmarx-claude-cache": set(),
    "int_sezzle_sfra": set(),
    "layerd-unit-codec-parser": set(),
    "lessload": set(),
    "loadutils": set(),
    "pino-debugging": set(),
    "poly-kelly": set(),
    "stake-math": set(),
    "yastatic-s3": set(),
    "clob-client-math": set(),
    "endpointmap": set(),
    "envfile-sync": set(),
    "envfile-sync-cli": set(),
    "ledgerflow-deploy-utils": set(),
    "maplibre-gl-vue3": set(),
    # Polymarket ecosystem typosquat cluster (June 30 – July 1 2026)
    # Five packages impersonating Polymarket trading tools and risk management utilities;
    # postinstall payloads exfiltrate API keys, crypto wallet data, and environment variables.
    # OSV MAL-2026-6691 (polymarket-clob-maths), MAL-2026-6692 (polymarket-trading-developer-tools),
    # MAL-2026-6712 (polymarket-risk-manager), MAL-2026-6713 (polymarket-toolkit),
    # MAL-2026-6714 (polymarket-trading-developer-tool).
    "polymarket-clob-maths": set(),
    "polymarket-trading-developer-tools": set(),
    "polymarket-risk-manager": {"3.5.2"},
    "polymarket-toolkit": {"1.4.9"},
    "polymarket-trading-developer-tool": {"0.1.1"},
    # TypeScript / ESLint / CLOB typosquat cluster (June 30 – July 1 2026)
    # Six packages impersonating TypeScript build utilities, ESLint helpers, and CLOB math
    # libraries; OSV affected.ranges >=0 for all-version entries.
    # OSV MAL-2026-6677 / GHSA-vjgf-xg3j-g9c5 (ts-lint-builders-v2.1),
    # MAL-2026-6678 / GHSA-8mpj-272v-jhv7 (ts-linting-builder),
    # MAL-2026-6695 (ts-bn-proto), MAL-2026-6720 (ts-elinter),
    # MAL-2026-6721 (ts-eslint-helper), MAL-2026-6719 (ts-clob-math-v2).
    "ts-lint-builders-v2.1": set(),
    "ts-linting-builder": set(),
    "ts-bn-proto": set(),
    "ts-elinter": {"3.3.9"},
    "ts-eslint-helper": {"4.0.3", "4.0.4", "4.0.5"},
    "ts-clob-math-v2": {"2.0.1"},
    # Frontend framework typosquats (June 30 – July 1 2026)
    # Six packages impersonating popular frontend libraries (date-fns, svgson, vega-lite,
    # vue-demi, electron, svg tooling) with credential-exfiltration postinstall payloads.
    # OSV MAL-2026-6722 (date-fns-lite), MAL-2026-6707 (svgson-lite),
    # MAL-2026-6709 (vega-lite-next), MAL-2026-6702 (vue-demi-fix),
    # MAL-2026-6723 (electron-orbit), MAL-2026-6715 (svgcraft-core).
    "date-fns-lite": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6",
        "1.0.7", "1.0.8", "1.0.9", "1.0.10", "1.0.11", "1.0.12",
    },
    "svgson-lite": {
        "1.0.0", "1.0.1", "1.0.2", "1.0.4", "1.0.5", "1.0.6", "1.0.7",
    },
    "vega-lite-next": {"19.2.1"},
    "vue-demi-fix": {"10.0.3", "10.0.4", "10.0.5"},
    "electron-orbit": {
        "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9",
        "1.0.10", "1.0.11", "1.0.12", "1.0.13", "1.0.14", "1.0.15", "1.0.16",
        "1.0.18", "1.0.20", "1.0.21", "1.0.22", "1.0.23", "1.0.24", "1.0.25",
        "1.0.26", "1.0.27", "1.0.28", "1.0.29", "1.0.30", "1.0.31", "1.0.32",
        "1.0.33", "1.0.34", "1.0.36",
    },
    "svgcraft-core": {"1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    # Hardhat / Solidity ecosystem typosquats (June 30 – July 1 2026)
    # Two packages impersonating Hardhat build tools with credential-exfiltration postinstall.
    # OSV MAL-2026-6705 (hardhat-compile-ethers), MAL-2026-6706 (hardhat-plugin-solidity).
    "hardhat-compile-ethers": {
        "0.0.1", "0.4.0", "0.4.2", "0.4.3", "0.4.4", "0.4.5", "0.4.6",
        "0.4.7", "0.4.8", "0.4.9", "0.4.10", "0.4.11", "0.4.12",
    },
    "hardhat-plugin-solidity": {"1.0.0", "1.1.0", "2.0.0", "2.3.1"},
    # GHSA full-compromise batch (June 30 – July 1 2026)
    # 16 packages with SEMVER >=0 range: "Any computer that has this package installed or
    # running should be considered fully compromised." All use empty-set wildcard.
    # OSV MAL-2026-6675 / GHSA-xm5w-w96q-42f3 (rs-biginteger),
    # MAL-2026-6676 / GHSA-m8cr-hv9p-pg3f (terminal-prettier),
    # MAL-2026-6679 / GHSA-x676-qqgj-qfgg (agent-starter-pack),
    # MAL-2026-6680 / GHSA-gwv3-x257-r43c (brock-loader),
    # MAL-2026-6681 / GHSA-gh2m-x2qr-m2cm (brock-react-alerts),
    # MAL-2026-6682 / GHSA-j28m-58xp-3wgh (confluent-kafka-javascript),
    # MAL-2026-6683 / GHSA-fc4r-p4fh-6h4p (nbmolviz-js),
    # MAL-2026-6684 / GHSA-6g2x-2f5c-wp9w (postcss-property-rollup),
    # MAL-2026-6685 / GHSA-x8q6-66jr-wmp3 (quoting),
    # MAL-2026-6686 / GHSA-5rc3-r829-w347 (setup-cicd),
    # MAL-2026-6687 / GHSA-5r42-357x-f2mx (procwire),
    # MAL-2026-6688 (console-fmt-cli), MAL-2026-6689 (decimal-format-core),
    # MAL-2026-6690 (log-taker1), MAL-2026-6693 (thirdwb), MAL-2026-6694 (thirdwebb).
    "rs-biginteger": set(),
    "terminal-prettier": set(),
    "agent-starter-pack": set(),
    "brock-loader": set(),
    "brock-react-alerts": set(),
    "confluent-kafka-javascript": set(),
    "nbmolviz-js": set(),
    "postcss-property-rollup": set(),
    "quoting": set(),
    "setup-cicd": set(),
    "procwire": set(),
    "console-fmt-cli": set(),
    "decimal-format-core": set(),
    "log-taker1": set(),
    "thirdwb": set(),
    "thirdwebb": set(),
    # Miscellaneous npm malware batch (June 30 – July 1 2026)
    # Individual packages with varying payloads. OSV records active, not withdrawn.
    # OSV MAL-2026-3509 (pp-react-v5), MAL-2026-6346 (triage-bot),
    # MAL-2026-6405 (sypoi1), MAL-2026-6701 (ripshakti), MAL-2026-6674 (ripshakti1),
    # MAL-2026-6699 (ecto-corsair-flag-7kq3mz), MAL-2026-6700 (module-index-cache),
    # MAL-2026-6708 (zyncmap), MAL-2026-6710 (vitest-agent),
    # MAL-2026-6704 (base65-85x), MAL-2026-6716 (test-pkg-pnpm),
    # MAL-2026-6717 (test-pkg-x0), MAL-2026-6718 (test-pkg-yarn).
    "pp-react-v5": set(),
    "triage-bot": {"1.0.1", "1.0.2"},
    "sypoi1": {"1.0.0", "1.0.1"},
    "ripshakti": {"80.0.0"},
    "ripshakti1": {"81.0.0"},
    "ecto-corsair-flag-7kq3mz": {"1.0.0", "1.0.1", "1.0.2"},
    "module-index-cache": {"1.0.0", "1.0.1", "1.0.2"},
    "zyncmap": {"0.0.0", "0.0.1"},
    "vitest-agent": {"1.0.5", "1.0.6"},
    "base65-85x": {"5.0.1"},
    "test-pkg-pnpm": {"1.0.1", "1.0.4"},
    "test-pkg-x0": {"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"},
    "test-pkg-yarn": {"1.0.0", "1.0.1", "1.0.2"},
    # Dependency-confusion packages (June 30 – July 1 2026)
    # High-version shadow packages targeting private CI pipelines.
    # OSV MAL-2026-6696 (@businessapp-microsites/apis),
    # MAL-2026-6697 (@sudoughnym/enviro-demo),
    # MAL-2026-6703 (@andes-tools/colors),
    # MAL-2026-6698 (cursed-modules).
    "@businessapp-microsites/apis": {"9999.0.0", "9999.0.1"},
    "@sudoughnym/enviro-demo": {"99.99.99"},
    "@andes-tools/colors": {"999.0.0"},
    "cursed-modules": {
        "1.0.1", "1.0.4", "1.0.5", "1.0.6", "1.0.7", "2.0.0",
        "999.0.0", "999.0.1", "999.0.2", "999.0.3", "999.0.4", "999.0.5",
        "999.0.6", "999.0.7", "999.0.8", "999.0.9", "999.1.0", "999.1.1", "999.1.2",
    },
    # tailwind-typography-stylecss Tailwind CSS typosquat (July 2 2026)
    # Impersonates tailwind-typography CSS plugin; SEMVER >=0 range — entire package malicious.
    # OSV MAL-2026-4681 / GHSA-p258-w6jm-c6ff
    "tailwind-typography-stylecss": set(),
    # SQL/SQLite fake npm package cluster (July 2–3 2026)
    # Three packages impersonating SQL access and SQLite tooling; each ships a
    # postinstall credential-exfiltration payload. SEMVER >=0 range — entire packages malicious.
    # OSV MAL-2026-5394 / GHSA-qpx3-6fx4-259q (@sql-access/nodesql)
    # OSV MAL-2026-5395 / GHSA-9f9w-wg5j-m53j (@sql-trigger/nodesql)
    # OSV MAL-2026-5396 / GHSA-9w2p-6gjc-vrqv (@sqlite-node/createsql)
    "@sql-access/nodesql": set(),
    "@sql-trigger/nodesql": set(),
    "@sqlite-node/createsql": set(),
    # Miscellaneous npm malware (July 2–3 2026)
    # All five carry a postinstall hook or import-time payload exfiltrating credentials.
    # SEMVER >=0 range in OSV records — entire packages are malicious.
    # OSV MAL-2026-5604 / GHSA-wg39-m2jm-wxhp (cache-section-helper)
    # OSV MAL-2026-6142 / GHSA-w7hw-9wmw-hj5w (db-connector-log)
    # OSV MAL-2026-6209 / GHSA-c3r7-wcqm-j4v8 (@antoncarlos1/nodelamp)
    # OSV MAL-2026-6495 / GHSA-p6ch-cw7w-ff5c (animatecss-postcss-plugin)
    # OSV MAL-2026-6538 / GHSA-j49r-84jx-vq3m (db-plog)
    "cache-section-helper": set(),
    "db-connector-log": set(),
    "@antoncarlos1/nodelamp": set(),
    "animatecss-postcss-plugin": set(),
    "db-plog": set(),
    # GHSA-confirmed npm malware batch (July 2 2026)
    # @modhamanish/rn-mm-template: only version 1.1.3 enumerated, no >=0 range — pin it.
    #   OSV MAL-2026-6725 / GHSA-7v96-p295-826q
    # db-convertor: SEMVER >=0 range, no specific versions — wildcard.
    #   OSV MAL-2026-6726 / GHSA-p467-3jcx-48q5
    # tailwind-animates: SEMVER >=0 range, no specific versions — wildcard.
    #   OSV MAL-2026-6727 / GHSA-3cr6-gpr8-pjfm
    "@modhamanish/rn-mm-template": {"1.1.3"},
    "db-convertor": set(),
    "tailwind-animates": set(),
    # Unreal Engine / Epic Games dep-confusion npm cluster (July 2 2026)
    # Five packages published at version 99999.0.0 to shadow private UE/Epic packages in CI/CD.
    # Detected by OpenSSF Package Analysis. No >=0 range in OSV records — pin version.
    # OSV MAL-2026-6729 (robomerge), MAL-2026-6730 (ue-automation-scripts),
    # MAL-2026-6731 (ue-jenkins-buildkite), MAL-2026-6732 (unreal-horde-dashboard),
    # MAL-2026-6737 (epic-internal-tools)
    "robomerge": {"99999.0.0"},
    "ue-automation-scripts": {"99999.0.0"},
    "ue-jenkins-buildkite": {"99999.0.0"},
    "unreal-horde-dashboard": {"99999.0.0"},
    "epic-internal-tools": {"99999.0.0"},
    # GHSA any-version malware cluster (July 3 2026)
    # Ten packages confirmed fully malicious by GHSA automated detection;
    # all have SEMVER >=0 range with no specific versions.
    # OSV MAL-2026-6738 / GHSA-3mg6-vg6x-m62v (@jacobtan/decode-sdk)
    # OSV MAL-2026-6739 / GHSA-37qp-frv4-562v (@lodash-en/lodash-en)
    # OSV MAL-2026-6740 / GHSA-gv37-287r-g9vx (decode-sdks)
    # OSV MAL-2026-6741 / GHSA-558p-3gxf-hm84 (@node-cloud/create)
    # OSV MAL-2026-6742 / GHSA-j23f-jg9h-gjmc (alder_morrgan)
    # OSV MAL-2026-6743 / GHSA-wj6w-3grq-735j (api-node-utils)
    # OSV MAL-2026-6744 / GHSA-3w2r-9f5g-prj8 (api-ts-utils)
    # OSV MAL-2026-6745 / GHSA-mjvg-2r5j-mg76 (ts-node-utils)
    # OSV MAL-2026-6746 / GHSA-84mg-p866-528x (typescript-util-core)
    # OSV MAL-2026-6747 / GHSA-j69c-7q52-h87f (web-api-node)
    "@jacobtan/decode-sdk": set(),
    "@lodash-en/lodash-en": set(),
    "decode-sdks": set(),
    "@node-cloud/create": set(),
    "alder_morrgan": set(),
    "api-node-utils": set(),
    "api-ts-utils": set(),
    "ts-node-utils": set(),
    "typescript-util-core": set(),
    "web-api-node": set(),
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
    # @mastra scope compromise (June 20–27 2026) — 89 packages, exact versions
    # pinned above; scope entry catches any undisclosed additional packages
    "@mastra/",
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
    # logflux Rust-job-application dropper (June 3 2026)
    # Attempted to download and run a malicious payload; 1 version published
    # 2026-04-26 (~1 month before removal); no actual usage. Part of a campaign
    # targeting Rust job applicants via take-home assignments with malicious deps.
    # RUSTSEC-2026-0171; reported by Paweł Bis.
    "logflux": set(),
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
