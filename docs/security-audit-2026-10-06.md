# Security audit — source-map-js (2026-10-06)

The production dependency audit went red on `main` at `1477981`, after
PR #31, for [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q)
(CVE-2026-93749). This record follows the dependency-triage section of
`docs/runbook-secure-web.md`.

## Confirmed affected dependency; application exposure unproven

- The reviewed advisory rates the finding high and marks `>=1.0.0 <1.2.2`
  affected, with `1.2.2` patched. Attacker-controlled indexed source-map
  section offsets can cause prolonged synchronous event-loop blocking.
- The baseline lockfile contains one `source-map-js` instance, version `1.2.1`.
  It is in the production installation tree through `next` 16.3.8 →
  `postcss` 8.5.23. It was already locked before PR #31.
- All three locked consumers accept `^1.2.1`: `postcss` 8.5.23,
  `vite/node_modules/postcss` 8.5.28, and `@tailwindcss/node` 4.3.2.
- Repository-authored web code does not import or invoke `source-map-js`,
  `SourceMapConsumer`, `SourceMapGenerator`, or `SourceNode`. No authored
  source-map annotation appears in the CSS. `web/app/layout.tsx` imports
  `globals.css`, which imports Tailwind; `web/postcss.config.mjs` enables
  the Tailwind PostCSS plugin, and `npm run build` uses Next's webpack build.
- PostCSS can consume previous maps from options, inline annotations, or
  local map files. The demonstrated path processes repository CSS and build
  inputs. Application route inputs are not passed to this pipeline. Raw TXT
  uploads go directly to the separate Python worker and its masking path.
- These facts do not prove network exploitability or its absence in a deployed
  application. Production-tree membership alone does not prove request-time
  use. No deployment inspection or attack was performed.

## Remediation

Update the single locked transitive package to `1.2.2`. Its tarball URL and
integrity come from `npm view source-map-js@1.2.2 dist --json`. The lockfile
diff changes only its `version`, `resolved`, and `integrity`; dependency
flags, consumer ranges, package membership, and all other entries are unchanged.
There is no direct dependency pin, override, Next update, or gate change.

The [upstream release](https://github.com/7rulnik/source-map-js/releases/tag/v1.2.2)
identifies the CVE fix. Its package-wide implementation validates indexed
offsets, bounds cumulative line offsets, and avoids excessive mapping work.
Normal flat and valid indexed maps keep the same API. This shared replacement
also covers encoded and file-based maps once PostCSS consumes them.

## Dependency audits

Run with Node `22.22.3` and npm `10.9.8`, against the baseline lockfile and
then the installed patched tree:

| Command | Before | After |
| --- | --- | --- |
| `npm audit --omit=dev --audit-level=high` | exit 1; one high entry, `source-map-js` | exit 0; zero vulnerabilities |
| `npm audit` | exit 1; six high entries | exit 1; five high entries, all the preexisting `braces` chain |

The before reports used `--package-lock-only --json`; the after reports used
`--json` on the tree installed by `npm ci --no-audit --no-fund`.
`npm ls source-map-js --omit=dev` resolves `1.2.2` through Next/PostCSS and
the existing Better Auth → Vitest → Vite/PostCSS path. The full-tree entries
left are `braces`, `micromatch`, `fast-glob`, `@next/eslint-plugin-next`, and
`eslint-config-next`. Their deferral remains as recorded in the 2026-10-05
audit. No audit bypass or forced downgrade was applied.

The original advisory is absent from both patched audit reports, and no
vulnerable `source-map-js` version remains installed. This is dependency-level
remediation evidence, not a claim that an application exploit was reproduced.

## Verification

Local validation used Node `22.22.3`, npm `10.9.8`, Python `3.12.14`, and the
lockfile-pinned Chromium headless shell revision `1194`. CI separately uses
Python `3.14` and the same pinned Node/browser versions.

| Check | Result |
| --- | --- |
| `npm ci --no-audit --no-fund` | 469 packages installed; lockfile unchanged |
| `python3 -m unittest discover -s tests` | 303 tests passed |
| `npm run test:run` | 85 tests passed in 16 files |
| `npm run typecheck` | passed |
| `npm run lint` | passed |
| `npm run build` | Next 16.3.8 webpack production build passed |
| Benign source-map compatibility controls | flat/indexed/SourceNode results match 1.2.1 and 1.2.2; both PostCSS versions preserve a benign inline map |
| Cross-process upload acceptance | passed; `rawCanaryLeaks: 0`, `finalState: sanitized`, model disabled |
| Accessibility acceptance | 23 axe scans; zero violations/incomplete results; 24 keyboard stops, zero failures; core flow passed |
| `detect-secrets-hook --baseline .secrets.baseline` over tracked non-PNG/non-lockfile files | passed, exit 0 |
| `git diff --check` and structural lockfile comparison | passed; only the three intended lock fields differ |

The first local `tsx` CLI acceptance launch could not create its Unix IPC
socket in the sandbox. The same unmodified scripts ran through tsx's Node
loader (`node --import tsx scripts/e2e-upload.ts` and `e2e-a11y.ts`) against
separate loopback web and worker processes, with fresh synthetic runtime data.
The CI commands and repository scripts remain unchanged.

`python3 scripts/run_phase_acceptance.py` returned the documented expected
exit 1: unsupported synthetic G2 baseline, `all_passed=false`. Its other
eleven gates passed. Live Google/LINE credentials, Codex-provider acceptance,
screen readers, real mobile devices, and deployment are outside this patch's
verification scope; no new acceptance claim is made for them.
