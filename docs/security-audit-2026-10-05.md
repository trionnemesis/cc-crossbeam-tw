# Security audit — `next/og` advisory and dev-tree findings (2026-10-05)

The blocking `security-scan` step ("Dependency advisories — production tree
(blocking)") went red after GHSA-vcvr-r3jv-pc5j was published for `next`. It
is red on `main`'s lockfile and on every branch built from it, including PR
#29, which does not touch `web/`. This record follows the runbook
(`docs/runbook-secure-web.md` → *When the dependency step goes red*). Every
finding the scan reports today is triaged below, but only one is changed here.
The repository owner approved this change for the blocking `next` finding.

A follow-up the same day fixed two of the deferred dev-tree findings
(`vitest` and `brace-expansion`). It is recorded at the end, in *Follow-up —
deferred dev-tree fixes*. The sections before it describe the `next` change
as it was made.

Baseline: `main` at `4aabfe9`. Checked on 2026-10-05.

## Tools

| Tool | Version / source | Ran against |
| --- | --- | --- |
| `npm audit` | npm 10.9.4 on Node 22.22.0, registry.npmjs.org advisory DB | `web/package-lock.json`, with `--omit=dev --audit-level=high` (the CI gate) and on the full tree |
| `npm ls`, `npm view` | same | production-tree membership (`--omit=dev`), dependency paths, published versions |
| GitHub advisory pages | github.com/advisories | preconditions for every advisory below |
| `git ls-files` + `grep` over `web/` | — | `next/og`, `ImageResponse`, `@vercel/og`, `satori`, `resvg`, and metadata image route files |

## Dependencies — before

- `npm audit --omit=dev --audit-level=high`: **exit 1**. The production-tree
  report has 3 entries: `next` (critical), `vitest` and `@vitest/mocker`
  (moderate).
- Full tree: 9 entries (1 critical, 6 high, 2 moderate).

## GHSA-vcvr-r3jv-pc5j — `next`, the blocking finding

- **Advisory.** "Next.js: Remote Code Execution in next/og ImageResponse".
  - Severity: critical, CVSS v4 9.5.
  - Affected: `>=16.2.0 <16.3.6`. Patched: `16.3.6`.
  - Published 2026-09-22, updated 2026-09-30.
- **Precondition, per the advisory.** The **Node.js** `ImageResponse` from
  `next/og` must render attacker-controlled values into SVG content,
  attributes or styles. The Edge implementation is unaffected, and so are
  applications that do not pass untrusted values.
- **Here.**
  1. Tree: `next` 16.3.4 is a direct production dependency, so it ships.
  2. Precondition: it does not exist here.
     - No tracked file under `web/` imports `next/og` or `ImageResponse`.
       None references `@vercel/og`, `satori` or `resvg`.
     - There are no metadata image route files (`opengraph-image`,
       `twitter-image`, `icon`, `apple-icon` as code). Those would use
       `ImageResponse` implicitly.
     - The social image is the static `public/og.png`. It is referenced from
       the metadata in `app/layout.tsx`.
     - The one grep hit, `socialImageResponse` in `scripts/e2e-homepage.ts`,
       is a variable that holds the `fetch` of that static PNG.
  3. Fix: a patch release in the same minor line.
- **Verdict: not reachable. Fixed anyway**, per runbook step 3, because the
  next advisory on `next` may not be unreachable.

### Remediation

| Change | From → to | Kind | Why this version |
| --- | --- | --- | --- |
| `next` (exact pin) | 16.3.4 → 16.3.8 | patch | The first patched release is 16.3.6. 16.3.8 is the `latest` dist-tag (published 2026-09-30) and is the version `npm audit` proposes. |

- **Install.** Installed with `npm install --save-exact next@16.3.8`, without
  `--force` or `--legacy-peer-deps`.
- **Lockfile delta.** +40/−40 lines. It covers only `next`, `@next/env` and
  the eight optional `@next/swc-*` platform binaries, all 16.3.4 → 16.3.8.
  Nothing else was re-resolved.
- **`eslint-config-next` stays at 16.3.4.**
  - It is a lint-time devDependency.
  - Its only peers are `eslint` and `typescript`; it has no `next` peer.
  - Moving it would not clear its findings below. `@next/eslint-plugin-next`
    16.3.8 still pins `fast-glob` 3.3.1, which reaches `braces`.
  - The 2026-09-07 audit moved it together with `next`. Doing that again is
    outside the approved scope.

## Dependencies — after

- `npm audit --omit=dev --audit-level=high`: **exit 0**. The report still
  lists `vitest` and `@vitest/mocker` as moderate, which is below the blocking
  level.
- Full tree: 8 entries (0 critical, 6 high, 2 moderate). All are lint-time or
  test-time; they are triaged next.

### Remaining findings — triage

"Reachable" means the advisory's stated precondition exists in this
repository, not merely that the package is installed.

| Package (path) | Advisory | Sev. | Tree | Precondition | Here | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `vitest` 4.1.10, `@vitest/mocker` 4.1.10 (root devDependency; also an optional peer of `better-auth` 1.7.3) | GHSA-82fw-gwwq-j7x9: path traversal / file read via redirect mock | moderate (5.9) | in the `--omit=dev` report; see the note below | a client that can reach the Vite HMR WebSocket of a network-exposed dev server, or use of the public `mockerPlugin`/`interceptorPlugin` | `vitest run` with `environment: "node"`; no browser mode, no `server.host`, no mocker plugin | not reachable; deferred here. **Fixed** in the follow-up: `vitest` 4.1.11. |
| `braces` 3.0.3 (`eslint-config-next` → `@next/eslint-plugin-next` → `fast-glob` 3.3.1 → `micromatch` 4.0.8) | GHSA-vfj7-8cjw-p6xm: stack exhaustion on deeply nested patterns | high (7.5) | dev | the attacker supplies the brace pattern | patterns come from this repository's own lint config, at lint time | not reachable; **deferred**. No patched `braces` exists (3.0.3 is the latest). npm only offers `--force` down to `eslint-config-next` 14.2.35, a breaking downgrade, which was not applied. Re-checked in the follow-up: still no patched release. |
| `micromatch`, `fast-glob`, `@next/eslint-plugin-next`, `eslint-config-next` | none of their own; flagged only because they depend on `braces` | high | dev | — | — | follows `braces` |
| `brace-expansion` 1.1.18 (`eslint` → `minimatch` 3.1.5) and 5.0.9 (`typescript-eslint` → `@typescript-eslint/typescript-estree` → `minimatch` 10.2.5) | GHSA-qhr7-859c-m2p7 and GHSA-6j4f-fj2g-mc7p: stack exhaustion; GHSA-q2hr-2g5m-vwhr: quadratic `{a},b}` rewrite | high (7.5), high (7.5), moderate (5.3) | dev | untrusted patterns passed to `expand()`, or through `minimatch`/`glob` | lint-time globs from this repository's own config | not reachable; deferred here. **Fixed** in the follow-up: `npm audit fix` moved them to 1.1.21 and 5.0.12. |

**Why `vitest` appears in the production-tree report.**
- `better-auth` 1.7.3 declares `vitest` (`^2.0.0 || ^3.0.0 || ^4.0.0`) as an
  optional peer dependency.
- The root devDependency satisfies that peer. npm therefore marks `vitest`
  `devOptional` instead of `dev`, and `--omit=dev` keeps it.
- The only `better-auth` file that imports `vitest` is
  `dist/test-utils/test-instance.mjs`.
- The application imports only `better-auth`, `better-auth/react`,
  `better-auth/client/plugins`, `better-auth/next-js` and
  `better-auth/plugins`.

**Deferred, not fixed here.** This change was approved for the blocking `next`
finding only. The runbook still prefers semver-compatible fixes for
unreachable findings, so two updates are left for a separate change:
`brace-expansion` (via `npm audit fix`) and `vitest` 4.1.11. `braces` waits for
an upstream release.

Both updates were made in that separate change; see *Follow-up — deferred
dev-tree fixes* below. `braces` still waits.

## Secrets

`detect-secrets` 1.5.0, run with the CI step's file list and baseline on this
branch: exit 0. The only files changed are `web/package.json`,
`web/package-lock.json` (excluded from the scan, as in CI) and this record.

## Regression validation on the bumped stack

Run on this branch after remediation. These are the CI `verify` and `a11y`
jobs, reproduced locally.

| Check | Result |
| --- | --- |
| `npm ci` from the new lockfile | 507 packages; `next` 16.3.8 installed |
| `npm audit --omit=dev --audit-level=high` | exit 0 (was exit 1 on `main`) |
| `python3 -m unittest discover -s tests` | 102 tests, OK |
| `npm run test:run` | 85 passed in 16 files |
| `npm run typecheck` | clean |
| `npm run lint` | clean |
| `npm run build` | `Next.js 16.3.8 (webpack)`, compiled successfully |
| `npm run acceptance:upload`, separate web and worker processes, fresh `.runtime` | `signIn`, `caseAuthorization`, `directWorkerUpload`, `responseDraft`, `verifiedDeletion` all `passed`; `finalState: sanitized`; `rawCanaryLeaks: 0`; `modelStatus: disabled`; `hitlAnswers: 1` |
| `npm run acceptance:a11y`, fresh `.runtime`, Chromium headless shell revision 1194 | 23 axe scans with 0 violations and 0 incomplete; 24 keyboard tab stops with 0 failures; `coreFlowByKeyboard: passed`; exit 0 |

## Follow-up — deferred dev-tree fixes

This is the separate change the triage above left two updates for. Neither
finding is reachable (see the triage); the runbook prefers the fix anyway.
`braces` was re-checked and stays deferred.

Baseline: `main` at `dd43e02`, which includes the `next` change (`faf993a`).
Checked on 2026-10-05.

### Tools

| Tool | Version / source | Ran against |
| --- | --- | --- |
| `npm install`, `npm audit fix`, `npm ci` | npm 11.21.0 and npm 10.9.8; see *How the lockfile was regenerated* | `web/package.json`, `web/package-lock.json` |
| `npm audit` | npm 10.9.8 (the npm in CI's Node 22.22.3) and npm 10.9.4, registry.npmjs.org advisory DB | the new lockfile, with `--omit=dev --audit-level=high` and on the full tree |
| `npm view` | same | published versions, dates, publishers, dependency ranges, `dist.integrity` |
| `npm audit signatures` | npm 10.9.8 | **not run**: it needs `tuf-repo-cdn.sigstore.dev`, which the network this audit ran from blocks. Instead, the lockfile `integrity` of `vitest`, `@vitest/mocker`, both `brace-expansion` versions, `vite` and `rolldown` was compared with `npm view <pkg>@<version> dist.integrity`: all six match. |

### Before

- `npm audit --omit=dev --audit-level=high`: exit 0. The report lists 2
  entries, `vitest` and `@vitest/mocker` (moderate).
- Full tree: 8 entries (6 high, 2 moderate), as in *Dependencies — after*.

### Remediation

| Change | From → to | Kind | Why this version |
| --- | --- | --- | --- |
| `vitest` (exact pin, devDependency) | 4.1.10 → 4.1.11 | patch | GHSA-82fw-gwwq-j7x9 affects `>=2.1.0 <4.1.11`, so 4.1.11 is the first patched release. It is also the `V4` dist-tag, the newest 4.x (published 2026-08-18). `latest` is 5.0.3, a major outside `better-auth` 1.7.3's optional peer range for `vitest` (which stops at `^4.0.0`); not taken. Against 4.1.10, 4.1.11 changes no third-party dependency range; only its lockstep `@vitest/*` pins move. |
| `brace-expansion` (transitive, under `minimatch`) | 1.1.18 → 1.1.21, 5.0.9 → 5.0.12 | patch | `npm audit fix`, no `--force`. These are the first versions outside all three advisories (GHSA-q2hr-2g5m-vwhr covers `<1.1.21` and `>=4.0.0 <5.0.12`; the other two end earlier) and the newest of their lines. Both were published on 2026-09-14 by `juliangruber`, a listed maintainer. They fit the existing ranges (`minimatch` 3.1.5: `^1.1.7`; 10.2.5: `^5.0.5`), so `package.json` does not change for them. |

### How the lockfile was regenerated

`npm install --save-dev --save-exact vitest@4.1.11` fails on every npm 10
release tried — 10.9.4, 10.9.8 (CI's) and 10.9.9 (the newest 10.x) — with
`Cannot read properties of null (reading 'edgesOut')`, before anything is
written:

- npm resolves the new `vitest`'s peers, optional ones included, into a
  temporary peer set. Today that walk loops back to `vitest`: `vite` 8.3.2
  (what `^6.0.0 || ^7.0.0 || ^8.0.0` resolves to) has the optional peer
  `@vitejs/devtools` `^0.7.1`; its 0.7.6 has the optional peer
  `@vitejs/devtools-vitest`; that package's only peer is `vitest` `*`.
- When the walk reaches `vitest` again, npm 10's arborist (8.0.5 in 10.9.8
  and 10.9.9) adds a second `vitest` to the peer set. That detaches a node the
  walk is still iterating over, and the next step reads that node's parent,
  which is now `null`. The arborist in npm 11.21.0 (9.9.2) checks for a
  detached node at that point and stops the loop.
- Every `vite` from 8.2.0 (2026-07-30) on leads into the loop, through
  `@vitejs/devtools` 0.4.2 or later. `vitest` 4.1.11 is newer (2026-08-18), so
  `npm install --before=<date>` cannot avoid it.
- `--legacy-peer-deps` would skip the walk. It was not used, as in the earlier
  audits.

npm 11 cannot simply replace npm 10 here, because it would also change what
the lockfile means to CI:

- Run as a no-op on `main`'s lockfile (`npm install --package-lock-only`),
  npm 11.21.0 already rewrites it. It drops the 64 entries the lockfile
  carries only as optional peers (`"dev": true, "optional": true,
  "peer": true`; listed under *What else moved*). It also clears the `dev`
  flag on 64 other entries, among them `tsx`, `jiti`, `punycode` and the
  `@rolldown/binding-*` packages, so the blocking `npm audit --omit=dev` step
  would scan them too.
- It writes `libc` fields, which npm 10 does not. The `vitest` step alone
  added 10, on new Linux platform packages.

So npm 11.21.0 did only the step npm 10 cannot do, and npm 10.9.8 wrote the
file last:

```sh
cd web
npx npm@11.21.0 install --package-lock-only --save-dev --save-exact --no-audit --no-fund vitest@4.1.11
npx npm@10.9.8 audit fix --package-lock-only --no-fund
npx npm@10.9.8 ci --no-audit --no-fund
```

- `npm audit fix` changes the tree, so npm 10.9.8 recomputes every dependency
  flag and re-serialises the whole file in its own format. The `libc` fields
  are gone, and every entry that is also in `main` keeps `main`'s flags,
  except `lightningcss` (see below).
- npm 10 does not rewrite the result: `npm install --package-lock-only` with
  npm 10.9.8 and with npm 10.9.4 leaves it byte-identical.
- The two commands, run again from `main` in a clean copy, produce the same
  bytes.
- The 64 optional-peer entries npm 11 dropped stay dropped. npm 10 does not
  add an optional peer that nothing requires, nor remove one a lockfile already
  has: a no-op npm 10.9.8 install on `main` keeps all 64.

For the next `vitest` update, npm 10 will crash the same way for as long as
the registry has this loop. Use the same two steps, or move CI to npm 11 as a
change of its own, after checking what it does to the `--omit=dev` scope.

### What else moved

Lockfile: +427/−1268 lines; 647 → 594 entries (17 added, 70 removed, 28
version changes). `npm ci` installs 469 packages instead of 507.
`package.json` changes only the `vitest` pin.

- **Re-resolved with `vitest` 4.1.11.** All test-time packages. They are in
  the `--omit=dev` tree only through `better-auth`'s optional `vitest` peer,
  as before.
  - `vite` 8.1.4 → 8.3.2 (`latest`). npm resolved it fresh as part of
    `vitest`'s peer set, so it now sits at the root instead of under `vitest`.
  - Pulled in by `vite`: `rolldown` 1.1.5 → 1.2.12 with its platform
    bindings, and `@oxc-project/types` 0.139.0 → 0.152.0. Rolldown 1.2.12 no
    longer lists `@rolldown/binding-wasm32-wasi`, so that binding and its
    three `@emnapi/*` packages go; `@rolldown/binding-android-arm-eabi` is
    new. `vite` also gets nested copies of `lightningcss` 1.33.0 (with 11
    platform packages), `picomatch` 4.0.7 and `postcss` 8.5.28.
  - `@vitest/*` 4.1.10 → 4.1.11; `@vitest/mocker` moves to the root.
    `vitest`'s nested `picomatch` 4.0.5 → 4.0.7. `chai` 6.2.2 → 6.3.0 and
    `tinyrainbow` 3.1.0 → 3.2.0, within the ranges `vitest` and `@vitest/*`
    already declared; nothing else depends on them.
- **Removed: 64 optional-peer entries that nothing requires.**
  - `jsdom` 29.1.1 and 36 packages only it needed, including `undici` 7.29.1.
    It is an optional peer of `vitest`, and `vitest.config.ts` runs
    `environment: "node"`.
  - `esbuild` 0.28.1 and 26 platform packages, nested under `vitest` as an
    optional peer of `vite`.
  - Nothing under `web/` except the lockfile mentions `jsdom`, `happy-dom` or
    `esbuild`.
- **`--omit=dev` scope.** The blocking audit now covers 161 entries instead
  of 159, and the whole difference is inside `vitest`'s subtree: the version
  moves above, plus `vite`'s nested `lightningcss`, `picomatch` and `postcss`.
  The root `lightningcss` 1.32.0 left the scope. It is now `dev`-only because
  only `@tailwindcss/node` uses it, and `vite` 8.3.2 carries its own 1.33.0.
  Nothing outside `vitest`'s subtree entered or left the scope.

### After

- `npm audit --omit=dev --audit-level=high`: **exit 0**, "found 0
  vulnerabilities" (npm 10.9.8 and 10.9.4). `vitest` is still in this tree,
  for the reason given above; 4.1.11 is inside `better-auth`'s optional peer
  range.
- Full tree: **5 entries (5 high, 0 moderate)**, down from 8. `vitest`,
  `@vitest/mocker` and `brace-expansion` are gone, and with them
  GHSA-82fw-gwwq-j7x9, GHSA-qhr7-859c-m2p7, GHSA-6j4f-fj2g-mc7p and
  GHSA-q2hr-2g5m-vwhr. Left: the `braces` chain (`braces`, `micromatch`,
  `fast-glob`, `@next/eslint-plugin-next`, `eslint-config-next`).

### `braces`, re-checked

Still deferred, with the triage unchanged. The registry has no fix:

- `braces`: the newest release is still 3.0.3, and the package metadata has
  not changed since 2024-09-18. GHSA-vfj7-8cjw-p6xm covers `<=3.0.3`.
- No newer release up the chain avoids it:
  - `micromatch` 4.0.8 (newest) needs `braces` `^3.0.3`;
  - `fast-glob` 3.3.3 (newest) needs `micromatch` `^4.0.8`;
  - `@next/eslint-plugin-next` pins `fast-glob` 3.3.1 in 16.3.4 (installed),
    16.3.8 (`latest`) and 16.4.0-canary.60 (`canary`).
- npm still offers only `npm audit fix --force`, which installs
  `eslint-config-next` 14.2.35. Not applied.

### Secrets

`detect-secrets` 1.5.0, run with the CI step's file list and baseline on this
branch: exit 0. The changed files are `web/package.json`,
`web/package-lock.json` (excluded from the scan, as in CI) and this record.

### Regression validation

Run on this branch after remediation, on the tree `npm ci` (npm 10.9.8)
installed. These are the CI `verify` and `a11y` jobs, reproduced locally on
Node 22.22.0 and Python 3.11.

| Check | Result |
| --- | --- |
| `npm ci` (npm 10.9.8) from the new lockfile | 469 packages; `vitest` 4.1.11 and `vite` 8.3.2 installed |
| `npm audit --omit=dev --audit-level=high` | exit 0, 0 vulnerabilities |
| `python3 -m unittest discover -s tests` | 303 tests, OK |
| `npm run test:run` | `vitest` v4.1.11: 85 passed in 16 files |
| `npm run typecheck` | clean |
| `npm run lint` | clean |
| `npm run build` | `Next.js 16.3.8 (webpack)`, compiled successfully |
| `npm run acceptance:upload`, separate web and worker processes, fresh `.runtime` | `signIn`, `caseAuthorization`, `directWorkerUpload`, `responseDraft`, `verifiedDeletion` all `passed`; `finalState: sanitized`; `rawCanaryLeaks: 0`; `modelStatus: disabled`; `hitlAnswers: 1` |
| `npm run acceptance:a11y`, fresh `.runtime`, Chromium headless shell revision 1194 | 23 axe scans with 0 violations and 0 incomplete; 24 keyboard tab stops with 0 failures; `coreFlowByKeyboard: passed`; exit 0 |
