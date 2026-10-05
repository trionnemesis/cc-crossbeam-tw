# Security audit — `next/og` advisory and dev-tree findings (2026-10-05)

The blocking `security-scan` step ("Dependency advisories — production tree
(blocking)") went red after GHSA-vcvr-r3jv-pc5j was published for `next`. It
is red on `main`'s lockfile and on every branch built from it, including PR
#29, which does not touch `web/`. This record follows the runbook
(`docs/runbook-secure-web.md` → *When the dependency step goes red*). Every
finding the scan reports today is triaged below, but only one is changed here.
The repository owner approved this change for the blocking `next` finding.

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
| `vitest` 4.1.10, `@vitest/mocker` 4.1.10 (root devDependency; also an optional peer of `better-auth` 1.7.3) | GHSA-82fw-gwwq-j7x9: path traversal / file read via redirect mock | moderate (5.9) | in the `--omit=dev` report; see the note below | a client that can reach the Vite HMR WebSocket of a network-exposed dev server, or use of the public `mockerPlugin`/`interceptorPlugin` | `vitest run` with `environment: "node"`; no browser mode, no `server.host`, no mocker plugin | not reachable; **deferred**. Fixed in `vitest` 4.1.11. |
| `braces` 3.0.3 (`eslint-config-next` → `@next/eslint-plugin-next` → `fast-glob` 3.3.1 → `micromatch` 4.0.8) | GHSA-vfj7-8cjw-p6xm: stack exhaustion on deeply nested patterns | high (7.5) | dev | the attacker supplies the brace pattern | patterns come from this repository's own lint config, at lint time | not reachable; **deferred**. No patched `braces` exists (3.0.3 is the latest). npm only offers `--force` down to `eslint-config-next` 14.2.35, a breaking downgrade, which was not applied. |
| `micromatch`, `fast-glob`, `@next/eslint-plugin-next`, `eslint-config-next` | none of their own; flagged only because they depend on `braces` | high | dev | — | — | follows `braces` |
| `brace-expansion` 1.1.18 (`eslint` → `minimatch` 3.1.5) and 5.0.9 (`typescript-eslint` → `@typescript-eslint/typescript-estree` → `minimatch` 10.2.5) | GHSA-qhr7-859c-m2p7 and GHSA-6j4f-fj2g-mc7p: stack exhaustion; GHSA-q2hr-2g5m-vwhr: quadratic `{a},b}` rewrite | high (7.5), high (7.5), moderate (5.3) | dev | untrusted patterns passed to `expand()`, or through `minimatch`/`glob` | lint-time globs from this repository's own config | not reachable; **deferred**. `npm audit fix` has a semver-compatible fix. |

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
