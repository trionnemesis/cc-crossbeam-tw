# Security audit — dependencies and secrets (2026-09-07)

Closes the scan, dependency-reachability and fixed-version parts of issue #10
item 7. Every finding below is classified as **confirmed**, **deferred** or
**suppressed**, with the evidence that put it there. What this audit could not
reach is listed at the end rather than folded into the totals.

Baseline: `main` at `8de9706`. Web app `web/`, Python packages `tw_law_mcp/`
and `worker/`.

## Tools

| Tool | Version / source | Ran against |
| --- | --- | --- |
| `npm audit` | npm 10.9.7, registry.npmjs.org advisory DB | `web/package-lock.json`, full tree and `--omit=dev` |
| `pip-audit` | PyPI advisory DB | the container's Python environment (see Python section) |
| `detect-secrets` | 1.5.0 | every tracked file except `*.png` and `package-lock.json` |
| git history sweep | regex over `git log -p --all` | AWS, GitHub, OpenAI, Slack, Google API key, private key and JWT shapes |
| GitHub secret scanning API | — | **unavailable**: the repository does not have GitHub Advanced Security enabled |

Advisory preconditions were read from the GitHub advisory pages themselves,
not inferred from titles.

## Dependencies — before

13 advisories: 8 high, 5 moderate, 0 critical. Production tree
(`--omit=dev`): 9, of which 4 high. Two direct dependencies carried them:
`next` 16.2.10 and `better-auth` 1.6.23.

### Reachability triage

"Reachable" means the advisory's stated precondition exists in this
application's runtime path, not merely that the package is installed.

| Package (path) | Advisory | Sev. | Tree | Precondition | Here | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `next` 16.2.10 (direct) | GHSA-6gpp-xcg3-4w24 middleware/proxy bypass | high | prod | App Router **+ Turbopack + single `i18n.locales` entry + middleware-based auth** | no `middleware.ts`/`proxy.ts`; build is `next build --webpack`; no `i18n` config; auth is enforced in route handlers via `requireAppSession` | not reachable |
| `next` 16.2.10 | GHSA-m99w-x7hq-7vfj Server Action DoS | high | prod | "at least one Server Action" | no `"use server"` anywhere in `app/` or `src/` | not reachable |
| `next` 16.2.10 | GHSA-89xv-2m56-2m9x SSRF in Server Actions on custom servers | high | prod | custom server + Server Actions | `next start`, no custom server; no Server Actions | not reachable |
| `next` 16.2.10 | GHSA-68g3-v927-f742 cache confusion of response bodies | moderate | prod | server-side `fetch(new Request(init), aDifferentInit)` | the three server-side fetches (`api/hitl/[questionId]/route.ts`, `channels/line.ts` ×2) are `fetch(url, init)`; `new Request(` does not occur in server code | not reachable |
| `postcss` 8.4.31 (via `next`) | GHSA-qx2v-qp2m-jg93, -6g55-p6wh-862q, -fxqj-rqcc-2cmp, -r28c-9q8g-f849 | high | prod (build-time) | attacker-controlled CSS / `sourceMappingURL` fed to PostCSS | PostCSS only processes the repository's own stylesheets at build time | not reachable |
| `sharp` 0.34.5 (via `next`) | GHSA-f88m-g3jw-g9cj libvips CVEs | high | prod | untrusted images through `next/image` | no `next/image` usage; `og.png` is referenced from metadata only, never optimised | not reachable |
| `nanoid` 3.3.15 (via `postcss`) | GHSA-28wg-ghj8-5hjv, -2v37-7h3g-55p8 | high | prod | caller passes size ≤ 0 to a custom/non-secure generator | only internal fixed-size calls inside PostCSS | not reachable |
| `better-auth` 1.6.23 (direct) → `drizzle-kit` → `@esbuild-kit/*` → `esbuild` 0.18.20 | GHSA-67mh-4wv8-2f99 esbuild dev server accepts any origin | moderate | prod | the esbuild **dev server** running | the chain exists only because better-auth 1.6 hard-depended on `drizzle-kit`; nothing here starts an esbuild dev server | not reachable |
| `brace-expansion` (eslint, typescript-estree) | GHSA-mh99-v99m-4gvg, -rgw5-rvv9-x895 DoS | high | dev | attacker-controlled glob pattern | lint-time only | dev-only |
| `browserslist` (eslint-config-next → babel) | GHSA-c83g-rgw3-j3cx, -73wf-gq98-2v4g | high | dev | attacker-controlled queries / custom stats file | lint-time only | dev-only |
| `js-yaml` (eslint) | GHSA-5p4m-2wfm-xmqj quadratic `!!omap` | high | dev | attacker-controlled YAML parsed at runtime | eslint config loading only | dev-only |
| `undici` 7.28 (vitest → jsdom) | GHSA-8xcm-r25x-g524, -4cwx-7wf7-3272, -m8rv-5g2x-5cg5, -jr45-8vmc-qm54 | high | dev | undici retry/cache interceptors, blob-type CRLF | test-time only; the app uses Node's built-in `fetch` | dev-only |

Net: **0 reachable** in the production tree. The fixes were applied anyway —
an unreachable advisory on a package is no guarantee about the next one.

### Remediation (fixed-version validation)

| Change | From → to | Kind | Why this version |
| --- | --- | --- | --- |
| `next`, `eslint-config-next` | 16.2.10 → 16.3.4 | semver-minor | patched line ≥ 16.2.11; 16.3.4 is `latest`; pulls fixed `postcss`/`sharp` |
| `better-auth`, `@better-auth/drizzle-adapter` | 1.6.23 → 1.7.3 | semver-minor | fixes `GHSA-537c-gmf6-5ccf`; the reinstall below also flushed a stale resolved `drizzle-kit`/esbuild-kit chain (see below — `drizzle-kit` was already an optional peer at 1.6.23, this was not a 1.7 change); 1.7.3 is `latest` (published 2026-09-06) |
| transitive (`nanoid`, `brace-expansion`, `browserslist`, `js-yaml`, `undici`) | — | `npm audit fix` | semver-compatible only; no `--force` |

Existence of each target version was checked against the registry before
installing. The first attempt hit `ERESOLVE` because the lockfile pinned the
old adapter against the new `@better-auth/core`; resolved by uninstalling the
pair and reinstalling both at 1.7.3 — **not** by `--legacy-peer-deps` or
`--force`. Lockfile delta: +439 / −1380 lines.

## Dependencies — after

`npm audit`: **0** (full tree). `npm audit --omit=dev`: **0**.

### What the bump changed, and what was checked

- `@better-auth/core` `internalAdapter.createUser` now takes a required
  `source` argument (the provisioning method feeding the new
  `user.validateUserInfo` gate). Only `web/tests/better-auth.test.ts` called
  it; updated to pass the Google OAuth source those tests model. Application
  code did not use the internal API.
- `next-env.d.ts` was regenerated with an additional
  `import "./.next/types/root-params.d.ts"`. Verified that `tsc --noEmit`
  still passes on a tree **without** `.next`, so CI's typecheck-before-build
  order is unaffected.
- **`@better-auth/telemetry`, pre-existing, not new with this bump.**
  Corrected after review (thanks @chatgpt-codex-connector on #23): the
  original text here called this "new surface" arriving with 1.7. It does
  not. `better-auth@1.6.23`'s own `dependencies` already listed
  `@better-auth/telemetry@1.6.23`, and it was already resolved in the
  pre-PR lockfile — confirmed against `web/package-lock.json` at `8de9706`
  (the commit before this audit's changes), not just registry metadata.
  1.6.23 was never separately audited for it, because nothing in this repo's
  history had. Read now, not assumed:
  - enabled only if `telemetry.enabled === true` or `BETTER_AUTH_TELEMETRY`
    is truthy (`options.telemetry?.enabled ?? false`); this was equally true
    at 1.6.23 — same gate, same default;
  - additionally a no-op unless `BETTER_AUTH_TELEMETRY_ENDPOINT` is set (no
    hard-coded endpoint in either version);
  - payload is config shape (booleans for hooks, plugin ids), runtime /
    framework / database / package-manager detection, and an anonymous
    project id derived from `baseURL`. No user or request data.
  - Decision: pinned `telemetry: { enabled: false }` in `buildAuth` and added
    a test that asserts it, so neither a future library default nor the host
    environment decides this for a process on the customer-data boundary.
    The pin closes the gap retroactively for 1.6.23's behavior too, not only
    1.7.3's.
  - Status: **confirmed (pre-existing since at least 1.6.23), mitigated**.

## Correction to the `drizzle-kit` / esbuild-kit remediation claim

Also raised in review on #23, also verified against the actual pre-PR
lockfile rather than taking the original write-up at its word.

**Original claim:** "1.7 makes `drizzle-kit` an optional peer, removing the
esbuild-kit chain." **Wrong.** `drizzle-kit` was already
`peerDependenciesMeta: { "drizzle-kit": { "optional": true } }` on
`better-auth@1.6.23` — confirmed against both the registry and the pre-PR
lockfile at `8de9706`. 1.7 did not change that declaration.

What actually happened, reproduced in an isolated `npm install` outside this
repo: a bare install of `better-auth@1.6.23` alone, and of
`better-auth@1.6.23` alongside `drizzle-orm@0.45.2` as a sibling — the two
packages actually present in this project — does **not** resolve
`drizzle-kit` at all, at either 1.6.23 or 1.7.3. The optional peer sits
unsatisfied and npm leaves it out, in both versions. So `drizzle-kit@0.31.10`
sitting resolved in the pre-PR `web/package-lock.json` was a stale artifact
of that lockfile's install history, not something either version's
declarations require.

The chain actually disappeared because remediation uninstalled
`better-auth`/`@better-auth/drizzle-adapter` and reinstalled both fresh,
which forced npm to re-resolve the whole dependency set from scratch rather
than build on the existing lockfile. That fresh resolution simply didn't
pull the optional peer in — matching the reproduction above. The `npm audit
fix` step afterward found nothing left to do on this chain because it was
already gone.

Practical effect on the finding: none. The reachability triage on
`esbuild`/`@esbuild-kit/*` (GHSA-67mh-4wv8-2f99 — requires the esbuild dev
server running, which this project never starts) stands regardless of why
the chain is gone. The fix stands too — the packages are no longer resolved,
however that came about. Only the *causal story* in the original write-up
was wrong, and it is corrected here rather than silently edited, so the
review comment and this record read the same way going forward.

## Python

`pyproject.toml` declares `dependencies = []`, and an AST scan of every
module under `tw_law_mcp/`, `worker/`, `tests/` and `scripts/` finds no
import outside the standard library. There is nothing for a Python advisory
scanner to check in this project.

`pip-audit` run against the **container environment** reported 39 advisories
in 8 packages (`cryptography`, `httplib2`, `idna`, `pip`, `pyjwt`,
`setuptools`, `urllib3`, `wheel`). None is imported or installed by this
project; CI provisions Python 3.14 fresh and installs nothing. Status:
**suppressed — not a dependency of this project**. They belong to whoever
owns the runner image.

## Secrets

`detect-secrets` over tracked files: 16 candidates in 8 files, every one
reviewed on the line:

| File | Count | What it is |
| --- | --- | --- |
| `tests/test_secure_worker.py`, `web/scripts/e2e-upload.ts` | 2 | the synthetic canary ID `A123456789` used to prove masking |
| `tw_law_mcp/data/local_rules/ntpc-interior-review-rule.json` | 5 | `normalized_content_sha256` values |
| `web/tests/{allowlist,better-auth,line-link,line-webhook-route,runtime-config}.test.ts` | 9 | literal placeholders (`"google-secret"`, `"line-secret"`, a `user:password@` test `DATABASE_URL`) |

History: 0 matches across all refs for the key shapes listed under Tools; no
`.env` file was ever committed; `.gitignore` covers `.env`, `.env.*`,
`.runtime/` and SQLite files.

Status: **0 confirmed; 16 suppressed with the reasons above**, recorded in
`.secrets.baseline` so the CI step fails only on something new.

## Continuous gate

`.github/workflows/secure-web.yml` gains a `security-scan` job beside
`verify`:

- `npm audit --omit=dev --audit-level=high` — blocking;
- `npm audit` on the full tree — informational, never blocking;
- `detect-secrets-hook --baseline .secrets.baseline` over tracked files —
  blocking on a candidate the baseline does not know.

How to respond when it goes red is in
`docs/runbook-secure-web.md` → *Dependency and secret scanning*. The rule is
triage and record, never `--force`, ignore lists or `continue-on-error`.

## Abuse-case coverage exercised by the regression run

Item 7 asks for abuse-case tests alongside the ordinary suites. The ones that
already exist and ran on the bumped stack:

- raw canary crossing the masking boundary → `acceptance:upload` asserts
  `rawCanaryLeaks: 0` across a real cross-process upload;
- PII the masker misses → `test_residual_detection_runs_with_the_model_disabled`
  (fail-closed with the model off);
- overload → `test_worker_refuses_uploads_once_processing_capacity_is_full`
  (503 before any body is read);
- agent-asserted HITL/audit fields → provenance tests in
  `tests/test_law_repository.py` (evidence record stays `unapproved`);
- tampered LINE webhook body → `web/tests/line-webhook-route.test.ts` (401);
- revoked owner → `web/tests/better-auth.test.ts` (session refused, user
  creation refused).

## Not closed here

- The original audit's "canonical worklist 11 / 257" lives in the tool that
  produced #10, not in this repository. It cannot be closed from here and its
  numbers are not reflected above.
- GitHub-side scanning (Dependabot alerts, secret scanning push protection)
  is a repository setting. Recommended, and cheap for a public repository,
  but it is the owner's switch.
- Runner/container image advisories (the `pip-audit` list above).

## Regression validation on the bumped stack

Run on this branch after remediation, in the order item 7 asks for —
targeted tests, related suites, typecheck, lint, build, then the abuse-case
acceptance across real processes.

| Check | Result |
| --- | --- |
| `python3 -m unittest discover -s tests` | 100 tests in 0.524s, OK |
| `npm run test:run` | 38 passed, 14 files (37 + the telemetry pin) |
| `npm run typecheck` | clean — also verified clean on a tree without `.next` |
| `npm run lint` | clean |
| `npm run build` (next 16.3.4, webpack) | production build passed |
| `npm run acceptance:upload` on a fresh `.runtime` | `signIn`, `caseAuthorization`, `directWorkerUpload`, `responseDraft`, `verifiedDeletion` all `passed`; `finalState: sanitized`; `rawCanaryLeaks: 0`; `modelStatus: disabled` |
| anonymous sign-in through better-auth 1.7.3 | HTTP 200, `user.isAnonymous: true`, `/cases` 200 with the issued cookie |

The acceptance run is the one that matters for the auth bump: it exercises
sign-in, session cookies, case authorization, the HITL answer path and
verified deletion against the tables this application creates itself, on the
new library version, in separate web and worker processes.
