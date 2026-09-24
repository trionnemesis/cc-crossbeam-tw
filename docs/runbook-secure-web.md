# Secure Web single-user runbook

## Supported modes

| Mode | Human auth | Storage/DB | Model | Exposure |
| --- | --- | --- | --- | --- |
| `local` | Loopback-only anonymous pilot | Private `.runtime` SQLite/files | Optional local Codex | `127.0.0.1` only |
| `single-user` | Google OIDC allowlisted to `OWNER_EMAIL` | Private host SQLite/files | Local Codex ChatGPT auth | HTTPS reverse proxy |
| `production` | Google OIDC invite table | Cloud SQL/GCS/Tasks | Approved service provider | Fails closed until provisioned |

Codex/ChatGPT auth is never a website identity provider. It is only the model credential
for the local worker process running as the authenticated host user.

Raw ingestion is intentionally limited to UTF-8 TXT. PDF/image extraction remains disabled
until it runs under a separate low-privilege, network-disabled parser sandbox; do not enable
host-level `pdftotext` or `tesseract` in the Codex-authenticated worker process.

## Single-user prerequisites

1. A dedicated host account with full-disk encryption and automatic OS security updates.
2. A public domain whose DNS points to the host or an approved private tunnel.
3. Caddy or an equivalent TLS reverse proxy.
4. Google OAuth web client with exact callback:
   `https://<domain>/api/auth/callback/google`.
5. LINE Messaging API channel with webhook:
   `https://<domain>/api/channels/line/webhook`.
6. Codex CLI logged in as the host user; verify only with `codex login status`.

Do not copy `~/.codex/auth.json`, browser cookies, or ChatGPT tokens to another host.

## Required configuration

Credentials belong in the process manager/secret store, not in the repository.

```text
APP_MODE=single-user
APP_ORIGIN=https://secure.example.com
WORKER_UPLOAD_ORIGIN=https://secure.example.com/worker
LOCAL_WORKER_ORIGIN=http://127.0.0.1:8787
OWNER_EMAIL=<single allowed Google email>
GOOGLE_CLIENT_ID=<credential>
GOOGLE_CLIENT_SECRET=<credential>
LINE_CHANNEL_ID=<credential>
LINE_CHANNEL_SECRET=<credential>
LINE_CHANNEL_ACCESS_TOKEN=<credential>
BETTER_AUTH_SECRET=<at least 32 random characters>
CODEX_WORKER_ENABLED=true
```

`DATABASE_PATH`, `QUARANTINE_ROOT`, and `SANITIZED_ROOT` default to the private
repository `.runtime` directory. That directory must be `0700`; files are `0600`.

### Worker capacity

The worker refuses work past these ceilings rather than queueing it without bound.
Defaults suit the one-user pilot; raise them only with the host's CPU and memory in
mind, because each pending job can start a Codex subprocess.

```text
WORKER_MAX_INFLIGHT_REQUESTS=16    # concurrent connections before 503
WORKER_MAX_PROCESSING_WORKERS=2    # concurrent document analyses
WORKER_MAX_PENDING_JOBS=8          # analyses accepted but not yet finished
WORKER_REQUEST_TIMEOUT_SECONDS=30  # per-connection read timeout
WORKER_MODEL_TIMEOUT_SECONDS=120   # Codex subprocess timeout
```

`WORKER_MAX_PENDING_JOBS` must be at least `WORKER_MAX_PROCESSING_WORKERS`; the worker
refuses to start otherwise. A `503` with `Retry-After` from the upload endpoint means
capacity was full — the upload was refused before any body was read, so nothing was
written to quarantine and the client may retry.

### Revoking access

Change `OWNER_EMAIL` (or deactivate the invitation) and restart the web process. The
allowlist is re-checked on every request, so the removed account's existing sessions are
deleted the next time they are used; there is no separate session-purge step.

## Build and start

```sh
cd web
npm ci
npm run test:run
npm run typecheck
npm run lint
npm run build
npm start
```

In a second host process:

```sh
python3 -m worker.secure_worker.server
```

Install `deploy/Caddyfile.example` after replacing the domain. Caddy routes `/worker/*`
directly to the loopback worker and all other paths to Next.js. This keeps raw upload
bytes out of the Next.js process.

## Health and smoke checks

- `GET /api/health` must report `single-user`, `local-private`, and no secret values.
- `GET /worker/health` must report `private-local`.
- Google OAuth must open in the external system browser when entered from LINE.
- LINE webhook modified-body signature test must return `401`.
- Run `npm run acceptance:upload` with only the synthetic canary fixture.
- Check `codex login status`; never print the credential file.

### `RESIDUAL_PII_BLOCKED` rejections

An upload rejected with this code was masked, then still tripped the independent
detector in `residual_pii.py`, so nothing was persisted: no sanitized file, no
`analysis_run`, no artifact row. The upload is `rejected` and terminal.

This is a working fail-closed, not an outage. It means the document carried a
sensitive shape that `masking.PATTERNS` does not cover — treat it as a masking gap
to fix, not a rejection to override. It fires with the model disabled too, since
the masked text is stored and rendered either way.

To diagnose without handling the raw file, reproduce with a synthetic string of the
same shape:

```sh
python3 -c "
from worker.secure_worker.masking import mask_sensitive_text
from worker.secure_worker.residual_pii import find_residual_sensitive_classes
sample = '證件 AB1234567 已附。'   # a synthetic stand-in, never the real value
masked = mask_sensitive_text(sample)
print(masked.text, find_residual_sensitive_classes(masked.text))
"
```

The detector's class names are safe to log; the matched text is not, and the
exception deliberately carries only the class list.

## Dependency and secret scanning

CI runs a `security-scan` job beside `verify`. It is deliberately separate so a
red result means a finding, not a failing test.

- `npm audit --omit=dev --audit-level=high` on the tree that ships. Blocking.
- `npm audit` on the full tree, including lint and test tooling. Informational.
- `detect-secrets-hook` over every tracked file against `.secrets.baseline`.
  Blocking on a candidate the baseline does not already know.

### When the dependency step goes red

Do not add `--force`, an ignore list, or `continue-on-error`. Triage the advisory
against this application and write the result down in
`docs/security-audit-<date>.md` under confirmed, deferred, or suppressed:

1. Is the package in the production tree (`npm ls <pkg> --omit=dev`) or only
   pulled in by eslint, vitest or the build?
2. Does the advisory's precondition exist here? Read the advisory itself — the
   preconditions are usually narrow (a middleware file, a Server Action, a
   custom server, a specific call pattern). Grep for the pattern; state what
   you found.
3. Is there a semver-compatible fix? Prefer it even when the finding is
   unreachable, because the next advisory on the same package may not be.
4. Re-run the full verify job plus the cross-process acceptance before merging.

### When the secret step goes red

`detect-secrets` flags shapes, not proof: high-entropy hex, `secret`-like
assignments, `user:password@` URLs. Every entry in the baseline today is a
test fixture or a content hash. For a new candidate:

- If it is a real credential, treat it as leaked: rotate it first, then remove
  it. Removing it from the working tree does not remove it from history.
- If it is a fixture or hash, refresh the baseline and record why:

```sh
detect-secrets scan --baseline .secrets.baseline
detect-secrets audit .secrets.baseline   # mark each new entry as reviewed
```

Commit the baseline with the change that introduced the candidate so the
review is in the same diff.

### Python

The Python packages have no third-party runtime dependencies
(`pyproject.toml` declares `dependencies = []`), so there is nothing for a
Python advisory scanner to check. If that ever changes, add `pip-audit` to the
`security-scan` job in the same commit that adds the dependency.

## Law corpus verification

Some articles are in the corpus as references without their text. They are marked
`verification_status: "pending_snapshot"` and fail the citation gate on purpose: the
corpus knows which law a correction points at, but nobody has verified what that law
currently says. Reviewers get the candidate article and its source URL instead of
"找不到可比對的法源條文", and the item still requires human confirmation.

Check the current state at any time:

```sh
python3 -c "from tw_law_mcp.repository import load_default_repository as r; import json; print(json.dumps(r().run_source_coverage_acceptance(), ensure_ascii=False, indent=2))"
```

Currently pending: 消防法第6條, 建築技術規則建築設計施工編第79條 and 第85-1條. They are
pending because the snapshots have not been taken, not because anything is broken.

### Promoting a pending article

Do this only from the official source; never from memory or a secondary site.

1. Retrieve the article from 全國法規資料庫 (`law.moj.gov.tw`). If the host running this
   work has restricted egress, allow that domain first — a snapshot from anywhere else
   is not the snapshot the source policy promises.
2. In `tw_law_mcp/data/p0_law_corpus.json`, set the article's `text`, change
   `verification_status` to `snapshot_verified`, and drop `verification_note`.
3. Set `verified_at` on the matching entry in `source_policies` and remove its
   `pending_reason`.
4. Re-run the Python suite. `run_source_coverage_acceptance` rejects a `pending_snapshot`
   article that carries text, so a half-finished promotion fails rather than shipping an
   unverified snapshot dressed as a verified one.

### Adding a new law

Add the source unit to the relevant pack under `tw_law_mcp/data/sources/`, add a source
policy, then add the article — as `pending_snapshot` if its text is not yet snapshotted.
The coverage gate fails when a pack references an article the corpus lacks, which is
what caught the original 消防法/建築技術規則 gap.

## Accessibility (R11)

What CI enforces on every push (`npm run test:run`):

- `web/tests/a11y-contrast.test.ts` reads the tokens in `web/app/globals.css` and fails
  if any text pair drops below 4.5:1 or any field border, dropzone border, or focus ring
  drops below 3:1 (WCAG 2.2 AA, SC 1.4.3 / 1.4.11). Add a pair there whenever a new
  foreground/background combination ships.
- `web/tests/a11y-structure.test.ts` checks the skip link is the first element in
  `<body>`, every page has exactly one `<main id="main-content" tabIndex={-1}>`, the
  sr-only file input draws its focus ring on the dropzone, and ink panels switch the
  focus ring to white.

Contrast fixes made when the palette was first measured (issue #25):

| Pair | Before | After |
| --- | --- | --- |
| Landing `--quiet` text on white | `#94a3b8` 2.56:1 | `#64748b` 4.76:1 |
| Landing primary button, white on `--accent` | `#3b82f6` 3.68:1 | `#2563eb` 5.17:1 |
| LINE link button text on `#06c755` | white 2.26:1 | `--ink` 6.68:1 |
| Text-field border on white | `--border` 1.47:1 | `--field-border` 3.56:1 |
| Focus ring inside the ink sidebar | `--interactive` 2.17:1 | white 15.06:1 |

Not yet gated or not yet done — R11 is **not** fully verified:

- The browser axe scan is manual. It was last run with axe-core against a local
  production build on seven of the eight routes (`/`, `/sign-in`, `/cases`,
  `/cases/[caseId]`, `/review`, `/sources`, `/admin`) with WCAG 2.0/2.1/2.2 A+AA tags:
  0 violations. `/link/line` redirects without a valid LINE token and was not scanned;
  its only new color pair is covered by the contrast test. Putting axe in CI needs a
  browser dependency in `web/package.json` and is tracked in issue #25.
- No screen-reader walkthrough (NVDA/VoiceOver) and no real-device mobile check has
  been recorded.

## Backup, retention, and incident response

1. Back up the encrypted `.runtime/secure-web.sqlite` and sanitized artifacts only to an
   approved encrypted target. Quarantine backups are disabled by default.
2. Use per-case deletion in the UI; verify raw and sanitized object paths no longer exist.
3. On suspected credential exposure, stop both services, revoke Google/LINE credentials,
   disconnect Codex, rotate `BETTER_AUTH_SECRET`, and invalidate all sessions.
4. Never attach `.runtime`, logs, customer files, or auth state to an issue.

## Production cloud gate

`APP_MODE=production` deliberately refuses SQLite, local storage, local auth, and Codex
CLI. Cloud SQL, GCS, Cloud Tasks, and an approved service model credential remain a
separate deployment decision; this single-user runbook does not claim that gate passed.
