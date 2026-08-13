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
