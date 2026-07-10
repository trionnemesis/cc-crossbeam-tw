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
