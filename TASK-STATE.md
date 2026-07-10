# TASK-STATE — Secure Web implementation through verified completion

Updated: 2026-07-10T14:05:00+08:00 / Progress: 5/6 milestones

## Goal

User objective: implement the next-phase Secure Web plan through complete delivery.

Success requires issue #8 behavior: Next.js UI, Google identity and LINE-first entry,
case authorization, raw-file quarantine, Python masking/domain processing, Codex local
provider for the single-user pilot, HITL/results/audit/deletion UX, production adapters,
and requirement-by-requirement acceptance evidence.

## Constraints

- Maximum expected concurrency is about twenty; optimize for auditability and low ops.
- Current pilot user count is one.
- Raw customer data must not enter LINE/Slack, Next.js request bodies, logs, or model prompts.
- `tw_law_mcp` remains the legal/auditability source of truth.
- Codex ChatGPT auth is local worker auth only, never website authentication.
- No secrets or `.env` values may be committed or printed.
- Missing external production credentials must fail closed and cannot be reported as verified.

## Completed

1. Framework/auth/privacy/UI decision recorded in GitHub issue #8; issue verified open.
2. Local capability check: Node 22.22.3, npm 10.9.8, Python 3.14.2, Docker 29.4.0,
   Codex CLI 0.142.5; `codex login status` reports `Logged in using ChatGPT`.
3. Branch created: `codex/secure-web` from clean `main@684bc1a`.
4. Phase plan and ADR persisted: `.plans/secure-web.md`, `docs/ADR-0002-secure-web.md`.
5. Phase 0 acceptance baseline: Python domain suite passed; Secure Web check failed before
   scaffold as intended (`web/package.json is not implemented yet`).
6. Phase 1 Next.js shell, runtime config, Better Auth local boundary, SQLite schema,
   canonical identity/membership DAL, sign-in, and cases UI implemented.
7. Phase 1 verification: Vitest 4 files / 9 tests passed; TypeScript and ESLint passed;
   Next.js 16.2.10 production build passed.
8. Browser smoke: local anonymous sign-in navigated to `/cases`, seeded one owner case,
   desktop navigation rendered, and 390x844 mobile navigation exposed four routes.
9. Secure upload implemented: metadata-only intent, browser-to-worker direct PUT,
   single-use capability, checksum/size/MIME checks, quarantine state machine, file modes,
   exact-origin CORS, and safe error mapping.
10. Python worker implemented: extraction, deterministic PII masking, existing legal-domain
    analysis, isolated ephemeral/read-only Codex provider, HITL response generation, and
    verified private-file deletion.
11. LINE account-link protocol implemented: signed raw-body webhook verification, expiring
    one-time token hash, nonce/state/replay rejection, canonical channel identity, and unlink.
12. Result, review, source, account, audit, correction, HITL, and deletion UI implemented
    with desktop and 390x844 mobile browser evidence.
13. Local acceptance passed: 50 Python tests, 27 web tests, TypeScript, ESLint, webpack
    production build, architecture R1-R12 orphan check, and Codex auth status.
14. Live synthetic Codex smoke produced schema-valid masked-only output. Full local HTTP E2E
    passed sign-in, authorization, direct upload, zero raw-canary leaks, HITL, response draft,
    and verified deletion.
15. Single-user operations documented with fail-closed runtime modes, loopback worker,
    HTTPS reverse proxy example, pinned CI actions, health checks, and incident runbook.
16. Four-position independent review completed. The critical DLP gap and actionable major
    findings were corrected: expanded Taiwan masking, provider-path spy, same-origin CSRF,
    same-origin upload endpoint, retryable HITL, zero-question completion, cross-user E2E,
    cross-process CI, dependency cleanup, and fail-closed TXT-only raw ingestion.
17. Route-level regressions cover HITL worker 503 then retry success and LINE webhook raw
    signature, body-size, Messaging API entry flow, and bounded upstream failure.
18. Post-hardening cross-process E2E passed sign-in, real second-user authorization denial,
    direct worker upload, zero canary leaks, live Codex result, HITL, response draft, and
    verified private-file deletion.
19. GitHub issue #8 updated with the selected Codex-auth worker boundary, implementation,
    remediation verdict, acceptance evidence, and remaining external gates.

## Active State

- cwd: `/Users/warden/Documents/cc-crossbeam-tw`
- branch: `codex/secure-web`
- changed files: governance docs, new `web/` application, Python worker, tests, and runbook
- test status: 7/7 local acceptance and post-hardening cross-process E2E green
- running processes: none
- current milestone: independent review and external single-user acceptance

## Next Step

Perform public HTTPS Google OIDC and LINE acceptance after credentials are supplied.

## Blocked

- Production Google OIDC client ID/secret not available.
- Production LINE channel secret/access token not available.
- GCP project, Cloud SQL, GCS, Cloud Tasks, and deploy authority are not required for the
  selected one-user self-host target; cloud production remains a documented future mode.
- External credentials do not block local completion; public single-user acceptance remains gated.

## Key Decisions

- Next.js App Router is the accepted web/BFF framework; React Router is the runner-up.
- Application `user.id` is canonical; Google `sub` and channel IDs are external mappings.
- Signed upload is only a capability; scan/mask/promotion state defines quarantine release.
- Pilot ingestion is UTF-8 TXT only; PDF/image parsing requires a separate sandboxed worker.
- Local pilot uses bounded local adapters and existing Codex ChatGPT auth.
- Production rejects local auth/storage/database/task/model adapters.
- FastMCP is deferred until a real remote consumer exists.

## Relevant Files

- `.plans/secure-web.md:1` — phased implementation and test contract.
- `docs/ADR-0002-secure-web.md:1` — selected architecture and flip conditions.
- `docs/ADR-0001-packaging-strategy.md:28` — standalone Python domain boundary.
- `docs/cc-crossbeam-feature-matrix.md:44` — existing app workflow mapping.
- `tw_law_mcp/repository.py` — domain source of truth.

## Historical (STALE — unless the user explicitly asks again, do not execute)

- The previous TASK-STATE tracked groups 1-6 / Phase 2.1-2.6 and was completed on
  `main`; its evidence remains in git history and README.
- The API-key setup blocker is superseded by the explicit local Codex-auth provider
  decision. Do not reopen API-key provisioning unless production provider selection changes.
