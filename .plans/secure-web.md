# Secure Web implementation plan

## Status

Active. Lane L2 feature with L5 long-task overlay.

## Problem Statement

The repository has a deterministic Taiwan law and auditability core, but no secure
browser application. The next phase must provide a single-user Secure Web that can
be entered from LINE or Slack, authenticates the human independently from the AI
provider, quarantines raw uploads, processes only masked text through the existing
Python boundary, and presents case, HITL, evidence, audit, retention, and deletion
workflows.

## Success Criteria

1. The browser application implements the case workflow described by issue #8.
2. Google OIDC and channel identities map to one canonical application user.
3. Raw file bytes bypass the Next.js request body and enter private quarantine.
4. Unscanned objects cannot be read by downstream analysis.
5. The model provider receives only the minimum masked text and emits structured output.
6. The existing `tw_law_mcp` remains the domain source of truth.
7. Local single-user mode is fully repeatable without an OpenAI API key by using the
   already authenticated Codex CLI in an isolated, read-only, ephemeral process.
8. The single-user deployment supports Google OIDC, LINE account linking, private host
   storage, HTTPS reverse proxy, and local Codex auth. Cloud production adapters remain
   explicit and fail closed when absent.

## Options

### Option A: Cloud-only implementation first

- Matches the final Cloud Run / Cloud SQL / GCS topology immediately.
- Requires Google, LINE, GCP, and model credentials before any end-to-end validation.
- Prevents a deterministic local acceptance run in the current environment.

### Option B: Ports-and-adapters implementation with a complete local mode

- Implements the final contracts once, with local filesystem/database/task adapters
  for acceptance and production adapters selected by configuration.
- Allows the one current user to run the complete workflow using existing Codex auth.
- Keeps raw data on the local machine during the pilot.

**Recommendation: Option B** — it provides a real end-to-end single-user system now
without embedding credentials or weakening the production boundary. Production
adapters are not silently emulated; missing production configuration fails closed.

## Configuration Precedence

1. Process environment credentials and deployment secrets.
2. Non-secret values in `web/config/defaults.ts`.
3. Test-only dependency injection passed directly to service constructors.

No credential may be committed. `.env.local` is ignored and optional.

## Implementation Plan

### Phase 0: Governance and executable contracts

**Files:** `.plans/secure-web.md`, `docs/ADR-0002-secure-web.md`,
`ARCHITECTURE.md`, `TASK-STATE.md`, `ACCEPTANCE.md`

#### 0a. Persist the selected architecture and trust boundaries (~220 lines)

- Record identity, channel, storage, worker, and model-provider boundaries.
- Map every issue #8 requirement to a component and acceptance check.
- Preserve the independent verifier corrections: application `user.id` is canonical;
  a signed upload is not equivalent to quarantine.

#### 0b. Create a machine-readable acceptance entrypoint (~120 lines)

- Print observable service health, configuration modes, storage boundaries, and
  scenario results.
- Exit non-zero when any required local acceptance scenario fails.

**Tests for Phase 0:**

- Architecture requirement/component orphan check passes.
- Acceptance script reports missing application until Phase 1 rather than silently passing.

### Phase 1: Application shell, identity, and authorization

**Files:** `web/package.json`, `web/app/**`, `web/src/auth/**`, `web/src/db/**`,
`web/src/config/**`, `web/tests/auth*.test.ts`

#### 1a. Scaffold a pinned Next.js TypeScript application (~260 lines)

- App Router, strict TypeScript, ESLint, Vitest, Tailwind tokens, and accessible shell.
- Public sign-in page; protected Cases, Review, Sources, and Admin navigation.

#### 1b. Implement canonical identity and single-user authorization (~300 lines)

- `user.id` is canonical.
- Google `sub` is stored as `(provider_id, account_id)` unique external identity.
- LINE/Slack identities map through `channel_identity`.
- Invite allowlist and case membership are enforced in the data-access layer.
- Local development auth is loopback-only and cannot be enabled in production.

#### 1c. Add Google and LINE protocol boundaries (~260 lines)

- Google OIDC callback state/nonce validation and exact redirect handling.
- LINE link-token/nonce lifecycle, raw-body signature verification, unlink, and replay rejection.
- External-browser redirect marker is included in LINE entry links.

**Tests for Phase 1:**

- Uninvited identity is rejected.
- Wrong tenant/case membership is rejected by the data layer.
- Expired, replayed, and consumed LINE nonce is rejected.
- Modified LINE webhook raw body fails signature verification.
- Production cannot start with local bypass auth enabled.

### Phase 2: Secure upload, quarantine, and processing

**Files:** `web/src/storage/**`, `web/src/uploads/**`, `web/src/jobs/**`,
`worker/**`, `web/tests/upload*.test.ts`, `tests/test_secure_worker.py`

#### 2a. Implement upload intent and direct upload (~320 lines)

- Server-generated opaque object key; no client filenames in storage paths.
- Case-scoped upload intent with short TTL, max size, expected media type, checksum,
  and create-only semantics.
- Local adapter accepts a stream directly into private quarantine; GCS adapter emits
  V4 signed upload details without proxying bytes through Next.js.

#### 2b. Implement quarantine state machine (~320 lines)

- `pending -> uploaded -> scanning -> rejected|clean -> masking -> sanitized`.
- Downstream open/read requires `sanitized` and case authorization.
- MIME sniff, size/checksum revalidation, retention, deletion, and audit events.
- Scanner interface fails closed if no production scanner is configured.

#### 2c. Implement Python masked-document worker (~360 lines)

- Reads only from quarantine worker boundary.
- Extracts text, detects/masks common Taiwan personal identifiers, writes sanitized
  artifacts, and invokes `tw_law_mcp` in process.
- Raw text and file content are never printed to stdout/stderr.

#### 2d. Implement isolated Codex CLI model provider (~220 lines)

- Accepts sanitized text only.
- Runs `codex exec --ephemeral --sandbox read-only --ignore-rules` in an isolated
  empty work directory with a JSON output schema.
- Uses timeout, output-size cap, cancellation, and fail-closed structured validation.
- Provider is local-only; production mode refuses Codex CLI auth.

**Tests for Phase 2:**

- Raw bytes never enter a Next.js route handler.
- Expired/wrong-case/oversize/checksum-mismatch uploads fail.
- Quarantine objects cannot be read before clean promotion.
- Taiwan ID, phone, email, and address canaries are absent from sanitized/model payloads.
- Worker logs do not contain raw canaries.
- Codex provider command has read-only, ephemeral, isolated flags and rejects raw input.

### Phase 3: Case, HITL, results, audit, and deletion UX

**Files:** `web/app/(secure)/**`, `web/src/components/**`, `web/src/cases/**`,
`web/src/hitl/**`, `web/src/audit/**`, `web/tests/workflow*.test.tsx`

#### 3a. Build the case workflow UI (~700 lines)

- Case list/detail, secure upload, processing stepper, masking summary, HITL review,
  result/evidence tabs, and audit timeline.
- Mobile navigation and exact post-login deep-link restoration.

#### 3b. Add HITL and result state transitions (~300 lines)

- Answers are case-scoped, versioned, audited, and re-run only affected analysis.
- Results always show source/gate state and required professional review.

#### 3c. Add retention and verified deletion (~220 lines)

- Admin can view policy, request deletion, and verify raw/sanitized/artifact deletion.
- Deletion event retains no raw content.

**Tests for Phase 3:**

- Keyboard-only primary workflow succeeds.
- Mobile routes expose Cases, Review, and Account without hidden-only navigation.
- HITL transition requires membership and records an audit event.
- Delete removes all object classes and leaves a content-free audit tombstone.

### Phase 4: Deployment and operational hardening

**Files:** `Dockerfile`, `worker/Dockerfile`, `deploy/**`, `docs/runbook-secure-web.md`,
`.github/workflows/secure-web.yml`

#### 4a. Add bounded production configuration (~280 lines)

- Cloud Run web/worker, Cloud SQL PostgreSQL, GCS buckets, Cloud Tasks, Secret Manager,
  and `asia-east1` defaults.
- Production startup verifies all required services and refuses local adapters.

#### 4b. Add security headers and operations (~180 lines)

- CSP, HSTS, frame denial, referrer policy, request/body limits, structured redacted
  logging, health/readiness, backup/retention checklist, and incident runbook.

**Tests for Phase 4:**

- Container build and local health check pass.
- Production config validator rejects missing secrets, public buckets, local auth,
  local storage, local DB, and Codex CLI provider.
- Security headers are present on public and protected pages.

### Phase 5: End-to-end acceptance and independent review

**Files:** `scripts/acceptance.py`, `ACCEPTANCE.md`, `research/VERIFIER-REPORT-secure-web.md`

#### 5a. Run real local E2E acceptance (~160 lines)

- Start the app and worker, create one invited user/case, upload a canary document,
  process/mask it, complete HITL, inspect evidence, and delete the case.

#### 5b. Run independent security/architecture/UI reviewers (~120 lines report)

- Resolve critical/major findings before completion.
- Record any external credential/deployment gates as unverified, never as passed.

**Tests for Phase 5:**

- Node unit/integration suites pass.
- Python suite passes.
- Typecheck, lint, and production build pass.
- Browser desktop/mobile acceptance passes.
- Raw canary leak scan returns zero matches outside the test fixture itself.

## Integration Issues & Edge Cases

1. Codex ChatGPT auth is a local Codex-client credential, not a third-party web login.
2. Google OAuth in LINE embedded browsers is prohibited; entry must open externally.
3. Signed URLs are bearer capabilities until expiration; application state also enforces
   one logical consumption and create-only object generation.
4. Storage location does not prove identity-provider or model-provider data residency.
5. Masking reduces exposure but does not guarantee anonymity; high-risk content stays
   out of the model path and requires human review.
6. Production completion requires externally supplied Google/LINE/GCP configuration;
   absence must be reported as an external deployment gate.

## Files Changed Summary

| File area | Phase | Changes |
| --- | --- | --- |
| Governance docs | 0 | Plan, ADR, architecture, acceptance, task state |
| `web/` | 1-4 | Next.js app, data/auth/storage/jobs/UI and tests |
| `worker/` | 2,4 | Python processing service and container |
| `deploy/` | 4 | Cloud Run/Cloud SQL/GCS/Tasks configuration |
| `scripts/acceptance.py` | 0,5 | Repeatable full-system acceptance |

**Estimated new code:** ~4,600 lines. **Estimated test code:** ~1,600 lines.

## Rollout Plan

1. Merge Phase 0-1 with local auth disabled by default; verify auth boundaries.
2. Merge Phase 2 with model provider disabled until sanitized payload tests pass.
3. Merge Phase 3 after accessibility and deletion tests pass.
4. Merge Phase 4 after production config fail-closed tests and container build pass.
5. Enable the local Codex provider only for the single-user local pilot.
6. Enable production providers only after external credential/deployment acceptance.

Each phase is independently mergeable and testable.
