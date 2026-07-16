# ADR-0002: Secure Web runtime, identity, and model provider

Status: Accepted
Date: 2026-07-10
Decision maker: repository owner
Delivery: GitHub issue #8

## Context

The next phase adds a browser application for at most about twenty concurrent users.
LINE or Slack is an entry channel, Google is the human identity provider, uploaded
documents can contain customer personal and project data, and the existing Python
`tw_law_mcp` must remain the legal/auditability source of truth.

The current pilot has one user. The local Codex CLI is already authenticated through
ChatGPT, while no `OPENAI_API_KEY`, Google, LINE, or GCP production credentials are
available in this repository.

## Decision criteria

| Criterion | Next.js + adapters | React Router + adapters | Vite + Fastify |
| --- | --- | --- | --- |
| One web UI/BFF artifact | Yes | Yes | No; separate UI/API |
| Google/LINE callback integration | Direct route handlers | Direct loaders/actions | Explicit API routes |
| Low-traffic operations | Good | Good | More deployables |
| Explicit cache/security controls | Requires discipline | Requires discipline | Most explicit |
| Team implementation path | Selected issue plan | Viable alternative | Largest initial surface |

## Decision

Use Next.js App Router with TypeScript for the UI/BFF and ports/adapters for identity,
database, storage, jobs, and model execution. Use PostgreSQL/GCS/Cloud Tasks in
production and bounded local adapters for repeatable single-user acceptance.

The application user ID is canonical. Google `sub` and LINE/Slack identifiers are
external identities mapped to the same user. Email is never the primary key.

Raw uploads go directly to private quarantine. A signed upload capability is not a
quarantine decision. Only a worker can scan, validate, mask, and promote an object;
downstream analysis can read only sanitized artifacts.

For the single-user deployment, the model port may invoke the already authenticated
Codex CLI in an isolated, read-only, ephemeral execution. Codex auth is not exposed to
the browser and is not used as website OAuth. The public single-user host terminates
HTTPS at a reverse proxy, authenticates the owner through Google, routes direct uploads
to a loopback worker, and stores data on an encrypted private volume. Cloud production
mode rejects this adapter and requires an approved service credential/provider.

FastMCP remains deferred until a real remote tool consumer requires discovery,
Streamable HTTP, auth, or concurrency beyond the in-process Python worker boundary.

## Why not React Router

React Router Framework mode is a strong alternative and can also provide a full-stack
BFF. If a proof of concept shows materially less auth/deployment glue for this team,
the framework decision may flip. It is not selected now because the accepted issue
already specifies Next.js and its route-handler ecosystem fits the planned callback
and upload-intent surface.

## Why not Vite + Fastify

The strongest case for Vite + Fastify is explicit server lifecycle control, independent
API deployment, and large streaming upload handling. Those advantages become decisive
if the web server must perform inline AV/DLP, resumable uploads, or separate API audits.
For the current direct-to-storage, low-concurrency workflow, the additional deployable
and duplicated auth/API contracts are not justified.

## Consequences and mitigations

| Risk | Mitigation |
| --- | --- |
| Next.js caching exposes user data | Dynamic protected routes, `no-store`, authorization in DAL |
| LINE account takeover/replay | Raw signature verification, TTL, single-use nonce, unlink/re-link policy |
| Signed URL reused | Short TTL, create-only key, expected checksum/size, state consumption |
| Masked data remains identifiable | Data minimization, canary tests, high-risk human-only path |
| Codex prompt injection | Sanitized text only, empty cwd, read-only sandbox, no project rules/tools |
| Local provider copied to cloud | Cloud production config validator rejects Codex CLI/local adapters |
| Single-user host is publicly reachable | HTTPS proxy, Google owner allowlist, worker loopback bind, direct route capability |
| Cloud SQL cost dominates pilot | Local database for pilot; measure before enabling managed instance |

## If verifier evidence flips

Open risks that do not flip the decision: exact managed-service cost, UI polish, and
whether LINE or Slack is the first channel adapter.

Evidence that flips the decision: React Router materially reduces measured deployment
and auth glue; requirements add large streaming/inline scanning; organization policy
requires a managed IdP or forbids GCS/external model processing; or Codex terms/docs
disallow the local programmatic workflow. In those cases the relevant adapter or web
framework must change before production rollout.
