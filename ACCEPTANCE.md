# ACCEPTANCE — Secure Web

Date: 2026-07-10 / Runtime: local + single-user self-host / Status: local accepted; external credentials pending

## 1. Live environment snapshot

| Service | Address | Required state |
| --- | --- | --- |
| Next.js web | `http://127.0.0.1:3000` | healthy, loopback local auth |
| Python worker | invoked by local job adapter | importable and redacted |
| Local database | private workspace runtime path | schema current |
| Local quarantine | private workspace runtime path | not web-served |
| Codex CLI | local subprocess | ChatGPT login, isolated/read-only/ephemeral |

Production services are not marked accepted without live Google, LINE, and GCP
credentials and deployment evidence.

## 2. Success criteria

| Source | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| Issue #8 | Next.js/TypeScript Secure Web | Passed local | build + desktop/mobile browser smoke |
| Issue #8 | Google/LINE identity boundary | Protocol passed; live pending | Better Auth + LINE nonce/signature/replay tests |
| Issue #8 | Direct quarantine upload | Passed post-hardening | `npm run acceptance:upload` |
| Issue #8 | Python masking/domain worker | Passed local | worker integration + full Python suite |
| Issue #8 | Cases/HITL/results/audit/deletion | Passed post-hardening | full synthetic E2E |
| Issue #8 | No raw content in model/log/channel | Passed post-hardening | provider spy + canary leaks = 0 |
| ADR-0002 | Local Codex provider | Passed live synthetic | structured Codex ChatGPT-auth output |
| ADR-0002 | Cloud production fail-closed configuration | Passed negative | runtime config tests |

## 3. Scenario results

Run `python3 scripts/acceptance.py`. With web and worker already running, use
`python3 scripts/acceptance.py --live --codex` for the full local gate.

Observed post-hardening local E2E:

```json
{"signIn":"passed","caseAuthorization":"passed","directWorkerUpload":"passed","finalState":"sanitized","rawCanaryLeaks":0,"modelStatus":"completed","hitlAnswers":1,"responseDraft":"passed","verifiedDeletion":"passed"}
```

The hardening patch is covered by 50 Python tests, 27 web tests, typecheck, lint,
production build, and the cross-process E2E above. CI runs the same E2E.

## 4. Working items and gaps

| Gap | Impact | Current state |
| --- | --- | --- |
| Public HTTPS domain | External callback cannot be accepted | External input absent |
| Google OIDC credentials | Live Google callback cannot be accepted | External input absent |
| LINE channel credentials | Live account link/webhook cannot be accepted | External input absent |
| PDF/image parsing | Unsafe native parser exposure | Disabled; UTF-8 TXT only until sandboxed |
| Cloud production | Not required for current one-user Codex-auth decision | Explicitly fail closed |

## 5. Early probes

- Codex CLI 0.142.5 is installed and reports ChatGPT login.
- Node 22 and Python 3.14 are available.
- Production credential absence is explicit and does not weaken local security policy.

## 6. Cost

The local pilot has no managed-service fixed cost. Cloud SQL dominates likely baseline
cost for a one-user production deployment and must be measured before enablement.

## 7. Production recommendations

1. Complete live Google and LINE protocol acceptance.
2. Provision private GCS quarantine/sanitized buckets and validate IAM.
3. Provision Cloud SQL backups/retention and verify restore.
4. Replace local Codex provider with an approved production service credential.
5. Verify data residency and retention contract across every external provider.
