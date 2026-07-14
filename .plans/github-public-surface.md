# GitHub Public Surface

## Overview

Improve the repository-facing public surface identified by the GitHub profile audit: make the README understandable to an English-first visitor, expose the existing Pages and project-documentation entry points, and document how contributors can work inside the project's privacy and fail-closed boundaries. This phase targets the current `main` baseline, changes documentation only, and does not advertise the separate Secure Web branch before it is merged.

## Design Principles

1. **Evidence-first** — only advertise workflows, commands, versions, and links that exist in the current repository.
2. **English-first entry** — provide a concise English summary at the top while preserving the existing Traditional Chinese domain explanation.
3. **Boundary-preserving** — keep the source-bound, metadata-only, human-in-the-loop, and fail-closed constraints visible.
4. **No legal inference** — do not add a `LICENSE` file or license badge without an explicit licensing decision.

## Architecture

```text
README.md
  ├── English-first project summary
  ├── existing Pages / ADR / feature-matrix links
  └── existing Traditional Chinese product and safety detail

CONTRIBUTING.md
  ├── local setup and verification commands
  ├── contribution scope and PR checklist
  └── privacy / secret-handling rules
```

Option A: update only the README with a public summary and links.

- Smallest diff.
- Does not explain contribution expectations or safe handling rules to collaborators.

Option B: update the README and add a focused contribution guide.

- Makes the public entry point and the contributor workflow consistent.
- Keeps runtime and legal scope unchanged.

**Recommendation: Option B** — it directly addresses the audit's documentation and trust-signal gaps while remaining a documentation-only change that can be verified from the repository.

## Configuration

No runtime configuration changes. The README may link to the existing GitHub Pages source and tracked project documents; it must not claim a CI workflow or license that is not present on the current `main` baseline.

## Implementation Plan

### Phase 1: Public README entry point

**File: README.md**

#### 1a. Add English-first project summary (~25 lines)

Add a concise project description, technology/status badges, and direct links to GitHub Pages, the packaging ADR, and feature matrices. Preserve the current Chinese product description and safety boundary sections below the new entry point.

#### 1b. Align public commands and claims (~5 lines)

Keep the existing Python, stdio, and acceptance commands grounded in the repository's actual scripts and preserve the explicit G2 synthetic-fixture limitation.

**Tests for Phase 1:**

- Every new README link resolves to a tracked repository path or the repository's public Pages URL.
- Every badge refers to a stable technology or explicitly stated project status.
- README retains the current fail-closed and professional-boundary statements.

### Phase 2: Contributor guidance

**File: CONTRIBUTING.md**

#### 2a. Document setup and verification (~35 lines)

Document the Python setup and verification commands using the existing scripts and package metadata.

#### 2b. Document contribution and privacy boundaries (~35 lines)

Define focused changes, test evidence, Conventional Commit examples, no-secret rules, metadata-only/raw-data boundaries, and the PR checklist.

**Tests for Phase 2:**

- Every command in the guide maps to an existing script or package command.
- The guide does not request credentials or raw customer documents.
- The PR checklist requires tests and boundary review.

## Integration Issues & Edge Cases

1. The repository has no license file: omit license claims and defer the legal decision.
2. The current `main` baseline has no committed CI workflow: do not add a CI badge for the separate Secure Web branch.
3. The Pages site is static under `docs/`: link to the public site and the tracked source without implying a production deployment.
4. The Secure Web branch remains a separate delivery and is intentionally not described as merged functionality here.

## Files Changed Summary

| File | Phase | Changes |
|---|---:|---|
| `.plans/github-public-surface.md` | Plan | Scope, evidence rules, implementation phases, and rollout |
| `README.md` | 1 | English-first public summary, verified badges, and project links |
| `CONTRIBUTING.md` | 2 | Setup, verification, contribution, and privacy guidance |

**Total new code**: 0 lines / **Total test code**: 0 lines

## Rollout Plan

1. Review the README and contribution guide for claims that are not supported by tracked files.
2. Run repository documentation checks plus the existing targeted test suites.
3. Commit as one documentation-focused change; no runtime deployment or account-level GitHub mutation is included.

The two documentation phases will be delivered in one focused commit; each phase has independent verification checks.
