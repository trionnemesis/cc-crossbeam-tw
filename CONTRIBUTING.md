# Contributing to cc-crossbeam-tw

Thank you for taking the time to improve this project. Contributions should make
the Taiwan interior-renovation document workflow easier to inspect, reproduce,
and audit without weakening its privacy or professional-boundary constraints.

## Scope

Good contributions are focused changes to one of these areas:

- `tw_law_mcp/`: source-bound domain tools and local evidence handling;
- `tests/`, `fixtures/`, and `scripts/`: reproducible verification; or
- `docs/` and `README.md`: public documentation that matches repository evidence.

Please open an issue first for changes that would alter the legal/auditability
boundary, introduce a new external provider, or change the production deployment
model.

## Local setup

The root Python project has no third-party dependency installation step. Use
Python `>=3.10,<4.0` and run the standalone stdio entrypoint when you need to
exercise the MCP boundary locally.

```bash
python3 scripts/tw_law_mcp_stdio.py
```

This starts a long-running MCP process that waits for JSON-RPC input; stop it
with `Ctrl-C` after local verification.

## Verification

Run the focused checks relevant to your change. For the current mainline baseline:

```bash
python3 -m unittest discover -s tests
python3 scripts/run_phase_acceptance.py
git diff --check HEAD
```

`run_phase_acceptance.py` currently exits non-zero and reports `all_passed=false`
for the unsupported synthetic G2 baseline. This is the expected fail-closed
baseline; inspect its JSON output and report that limitation. Do not turn a
synthetic fixture result into a real-case or production claim. For focused work,
also run the relevant acceptance script under `scripts/`, such as
`run_scenario_matrix_acceptance.py` or `run_source_policy_acceptance.py`.

## Privacy and security rules

- Never commit secrets, `.env` files, tokens, private keys, customer documents,
  raw drawings, raw PDFs, or unmasked personal data.
- Do not paste raw customer content into issues, pull requests, logs, test output,
  or model prompts. Use the existing de-identified fixtures or metadata-only
  examples.
- Do not bypass the metadata-only and source-bound input contracts of
  `tw_law_mcp`.
- Keep synthetic and de-identified fixtures separate from any future approved
  real-case corpus.
- Keep uncertain, unsupported, or professional-judgment cases fail closed and
  require human confirmation.
- Use GitHub private vulnerability reporting when it is enabled, or contact the
  repository owner through a private channel. Never publish exploit data in a
  public issue.

## Documentation changes

When changing behavior, update the relevant README, ADR, feature matrix, or
acceptance evidence in the same change. Documentation must
describe the current repository state; do not add badges, versions, releases, or
production claims that are not supported by tracked files or verification output.

This repository currently has no committed license file. Do not add a license
badge or assume reuse rights until the project owner makes an explicit licensing
decision.

## Pull requests

Keep each pull request focused and use a Conventional Commit style title, for
example:

```text
docs: clarify contribution boundaries
fix(stdio): preserve recovery after malformed input
feat(workflow): add a verified correction packet path
```

The pull request description should include:

- the user-visible or operator-visible outcome;
- files and behavior changed;
- commands actually run and their results;
- known gaps or external gates that were not run; and
- any data-boundary, source-authority, or professional-review implications.

Before requesting review, confirm:

- [ ] the change is scoped to the stated objective;
- [ ] tests or documentation checks cover the changed behavior;
- [ ] no secrets or raw customer data are present in the diff;
- [ ] fail-closed and human-in-the-loop behavior remains intact;
- [ ] public documentation matches the current implementation;
- [ ] documented commands and links were rechecked against tracked files.
