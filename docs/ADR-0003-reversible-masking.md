# ADR-0003: Reversible TXT masking core (`cb.mask.v1`)

Status: Accepted (PR A scope)
Date: 2026-10-04
Decision maker: repository owner
Delivery: GitHub issue #28 (PR A of four slices; the issue stays open for PR B/C/D)

## Context

Issue #28 asks for the next phase of the secure upload flow: detect and mask sensitive
text in a trusted environment, let the existing legal/correction analysis see only the
masked content, and afterwards let controlled code put the original values back, by
the original encoding and position, for an authorized person. This is reversible
pseudonymization with controlled restoration. It is not irreversible anonymization and
it does not promise zero personal data.

What exists on `main@4aabfe9` cannot do that safely:

- `masking.mask_sensitive_text` replaces each match with `[MASKED_<CLASS>]`. The result
  has only `text` and `counts`: no original value, no position, no per-occurrence
  identity, no version. Two different people become the same marker, and nothing can
  be restored. A document that carries only legacy markers must stay unrestorable.
- Patterns run one after another over the already-replaced string, so there is no single
  coordinate system for original offsets. Several patterns also include the field label
  in the match (`申請人：王大明`), so the label disappears with the value.
- Text is read with newline translation (`Path.read_text`), which is not a byte-exact
  baseline for restoration.

PR A delivers only the pure, in-memory core that makes restoration provable: a manifest
created by one immutable masking run, unique per-occurrence tokens, conflict handling,
a byte-exact round trip, and negative tests. It adds a separate opt-in module. The
legacy API, `process_upload`, the HTTP worker, the MCP server and the web app are not
changed.

## Decision

Add `worker/secure_worker/reversible_masking.py` (standard library only, Python 3.10 to
3.14). It exposes `mask_document`, `check_release_text`, `restore_original` (Mode A) and
`InMemoryManifestRegistry`, plus the safe and private record types in the next section.
It is not exported from `worker/secure_worker/__init__.py` and no production module
imports it.

Design rules that every later PR inherits:

1. Detection reuses `masking.PATTERNS` and the same `NON_NAME_TERMS` filter. Its
   candidates cover everything `mask_sensitive_text` replaces: every pattern over the
   decoded original, plus an exact replay of the legacy sequential masker whose matches
   are mapped back to the original. Every recorded position is a position in the original
   text.
2. Detection proposes; deterministic code decides. No model is involved.
3. The private mapping and the safe document are different types. The safe type has no
   field that can hold an original value, an original offset or the original digest.
4. A manifest is immutable and bound to case, document and version. Tokens are random
   per manifest and never derived from a value.
5. Restoration only puts registered bytes at registered spans. Unknown, missing,
   duplicated, swapped, out-of-range, overlapping or digest-mismatched input is refused
   in full. There is no fuzzy matching and no global `str.replace`.
6. Refusals carry a stable code and nothing else. No raw value in `repr`, `str`,
   `args`, traceback text, exception chain, log record or the safe document.

Illustration (the namespace is random per manifest):

```text
申請人：王大明   ->  申請人：[[CB1:PERSON:<28 lowercase letters>:000001]]
```

## Data contract

### Safe versus private

| Type | Holds | Never holds |
| --- | --- | --- |
| `SafeMaskedDocument` | `schema_version`, `manifest_id`, `binding`, `masked_text`, `masked_sha256`, `mask_counts`, `occurrence_count`, `parser_version`, `policy_version`, `detector_version`, `status="masked"` | original values, original offsets, `original_sha256`, token-to-value pairs |
| `PrivateManifest` | `schema_version`, `manifest_id` (uuid4), `binding`, `token_namespace`, `original_sha256`, `masked_sha256`, the three versions, `encoding="utf-8"`, `bom`, `newline_policy="preserve"`, `restore_policy`, `retention_deadline`, `key_id` (always `None` in PR A), `occurrences` | nothing is hidden inside; it is the private boundary object |
| `Occurrence` | `occurrence_id`, `token`, `entity_id`, `entity_type`, `detector_class`, `segment_id="body"`, original and masked byte offsets, `original_value: PrivateBytes` | |
| `PrivateBytes` | the exact original bytes of one occurrence | a readable `repr`, `str`, iteration, indexing, pickling |

- `DocumentBinding(case_id, document_id, document_version)`: each field must
  `fullmatch` `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` and be a `str`, otherwise
  `INVALID_BINDING`. `fullmatch` matters: `$` would accept a trailing newline. The rule
  keeps free text, and therefore personal data, out of opaque identifiers.
- `mask_counts` has one entry per `PATTERNS` class name, in `PATTERNS` order, including
  zeros. It counts emitted tokens by detector class after span resolution and is a
  read-only mapping. Its sum equals `occurrence_count`.
- `SafeMaskedDocument.outbound_payload()` is the simulated model allowlist: a fresh plain
  dict with exactly `schema_version`, `masked_text`, `mask_counts` (a plain dict copy).
  It carries no binding, manifest id, digest or offset.
- `PrivateBytes(data)` copies a bytes-like argument (`bytes`, `bytearray`, `memoryview`)
  into immutable `bytes` and rejects anything else with `TypeError`. `reveal()` returns
  those `bytes`; `len()` is the byte length. `repr` and `str` are fully redacted, without
  even the length, which in a log line already narrows down a short value. `bytes()`,
  `iter()` and indexing raise `TypeError`.
  `__reduce__` raises `TypeError`, which blocks `pickle` and `copy.copy` of the object
  itself, and `pickle`, `copy.deepcopy` and `dataclasses.asdict` of any record that
  contains one.
- `PrivateManifest` and `Occurrence` have a redacted `repr`/`str`: the manifest shows only
  its id, schema version and occurrence count, an occurrence only its id and entity type;
  neither shows digests, namespace, tokens, offsets or values. `PrivateManifest.__reduce__`
  raises `TypeError`. Both stay frozen dataclasses so that `dataclasses.replace` works for
  tamper tests.
- `occurrence_id` and `entity_id` are opaque ids (same character rule as binding ids),
  random, unique across manifests with overwhelming probability, never derived from a
  value. `entity_id` is unique per occurrence in PR A: the same literal does not mean
  the same entity, and linking occurrences needs explicit evidence in a later PR.
  `manifest_id` is `str(uuid.uuid4())`.
- `retention_deadline` is `None` or a finite, non-`bool` real number on the registry
  clock's scale (`INVALID_RETENTION_DEADLINE` otherwise). A `NaN` deadline would never
  expire, which is a fail-open retention rule.
- `restore_policy` is `"original_in_place"` or `"masked_only"`. `mask_document` has no
  parameter for it and creates `"original_in_place"`, because Mode A needs it and PR A
  has no product flow. Anything else, including an unknown value, is not restorable.
  PR B decides policy from the privacy-release state; until then `masked_only` is
  reachable only by `dataclasses.replace`.
- `PARSER_VERSION = "txt-utf8-strict/1"`. `DETECTOR_VERSION = "det-" + 16 hex` is derived
  at import from the ordered `(name, pattern, flags)` of `PATTERNS` and the sorted
  `NON_NAME_TERMS`. `POLICY_VERSION = "pol-" + 16 hex` is derived the same way from the
  label rules, the entity map and `RESOLUTION_POLICY_ID`. `derive_detector_version` and
  `derive_policy_version` are public so a change can be proven without editing
  `PATTERNS`. The result must not depend on `PYTHONHASHSEED`. A manifest records the
  versions it was made with; restore does not compare them with the current constants,
  because they are provenance, not a compatibility switch. Limits (`MAX_DOCUMENT_BYTES`,
  `MAX_OCCURRENCES` and the candidate factor `_CANDIDATES_PER_OCCURRENCE`) and the
  version constants are read from the module at call time.

### Byte offsets, BOM and newlines

- All offsets are UTF-8 byte offsets of the original byte string, 0-based and
  end-exclusive (`original[start:end]` is the occurrence). Code-point indices and UTF-16
  units are never stored or mixed in. For `備註😀 𠀋 申請人：王大明`, the name value
  starts at code point 10, UTF-16 unit 12 and byte 28; only 28 is correct.
- Detection runs on the decoded string (code-point indices); each boundary is converted
  to a byte offset in one linear pass, with no per-span re-encoding of a prefix.
- The input is decoded with strict `utf-8` (not `utf-8-sig`). A leading BOM stays as
  U+FEFF in both texts, offsets include its three bytes, and `bom` records it. Encoded
  surrogates, overlong forms and truncated sequences are `INVALID_UTF8`.
- No newline translation and no normalization: `\r\n`, lone `\r`, `\n`, mixed endings,
  trailing whitespace and a missing final newline pass through byte for byte outside
  the masked spans. `newline_policy` is always `"preserve"`.
- The empty document and a document with no personal data are valid. They produce zero
  occurrences, a masked text equal to the original, and an exact round trip.

## Token grammar

```text
[[CB1:<TYPE>:<NS>:<SEQ>]]
\[\[CB1:([A-Z][A-Z_]{0,31}):([a-z]{28}):([0-9]{6})\]\]        (TOKEN_RE, str pattern)
```

- `<TYPE>` comes from a fixed map whose keys must equal the `PATTERNS` class names (a
  test enforces it): `name` and `personal_name` map to `PERSON`; `taiwan_id` to
  `NATIONAL_ID`; `tax_id` to `TAX_ID`; `passport_or_resident_id` to `IDENTITY_DOCUMENT`;
  `email` to `EMAIL`; `mobile` and `landline` to `PHONE`; `birth_date` to `BIRTH_DATE`;
  `parcel_id` to `PARCEL_ID`; `bank_or_case_id` to `ACCOUNT_OR_CASE_ID`; `address` to
  `ADDRESS`.
- `<NS>` is the per-manifest namespace: 28 characters drawn from `a` to `z` with
  `secrets.choice` (26^28 is about 2^131.6, above the 128-bit floor in the issue). It
  is never seeded from, or reproducible by, the `random` module, the document or the
  binding. The same document masked twice, or under two bindings, gets unrelated
  namespaces.
- `<SEQ>` is the 1-based ordinal in original-document order, six digits, unique per
  manifest. `MAX_OCCURRENCES = 50_000` is a resource bound (see "Limits and the
  candidate budget"); more is `TOO_MANY_OCCURRENCES`. The limit is also capped at the
  capacity of six digits (999 999), so raising the constant cannot produce a token that
  does not match the grammar.
- No part of a token, id or namespace is derived from a value: no value, no base64 or
  hex of it, no hash of it.
- Reserved prefix: if the original contains `[[CB`, compared case-insensitively
  (`[[cb1:` too), `mask_document` raises `RESERVED_TOKEN_COLLISION`. Version 1 refuses;
  there is no escaping, so a user-made token can never be mistaken for a system token
  and a pre-existing look-alike can never skip the scan.
- A token is exactly 44 + `len(TYPE)` ASCII bytes, so short values grow. Growth is
  bounded by the input limit and `MAX_OCCURRENCES`.

### Why the namespace is letters only

The release scan runs the independent `residual_pii` detector over the whole text and
skips nothing, so every token must be inert under both `masking.PATTERNS` and
`residual_pii.RESIDUAL_PATTERNS`. A hex namespace is not: digit runs inside it trip the
phone and identity-document patterns. In two seeded runs on `main@4aabfe9`, 597 and 640
of 20 000 random tokens with 32-hex namespaces were flagged (about 3 %), against 0 of
20 000 tokens with 28-letter namespaces. With hex, release scanning would fail at random
on valid output. The namespace is therefore letters only, the sequence is six digits
(too few for any digit-based pattern), and a property test asserts inertness for at
least 2 000 generated tokens covering every `<TYPE>`, alone and joined.

## Detection, label preservation and span resolution

### Candidates

Two sources feed the candidate list, so that the candidates are a superset of what
`mask_sensitive_text` replaces:

1. Every `PATTERNS` entry is run with `finditer` over the decoded original. A match of
   `personal_name` is dropped when it is in `NON_NAME_TERMS` (the same filter as the
   legacy masker, `masking._is_masked_class`).
2. A private replay of `mask_sensitive_text`: the patterns in `PATTERNS` order over a
   working text in which every earlier replacement stands as `[MASKED_<CLASS>]`, with the
   same filter and the same `finditer` semantics. The replay carries an alignment map
   from its working text back to the original: text that was never replaced maps one to
   one, and a placeholder maps to the whole original range of the match it replaced, so a
   match that touches a placeholder covers that placeholder's whole range, plus whatever
   original text the match also covers. It returns the original range and class of every
   replacement, and its final working text, which must equal
   `mask_sensitive_text(text).text` (a test compares the two on every corpus document,
   both repo fixtures and 400 seeded documents).

Why a second source: the legacy masker runs the patterns one after another, so a later
pattern can see a boundary that the original text lacks. The email pattern ends in
`(?![\w.-])`, and a Han character is a word character. In
`聯絡信箱 owner@example.com統一編號：12345678` the email therefore has no end over the
original alone, and the first source finds nothing. The legacy masker replaces the tax id
first; the `[` that takes its place is the boundary, and the email is masked. Without the
replay the core would have left the email in the clear, and `residual_pii`, which has the
same lookarounds, would not have blocked it.

Both sources yield ranges of the original. Each goes through the value-span step and the
resolution rules below, so a range proposed twice is one span, and a range of one source
that crosses a range of the other is a `SPAN_CONFLICT` like any other. The index of the
entry in `PATTERNS` is the priority of a class: a lower index wins.

Issue #28 rules out running the next regex over replaced text as the way to record
offsets. The replay does not do that. It is a detection view with an exact alignment map
back to the original, the kind issue section 4.A.1 allows, and never a source of offsets
by itself: the only positions that reach the manifest are code-point indices of the
original, taken from the ranges the map returns.

What is finally masked is decided by the next two steps. Nothing the legacy masker hides
may stay visible in front of a label, which is why the `address` label rule below accepts
only a known qualifier before the label word.

### Value span (label preservation)

Several patterns include a field label in `group(0)`. Only the value is masked; the
label bytes stay, so the document keeps the structure that the correction rules read.
A label rule is applied anchored at the start of the detector match
(`rule.match(text, start, end)`). If it matches and leaves a non-empty remainder, the
value starts after it. If it does not match, or would leave nothing, the whole match is
the value (over-masking, never under-masking).

| Detector class | Leading label that stays |
| --- | --- |
| `name` | `(?:申請人\|業主\|所有權人\|聯絡人\|姓名\|承辦人)\s*(?:為\|[:：])?\s*` |
| `tax_id` | `(?:營業人統編\|統一編號\|統編)\s*[:：]?\s*` |
| `passport_or_resident_id` | `(?:護照\|居留證)(?:號碼\|號)?\s*[:：]?\s*` |
| `birth_date` (ignore case) | `(?:出生年月日\|出生日期\|出生\|生日\|D\.?O\.?B\.?)\s*(?:為\|[:：])?\s*` |
| `parcel_id` | `(?:地號\|建號)\s*[:：]?\s*` |
| `bank_or_case_id` | `(?:銀行帳號\|帳戶號碼\|案件編號\|申請案號)\s*[:：]?\s*` |
| `address` | `(?:案件\|戶籍\|通訊\|聯絡\|施工\|工程\|建物\|基地\|本案)?(?:地址\|住址\|地點\|位置)\s*(?:為\|[:：])?\s*` |

Classes without a rule (`taiwan_id`, `email`, `mobile`, `landline`, `personal_name`) mask
the whole match.

After the label is removed, trailing whitespace (characters for which `str.isspace()` is
true, the same set as regex `\s`) is trimmed from the value span. This is not cosmetic:
the `birth_date` pattern ends in `\s*`, so `生日：1990/01/02\r\n` matches with the
line terminator inside the value, and the legacy masker swallows it. Masking that span
would join two lines in the safe document. The trimmed bytes stay outside the token.

The `address` rule accepts only a known qualifier (`案件`, `戶籍`, `通訊`, `聯絡`, `施工`,
`工程`, `建物`, `基地`, `本案`) or nothing in front of the label word. Any other Han text
there can be a name (`林志豪地址：新北市…`), which the legacy masker hides as part of the
address match; with no label recognised the whole match is the value, so the name is
masked with the address and the label is lost.

Known gap, kept on purpose: the label is only recognised at the start of the match.
`說明五：地址 新北市…` (a match that starts earlier than the label) masks the whole
match, including that earlier text. See Known limitations.

### Span resolution

Spans are compared as value spans, in code-point indices of the decoded text:

1. Identical spans from several classes: keep the class with the lowest `PATTERNS`
   index (`申請人：王大明` is `name`, not `personal_name`; `0912345678` is `mobile`, not
   `landline`; `護照號碼：A123456789` is `taiwan_id`, so `NATIONAL_ID`).
2. A span fully inside another is dropped; the outer span masks a superset. Containment
   beats priority: `x.a123456789@example.com` is one `EMAIL` token even though
   `taiwan_id` has a lower index. (The legacy masker leaks `x.` and `@example.com` here.)
3. Partial (crossing) overlap raises `SPAN_CONFLICT` for the whole document. Merging
   would invent a type, shrinking would mask less than a detector asked for, so the
   core fails closed and leaves the case to a human. Example: in `生日：1-02-12345678`
   `birth_date` covers `1-02-12` and `landline` covers `02-12345678`.
4. Adjacent spans (`end == next.start`) stay separate tokens:
   `證號A123456789王大明` is `NATIONAL_ID` followed by `PERSON`.

A span is never empty. The surviving spans are disjoint and ordered, and their order
defines `<SEQ>`. These four rules are identified as `span-resolution/1`
(`RESOLUTION_POLICY_ID`), one of the inputs of `POLICY_VERSION`.

### Limits and the candidate budget

`MAX_DOCUMENT_BYTES` is 25 MiB. `MAX_OCCURRENCES = 50_000` is a resource bound, not the
capacity of the token grammar: the six digits of `<SEQ>` stay the hard ceiling, so the
effective limit is `min(MAX_OCCURRENCES, 999_999)`.

The first implementation allowed 999 999 and enforced it only after both candidate
sources, the table of spans and the sort had been built in full. Measured, one
occurrence costs about 1.5 KB while a document is masked (a 5 MiB document with 212 547
occurrences peaked at 352 MiB), and a crowded document was refused late and dear: 10 MiB
of `王大明 ` (a million spans) after 19 s and 650 MiB, 24 MiB after 48 s and 1.6 GiB. A
bound that is only checked at the end bounds nothing, so each stage checks the part it
can see:

1. Candidate budget. The budget is `_CANDIDATES_PER_OCCURRENCE = 4` times the effective
   limit, 200 000 by default. A running count is kept while the candidates of the
   original are collected; the first one past the budget raises `TOO_MANY_OCCURRENCES`,
   before the replay starts and before any value span is cut.
2. Replay. It receives what is left of the budget as `limit` and counts its
   replacements; the one past it raises. Without a `limit` it behaves as before.
3. Sweep. `_resolve_spans` raises at the first kept span past the limit, before any byte
   offset, token or manifest entry exists. `mask_document` has no check of its own after
   the fact.

Both constants are read at call time, and every refusal is raised outside any `except`
block. A document may propose four candidates per allowed occurrence; real ones need
fewer (a name with its label, a phone number and an email are three spans and seven
candidates). When a document has more than one problem, the stage that is reached first
decides the code: a `SPAN_CONFLICT` behind the 50 001st span is never found.

With these checks the crowded documents above are refused in 3.6 s (peak RSS 62 MiB) and
8.2 s (87 MiB), and the 5 MiB one, now over the limit, in 0.4 s (55 MiB). A document of
49 998 occurrences (1.2 MiB) is still accepted, in 3.0 s at 102 MiB; one with 50 001 is
refused in 1.1 s. What a refusal still costs is the linear scan of the text by the
patterns that find nothing, and no memory beyond it.

### `mask_document` order

1. `original` is `bytes`, else `INVALID_INPUT_TYPE` (no `str`, `bytearray` or
   `memoryview`: a mutable buffer could change between check and use).
2. `binding` is a `DocumentBinding`, else `INVALID_BINDING`.
3. `retention_deadline` is valid, else `INVALID_RETENTION_DEADLINE`.
4. `len(original) <= MAX_DOCUMENT_BYTES` (25 MiB), else `DOCUMENT_TOO_LARGE`. This runs
   before decoding, so an oversized invalid input is reported as oversized.
5. Strict UTF-8 decode, else `INVALID_UTF8`.
6. Reserved prefix, else `RESERVED_TOKEN_COLLISION`.
7. Candidates, value spans and resolution (`SPAN_CONFLICT`). The occurrence limit is
   enforced inside, as early as the work allows: `TOO_MANY_OCCURRENCES` comes from the
   candidate budget, the replay or the sweep (see "Limits and the candidate budget"),
   and nothing is built from a document that crosses it.
8. Convert boundaries to byte offsets (one linear pass); assemble the masked bytes in one
   pass from original byte slices and tokens, recording masked offsets; compute both
   digests.
9. `check_release_text(masked_text, manifest)`. Failure is fail closed.
10. Return `(SafeMaskedDocument, PrivateManifest)`. Nothing partial is ever returned.

Every refusal is raised outside any `except` block, so `__cause__` and `__context__`
are `None`. This includes the re-raised `ResidualPiiBlocked`. A `UnicodeDecodeError`
keeps the whole raw input in `.object`; it must not become a context.

## Release scan

`check_release_text(text, manifest)` is the outbound and release rule (issue section 5:
"everything else is scanned too"). Only tokens issued by this manifest are accepted;
everything else is scanned.

The manifest is judged first, because the tokens come from it. A manifest that
`mask_document` could not have made (occurrences that are not a tuple of well-formed
`Occurrence`, a wrong schema or namespace, a token that does not match its sequence,
class or namespace, a duplicate) is `MANIFEST_INVALID` before any token of the text is
read, never a `TypeError`. These are the structure rules of Mode A step 6 that need no
masked artifact; the bom comparison and the masked ranges stay with restore.

1. Every occurrence of `[[CB`, case-insensitive, must start a full-grammar token
   (`TOKEN_RE` matched at that index). Otherwise `MALFORMED_TOKEN` (`[[CB1:` fragments,
   `[[cb1:` look-alikes, a broken namespace, non-ASCII digits, truncation).
2. Every full-grammar token must be exactly one of the manifest's tokens (namespace,
   type and sequence together). Otherwise `UNKNOWN_TOKEN` (a forged or other-manifest
   token, a valid namespace with a type or sequence nobody issued).
3. Then `residual_pii.find_residual_sensitive_classes(text)` runs over the full text,
   nothing skipped, and any hit raises `ResidualPiiBlocked` unchanged.

Category order is 1, then 2, then 3, evaluated over the whole text, not by position. A
valid token is not a free pass: personal data next to a token is still caught. The scan
is a membership check, not a completeness check: a summary may legitimately omit or
repeat tokens (completeness is Mode A restore's business). `mask_document` runs it on
the masked text, so personal data that only `residual_pii` recognises, such as
`證件 AB1234567 已附。`, blocks the document instead of being returned as masked.

## Mode A: restore algorithm

Mode A restores the original document in place from an unmodified masked artifact. It
does not turn a model-edited document into the original (that is Mode B's job).

`restore_original(masked, manifest, binding)`, in this order, stopping at the first
failure:

1. Argument types: `masked` is `bytes` (`INVALID_INPUT_TYPE`), `manifest` is a
   `PrivateManifest` (`MANIFEST_INVALID`), `binding` is a `DocumentBinding`
   (`INVALID_BINDING`).
2. `binding == manifest.binding`, all three fields, case-sensitive, no normalization,
   else `BINDING_MISMATCH`.
3. `manifest.restore_policy == "original_in_place"`, else `RESTORE_NOT_PERMITTED`
   (any other value, including `masked_only`, `None` or an unknown string).
4. `sha256(masked) == manifest.masked_sha256`, else `MASKED_DIGEST_MISMATCH`. Any edit to
   the masked artifact, including outside token spans, ends here.
5. Strict UTF-8 decode of `masked`, else `INVALID_UTF8`.
6. Manifest structure, else `MANIFEST_INVALID`. Python slicing never raises on a bad
   range, so every item is checked explicitly:
   - `schema_version` is `cb.mask.v1`; `encoding` is `utf-8`; `newline_policy` is
     `preserve`; `bom` is a `bool` equal to "masked bytes start with EF BB BF";
   - `token_namespace` is `[a-z]{28}`; `original_sha256` is 64 lowercase hex digits;
   - `occurrences` is a tuple of `Occurrence`; each `original_value` is a `PrivateBytes`
     and each offset is an `int` (not `bool`);
   - for the i-th occurrence (1-based): `detector_class` is known and
     `entity_type == ENTITY_TYPES[detector_class]`; the token is full-grammar with the
     same type, the manifest namespace and `SEQ == i`; `segment_id == "body"`;
     `occurrence_id`, `entity_id` and `token` are valid and unique in the manifest;
   - `len(value) > 0`, `original_end - original_start == len(value)` and
     `masked_end - masked_start == len(token)`;
   - occurrences are sorted and non-overlapping in both coordinate systems (each start
     is at or after the previous end);
   - offsets are mutually consistent:
     `masked_start_i == original_start_i + sum over j < i of (len(token_j) - len(value_j))`;
   - every masked range lies inside the masked bytes.
7. Token scan of the decoded masked text against the manifest, category order over the
   whole text: `MALFORMED_TOKEN`, `UNKNOWN_TOKEN`, `DUPLICATE_TOKEN` (a registered token
   appears more than once), `MISSING_TOKEN` (a registered token does not appear), and
   `TOKEN_POSITION_MISMATCH` (every token appears exactly once but at the wrong byte
   offset, for example two tokens swapped). Token format being legal is not enough: the
   complete set and every position must match.
8. Rebuild: copy the masked bytes between registered spans and write each
   `original_value` at its registered span. No `str.replace`, no regex substitution, no
   fuzzy match; a token outside a registered span cannot reach this step.
9. `sha256(result) == manifest.original_sha256`, else `RESTORE_DIGEST_MISMATCH`. This is
   the last line of defence, for example for two equal-length values swapped inside the
   manifest, which pass every structural check.
10. Return the bytes. Never earlier: nothing partial leaves on any failure.

Digests are compared by one function. Both sides must be a `str` of exactly 64 lowercase
hex digits, and only then are they compared with `hmac.compare_digest`. Anything else
(bytes, upper case, a lone surrogate, `None`) is simply not equal, and two equal malformed
values are not equal either. Nothing is encoded, so a digest in a tampered manifest
cannot raise.

Consequences worth pinning: a swapped pair of unequal-length values fails step 6
(`MANIFEST_INVALID`); a swapped pair of equal-length values or a replaced
`original_sha256` fails step 9; tampering with the masked bytes alone fails step 4, as
does a `masked_sha256` that is no well-formed digest; tampering plus a forged
`masked_sha256` reaches step 7 and gets the token-level code.

## Registry (RAM stand-in for the PR B vault)

`InMemoryManifestRegistry(*, clock=time.time)` is the trusted load path that issue
section 4.A.4 asks for: callers hold a `manifest_id`, never a manifest.

- Public methods are exactly `issue`, `restore_original` and `discard`. None returns a
  `PrivateManifest`. A `threading.Lock` makes them safe across threads (one process).
- `issue(original, binding, *, retention_deadline=None) -> SafeMaskedDocument`. The key
  is the binding triple. Same binding, same original digest and same versions returns
  the same safe document (same tokens): an idempotent retry of one immutable job. The
  same binding with different content, or under changed parser/detector/policy
  versions, is `VERSION_CONTENT_MISMATCH`: a version is immutable and reprocessing
  needs a new version. A retry does not extend retention: the first deadline stays. A
  failed `issue` (any refusal, including `ResidualPiiBlocked`) registers nothing, so
  the binding is not left half-used. The size limit is checked after the argument checks
  and before the original is hashed: an oversized document is `DOCUMENT_TOO_LARGE`
  whether or not the binding exists (never `VERSION_CONTENT_MISMATCH`), and it costs no
  hashing.
- `restore_original(masked, *, manifest_id, binding) -> bytes`. A manifest that is
  unknown, discarded or expired (`clock() >= retention_deadline`; it is purged on
  access) gives `LEGACY_MAPPING_UNAVAILABLE` when `masked` contains an exact legacy
  marker `[MASKED_<CLASS>]` for a `PATTERNS` class, and `MAPPING_UNAVAILABLE`
  otherwise. `manifest_id=None` is the legacy-artifact case. It never guesses from
  other content, never falls back to another manifest, and never reaches into the
  binding to look one up. Otherwise it runs Mode A.
- `discard(manifest_id)` is idempotent. After discard or expiry the binding is free
  again in PR A; whether a deleted version must stay terminal (a tombstone) is a PR B
  decision.

## Mode B (deferred to PR C, described only)

Analysis output is new content, so original byte offsets cannot be reused. Mode B will
use server-owned template slots. Each slot is fixed by `template_id` and
`template_version`, a `field_id`, a `source_occurrence_id` (an `occurrence_id` from the
manifest), an `expected_entity_type` and the `result_digest` of the validated result.
Only a field-to-source binding approved by a human can be rendered by the renderer. A
model may not choose a vault key or an output position.

Mode A requires the complete token set. Mode B checks only the exact set and types that
the approved fields need, because a summary may legitimately omit some originals. A
`PERSON` field must never be filled from a valid `ADDRESS` token that a model placed
there, so tests for Mode B must include known-valid tokens in the wrong slot. Free-text
summaries stay masked; no automatic de-pseudonymization of prose. PR A keeps what Mode B
needs (random per-occurrence ids, the entity type in the manifest and in the token,
`restore_policy`, an immutable manifest) and adds no Mode B code, constant or API.

## Error codes

`ReversibleMaskingError.code` is one of these; `str(err)` is the code and `err.args` is
`(code,)`. A test keeps this table and `ERROR_CODES` identical.

| Code | Raised when |
| --- | --- |
| `INVALID_INPUT_TYPE` | a document, masked artifact, text or registry argument has the wrong type |
| `DOCUMENT_TOO_LARGE` | `len(original) > MAX_DOCUMENT_BYTES` (`mask_document`, and `issue` before it hashes) |
| `INVALID_UTF8` | the document, or a masked artifact being restored, is not strict UTF-8 |
| `INVALID_BINDING` | a binding field fails the opaque-id rule, or the argument is not a `DocumentBinding` |
| `INVALID_RETENTION_DEADLINE` | the deadline is not `None` or a finite non-`bool` real number |
| `RESERVED_TOKEN_COLLISION` | the original contains `[[CB`, any case |
| `SPAN_CONFLICT` | two value spans partially overlap |
| `TOO_MANY_OCCURRENCES` | more candidates than the budget, or more spans than the limit (see "Limits and the candidate budget"); raised as soon as it is known |
| `MALFORMED_TOKEN` | a `[[CB` occurrence does not start a full-grammar token |
| `UNKNOWN_TOKEN` | a full-grammar token was not issued by this manifest |
| `DUPLICATE_TOKEN` | a registered token appears more than once (restore) |
| `MISSING_TOKEN` | a registered token does not appear (restore) |
| `TOKEN_POSITION_MISMATCH` | registered tokens appear once each but at other offsets (restore) |
| `BINDING_MISMATCH` | the supplied binding differs from the manifest binding |
| `RESTORE_NOT_PERMITTED` | the manifest restore policy is not `original_in_place` |
| `MASKED_DIGEST_MISMATCH` | the masked bytes do not match the manifest digest, or that digest is not a lowercase hex digest |
| `MANIFEST_INVALID` | the manifest fails the structure checks, or is not a manifest (`restore_original`; `check_release_text` for the checks that need no masked artifact) |
| `RESTORE_DIGEST_MISMATCH` | the rebuilt bytes do not match `original_sha256` |
| `VERSION_CONTENT_MISMATCH` | the registry already holds this binding with other content or versions |
| `MAPPING_UNAVAILABLE` | the registry has no live manifest for the id (unknown, discarded, expired) |
| `LEGACY_MAPPING_UNAVAILABLE` | the same, and the masked bytes carry a legacy `[MASKED_<CLASS>]` marker |

Residual personal data is reported with the existing `ResidualPiiBlocked`
(`RESIDUAL_PII_BLOCKED`, with the class list only), so existing handling of that code is
unchanged. It is intentionally not in this table or in `ERROR_CODES`.

## What PR A does not do

- No persistence. The mapping lives in process memory only; a restart makes every masked
  document unrestorable (`MAPPING_UNAVAILABLE`) by design. No plaintext sidecar, no
  encryption, no key (`key_id` is `None`).
- No HTTP endpoint, no MCP tool, no UI. In particular no agent-callable `reidentify`,
  `restore` or `unmask` tool: restoration is a human-authorized export operation, not a
  capability a model gains by seeing a token.
- No model call and no model-facing restore. `outbound_payload()` only simulates the
  allowlist that a later gateway enforces.
- Not wired into `process_upload`, `server.py` or `codex_provider.py`, and not exported
  from `worker/secure_worker/__init__.py`. The legacy `mask_sensitive_text` and the
  `[MASKED_<CLASS>]` flow stay the production path and are unchanged.
- UTF-8 TXT only. No PDF, image, DOCX, OCR, NER or new dependency. The pilot's
  "UTF-8 TXT only, PDF disabled" statements stay as they are.
- No privacy-review or release state, no capability tokens, no Mode B.
- No real or customer document. Every test input is synthetic.

## Follow-up gates

A later PR may claim a capability only when the evidence in its row exists.

| PR | Scope | Gate before it can claim the capability |
| --- | --- | --- |
| PR B | Protected persistence and privacy release | A reviewed AEAD vault adapter (no home-made crypto) with authenticated context bound to case, document, version and manifest; fail closed when key or config is missing; keys never in the repo, the web database, a prompt or a provider subprocess environment; a store separate from the web SQLite. A privacy-review state separate from the legal HITL, bound to the sanitized digest, the three versions, approver, purpose and time. A gate on the final serialized payload, not only `masked_text`. Evidence of the real filesystem, UID, environment, tool and egress boundary for the model path, otherwise that path stays off for real sensitive files. TTL, retry, deletion (tombstone semantics, verified deletion, backups). Registry rules above become vault rules. |
| PR C | Authorized restore/export and the TXT end-to-end flow | Mode B with server-owned slots; both restore modes; one-time short-lived capabilities bound to user, case, version, digest, purpose, expiry and nonce, redeemed atomically; raw bytes go worker to browser, not through Next.js; revocation, replay, cross-case and deletion negative tests; a zero-leak end-to-end run; a known-valid token in the wrong slot is still refused. |
| PR D | Isolated document adapters | A network-less, low-privilege parser sandbox with resource limits; real redaction of text layer and pixels; source geometry instead of TXT offsets; hostile and broken file rejection; unsupported layouts reported, not guessed. |

## Known limitations

- Detector recall is that of the legacy masker, not better. The core masks what
  `PATTERNS` finds, over the original and in the legacy masker's sequential run, and
  nothing else; "no hit" never means "safe to send". Identifiers written entirely in
  full-width characters (`Ａ１２３４５６７８９`, `０９１２－３４５－６７８`) are found by neither the masking nor
  the residual detector. A value that only contains full-width digits after an ASCII
  prefix (`A1２３４５６７８９`) is found, because `\d` accepts them, and is restored
  byte for byte: values are never normalized.
  An email whose local part contains a combining mark is masked only after the mark
  (`owne` + U+0301 + `r@example.com` leaves `owné` in the clear, and the residual scan
  then sees no email); one whose domain contains a combining mark is not found at all.
  There is no normalization view (issue section 4.A.1 allows deferring it); the only
  alignment map is the one of the legacy replay above. A later detection view must map
  back to original byte offsets.
- Unlabeled `personal_name` is a surname-list heuristic: it can mask ordinary words
  (`NON_NAME_TERMS` trims the common ones) and can miss a name.
- Over-masking is the failure mode by design: when no label rule matches at the start of
  a detector match, the whole match is masked, including any text before the label.
- An email directly next to Han text with no separator (`信箱owner@example.com`,
  `owner@example.com請回覆`) is found by neither `masking.PATTERNS` nor `residual_pii`: both
  end an email with `\w` lookarounds, and a Han character is a word character. This is
  already so in the production path, so it is not a regression of the core, and fixing it
  means changing the legacy detectors, which is out of PR A scope. The replay does not
  help: it reproduces the legacy masker, and the legacy masker does not mask these either.
  Only a neighbour that is masked can expose such an email: once `owner@example.com林志豪`
  has a token in place of the name, the `[` gives the email a boundary, `residual_pii`
  finds it and the document is blocked, exactly as the legacy masker's own output would be.
- Values written back to back can be cut differently by the two candidate sources, or by
  two patterns over the original, and the ranges then cross. The document is refused with
  `SPAN_CONFLICT` (fail closed). The usual case is a birth date or a parcel number followed
  on the same line by an address without a comma
  (`生日：民國80年1月2日 案件地址：新北市板橋區文化路一段123號`,
  `文化段123地號 案件地址：新北市板橋區文化路一段123號`): run over the original, the address
  pattern starts inside the last Han character of the earlier value. The legacy masker has
  replaced the earlier value before the address pattern runs, so it resolves the case by
  pattern order and never refuses. A comma, a full stop or a line break between the two
  values avoids it.
- Only `\n` ends a line for the existing patterns. In documents that use a lone `\r` or
  U+2028 as separator, the address pattern can run across it and the separator can end
  up inside a masked span. The round trip stays exact; CRLF and LF documents are not
  affected.
- `residual_pii` is the only second look. It is conservative: legitimate text can block
  a document, which fails closed, and shapes it does not know pass.
- In-process memory is not protected. CPython `bytes` cannot be wiped, values can reach
  swap or a core dump, and code in the same process can read a manifest. PR A is not a
  defence against a hostile process; PR B's vault and process isolation are.
- One body segment, one process, one injected clock. Entities are not linked: the same
  person in two places is two entities until a later PR adds explicit evidence.
- Versions are provenance. A changed detector affects new issues only; an existing
  masked document keeps restoring from its own manifest.

## Consequences and mitigations

| Risk | Mitigation |
| --- | --- |
| Valid output fails the release scan at random | Letters-only namespace, six-digit sequence, inertness property test over at least 2 000 tokens |
| A user-made token skips the scan or is treated as a system token | Reserved prefix refused at input; the release scan accepts only manifest-issued tokens and scans the rest |
| Label disappears with the value | Label rules plus synthetic golden tests, one per rule |
| A value span swallows a line terminator | Trailing-whitespace trim; LF, CRLF and CR tests |
| Raw value leaks through an exception chain or a log | Codes only, raised outside `except`; checks on `str`, `repr`, `args`, traceback text, `__cause__`, `__context__`, `assertLogs` |
| Tampered manifest or masked bytes restore the wrong thing | Fixed check order, structure checks, token scan, final digest; one tamper test per class |
| Tokens reused across cases | Random per-manifest namespace; binding equality is checked first |
| Mapping outlives its purpose | RAM only, retention deadline, `discard` |
| Core is wired into a flow before PR B/C | No-import contract tests; docs call it an experimental core |
| A crowded or oversized document costs minutes and gigabytes before it is refused | `MAX_OCCURRENCES = 50_000`, a candidate budget, each stage checks the bound it can see, size before hashing; a `tracemalloc` test on a crowded 3 MiB document |
| A tampered manifest or digest ends in a raw exception instead of a code | One digest comparison that never encodes; the release scan judges the manifest first; every such refusal is tested through `assertRejected` (code only, no chained exception) |

## Verification

`tests/test_reversible_masking.py` is the executable form of this ADR. Each test class
carries a comment naming the item of the PR A checklist in issue #28 section 10 that it
proves (round trip, location and isolation, rejection, leak checks, golden preservation,
separation of interfaces), plus contract tests for the grammar, the versions and this
document. A parity class guards candidate coverage: the replay of the legacy masker must
equal `mask_sensitive_text` on every corpus document, both repo fixtures and 400 seeded
documents; its original ranges must agree with a slow character-level oracle, also on 600
documents glued together at random and on synthetic patterns that start inside a
placeholder; and a value the legacy masker hides must not be visible in an accepted
document. Hardening classes cover tampered digest and manifest shapes, size before hashing
in the registry, and the occurrence budget, including a memory bound measured with
`tracemalloc` on a crowded 3 MiB document. All inputs are synthetic and the suite is
deterministic: it asserts properties of random tokens, never their values, and holds no
random-looking hex or base64 literal.

```sh
python3 -m unittest discover -s tests -p 'test_reversible_masking.py' -v
python3 -m unittest discover -s tests
```
