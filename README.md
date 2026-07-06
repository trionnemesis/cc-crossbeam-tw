# cc-crossbeam-tw

台灣建築／室內裝修審查文件助手原型，首發場景聚焦新北市室內裝修文件流程。

本專案從 `cc-crossbeam` 的文件審查與補正回覆流程映射而來，但不直接移植美國 ADU 法規邏輯。現階段先建立 `tw-law-mcp`：一個可由 Codex、Claude Code 或其他 agent host 呼叫的 deterministic、source-bound MCP 工具，用來查詢台灣／新北市室內裝修相關的 P0 法規與程序資料。

GitHub Pages 上手頁位於 [`docs/index.html`](docs/index.html)，用途是讓已安裝 Codex App 的使用者快速完成 clone、MCP 啟動、Phase acceptance、scenario matrix acceptance 與資料邊界確認。

## 目前定位（v0.3 對齊）

- 目標使用者：建築師、室內裝修業者、代辦人員、審查文件整理者。
- MVP 地區：`{central: "TW", local: "ntpc"}`。
- MVP 案型：`室內裝修`。
- 技術形態：stdio JSON-RPC MCP subset。
- 版本：`0.3.0`。資料狀態：P0 fixture corpus，先用來驗證正式流程工具契約（法規快照、程序分流、gates）與 host integration。

## 不是法律判斷工具

本專案只做來源可追溯的文件輔助與流程整理，不提供法律意見、合規保證、違章認定或審查必過承諾。Agent 回答必須保留來源、日期、適用範圍與不確定性，不能把工具輸出包裝成最終法律結論。

## 已完成能力

目前 `tw-law-mcp` 提供以下工具：

- `list_law_packs`：列出可用法規資料包。
- `search_law`：以關鍵字查詢 P0 corpus。
- `get_article`：依 citation id 取得條文或程序片段。
- `verify_citation`：驗證 citation id 是否存在。
- `get_source_policy`：取得引用與回答邊界規則。
- `compare_source_policies`：比對 P0 官方來源的授權、更新政策、crawl policy 差異。
- `run_source_policy_acceptance`：驗證 P0 source policy evidence 與官方來源類別比較覆蓋。
- `list_jurisdictions`：列出 jurisdiction registry；新北市以外 entries 目前 fail-closed。
- `run_jurisdiction_registry_acceptance`：驗證 enabled jurisdiction 有 law pack/stage，disabled jurisdiction 維持 fail-closed。
- `run_packaging_acceptance`：驗證 Codex/Claude Code wrapper 指向同一 standalone MCP server，且 ADR 決策完整。
- `run_scenario_matrix_acceptance`：驗證台灣場景矩陣 fixture 已宣告 corpus packs、tool boundary、artifact、gate、HITL 與禁語政策。
- `run_phase_acceptance`：聚合驗收 P0 source、procedure/HITL、G2 fixture、metadata、jurisdiction、packaging、scenario matrix 七個 roadmap gates。
- `resolve_procedure_requirements`：回傳室內裝修流程需求摘要。
- `resolve_procedure_stage_confidence`：依文件文字與檔案 metadata 判定 `procedure_stage` 信心分數；低信心進 HITL。
- `build_law_snapshot`：依 `{jurisdiction, case_type, procedure_stage, as_of_date}` 產生帶有 `source_policy_state`、`source_authority_rank`、`source_license_status` 的版本化法規快照。
- `check_claim_support`：以低信心 fail-closed 方式做 claim 與條文文字覆蓋檢核（非法律保證）。
- `get_local_rule`：依照 `jurisdiction + rule_name` 查詢在地規範與程序欄位（含文件欄位、授權邊界）。
- `detect_illegal_construction_reference`：偵測違建指標文字/附件存在，但只回 `present/evidence_type/handling`，不做違建認定。
- `extract_file_metadata`：只抽取檔案 metadata，不允許 raw drawing/document content 進 agent input。
- `parse_masked_document`：將已遮罩公文文字轉成 `document_parsed`。
- `normalize_atomic_correction_items`：將解析結果拆成 atomic correction items。
- `build_sheet_manifest`：由圖說/快照檔名建立 metadata-only sheet manifest。
- `build_hitl_confirmation_packet`：將低信心程序或需人工認定項目轉成 `client_questions`。
- `apply_hitl_confirmations`：套用人工回答；缺答、未知 key、無效選項一律 fail-closed。
- `get_fixture_baseline_status`：驗證 G2 fixture baseline 數量、去識別化與欄位契約。
- `run_fixture_pipeline_acceptance`：將 G2 fixture 跑過 snapshot、sheet manifest、HITL packet 與 audit gates。
- `run_audit_gates`：七層可回溯 gate；輸出 `run_meta.gates`（含 gate 序號、retries、intercepted）與 `run_meta.human_review_required`，供後續降級流程使用。

## v0.3 正式地方法規流程對齊摘要

- `law_snapshot`：每次查詢綁定 `{as_of_date, as_of_date_basis, jurisdiction, case_type, procedure_stage}`，輸出 `source_policy_state`、`source_authority_rank`、`source_license_status` 與 `source_update_policy`。
- `procedure_stage`：支援 `圖說審核`、`竣工查驗`、`變更使用併室內裝修竣工查驗`、`簡易室內裝修`，對應不同 required_documents。
- `data_governance_state`：`run_audit_gates` 會檢核 consent、retention、raw/masked 政策、PII 偵測/遮罩與刪除/稽核旗標是否齊備。
- `source_license_status` 與 `source_authority_rank` 已明確分離；`claim_supported` 僅供 fail-closed 降級，不作最終法規裁量。

## 與 upstream cc-crossbeam 的映射

原始 `cc-crossbeam` 是 California ADU permit assistant。本專案採用其產品流程概念，而不是法規內容：

- Corrections Letter Interpreter → 台灣版補正／退件／審查意見解析。
- Response Package → 台灣版補正回覆草稿、專業確認清單、補正狀態報告。
- Permit Checklist Generator → 送審前文件檢核清單。
- City Pre-Screening → 後續城市端初步完整性檢查。

詳細 mapping 文件見 [`docs/cc-crossbeam-feature-matrix.md`](docs/cc-crossbeam-feature-matrix.md)。台灣實務場景主索引見 [`docs/tw-scenario-feature-matrix.md`](docs/tw-scenario-feature-matrix.md)。

## 專案結構

```text
.
├── README.md
├── pyproject.toml
├── docs/
│   ├── index.html
│   ├── styles.css
│   ├── ADR-0001-packaging-strategy.md
│   ├── cc-crossbeam-feature-matrix.md
│   └── tw-scenario-feature-matrix.md
├── fixtures/
│   ├── g2_baseline.json
│   └── tw_scenario_queries.json
├── scripts/
│   ├── build_law_snapshot.py
│   ├── run_fixture_pipeline.py
│   ├── run_jurisdiction_registry_acceptance.py
│   ├── run_packaging_acceptance.py
│   ├── run_phase_acceptance.py
│   ├── run_scenario_matrix_acceptance.py
│   ├── run_source_policy_acceptance.py
│   └── tw_law_mcp_stdio.py
├── tests/
│   ├── test_law_repository.py
│   └── test_stdio_server.py
├── tw_law_mcp/
│   ├── repository.py
│   ├── server.py
│   └── data/
│       └── p0_law_corpus.json
├── .codex/
│   └── config.toml
└── .mcp.json
```

## 執行 MCP server

```bash
python3 scripts/tw_law_mcp_stdio.py
```

輸出法規快照：

```bash
python3 scripts/build_law_snapshot.py --procedure-stage 圖說審核 --as-of-date 2026-07-06
```

執行 G2 fixture pipeline acceptance：

```bash
python3 scripts/run_fixture_pipeline.py
```

執行 P0 source policy acceptance：

```bash
python3 scripts/run_source_policy_acceptance.py
```

執行 registry 與 packaging acceptance：

```bash
python3 scripts/run_jurisdiction_registry_acceptance.py
python3 scripts/run_packaging_acceptance.py
```

執行 Taiwan scenario matrix acceptance：

```bash
python3 scripts/run_scenario_matrix_acceptance.py
```

執行全部 Phase acceptance：

```bash
python3 scripts/run_phase_acceptance.py
```

Codex 專案 MCP 設定在 `.codex/config.toml`。

Claude Code 專案 MCP 設定在 `.mcp.json`。

## 測試

```bash
python3 -m unittest discover -s tests
```

目前測試涵蓋：

- law repository lookup。
- citation verification。
- source policy boundary。
- P0 source policy acceptance。
- jurisdiction registry fail-closed acceptance。
- packaging strategy acceptance。
- Taiwan scenario matrix acceptance。
- aggregate Phase acceptance。
- procedure-stage confidence + HITL confirmation loop。
- G2 fixture pipeline acceptance。
- metadata-only document/drawing extraction contracts。
- stdio JSON-RPC smoke test。

## Fixture Baseline

`fixtures/g2_baseline.json` 是 G2 contract baseline：12 份 synthetic de-identified cases、84 個 atomic correction items。此 baseline 用來驗證 schema、gate 與 HITL flow contract，不包含真實姓名、地址、電話、身分證字號、title block 原圖、raw PDF 或 raw drawing。真實去識別案件導入前，必須維持相同欄位與 raw/masked 分流規則。

`fixtures/tw_scenario_queries.json` 是台灣場景矩陣 baseline：每題宣告 scenario category、預期 corpus packs、tool boundary、artifact、gate、HITL policy 與禁止輸出。它先驗證 contract coverage，不代表所有正式 corpus pack 已完成 ingestion。

目前 scenario matrix 覆蓋 `procedure`、`fire_equipment`、`fire_compartment`、`material`、`completion_packet`、`response_draft` 六類 MVP scenarios，另含 `web_fallback` 作為 corpus miss 的 fail-closed plan-only 行為。

## Phase Acceptance 狀態

`python3 scripts/run_phase_acceptance.py` 會聚合驗收以下 gates：

- P0 corpus 官方文件來源授權與更新政策差異比對。
- `procedure_stage` 信心分數與 HITL 確認回路。
- G2 fixture baseline：12 份 synthetic de-identified cases 與 84 個 atomic correction items。
- 圖說／申請文件 metadata-only extraction。
- 新北市以外 jurisdiction registry fail-closed stubs。
- Codex plugin／Claude Code plugin／獨立 MCP server 封裝策略；目前決策為 standalone MCP server first，Codex/Claude Code 只保留 thin MCP wrappers。
- Taiwan scenario matrix：procedure、fire equipment、fire compartment、material、completion packet、response draft 六類 MVP scenario 均有 fixture coverage。

Production 導入前仍需以 approved real de-identified cases 補強或替換 synthetic fixture，並建立 live source ingestion/refresh workflow；目前 acceptance 驗證的是 contract 與 fail-closed 邊界。
