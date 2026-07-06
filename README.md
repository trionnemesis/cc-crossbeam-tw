# cc-crossbeam-tw

**台灣室內裝修送審文件助手原型**，首發場景聚焦新北市室內裝修申請與補正流程。

這個專案要處理的是建築師、室內裝修業者、代辦人員反覆遇到的文件整理問題：

> 這個案子到底走哪個程序？要備哪些文件？主管機關公文上的補正意見，每一條對應到什麼資料、圖說、法規來源或人工確認？

`tw-law-mcp` 把這些判斷拆成可追溯的 MCP 工具，讓 Codex、Claude Code 或其他支援 MCP 的 AI 助手在回答時先查本機工具與來源快照，而不是憑印象補法條、補文件或直接下結論。

GitHub Pages 上手頁位於 [`docs/index.html`](docs/index.html)。

## 適合誰

- 建築師事務所：整理室內裝修圖說審核、竣工查驗、變更使用併室內裝修竣工查驗的文件缺口。
- 室內裝修業者：把補正公文拆成逐條任務，確認哪些資料要回頭找業主、廠商或專業人員補。
- 代辦與行政窗口：先做程序分流、送件 packet、缺件清單與回覆草稿，再交由專業人員確認。
- AI/工程團隊：把室內裝修送審流程包成 deterministic、source-bound 的 MCP server，避免 agent 任意編造。

## 能幫上什麼忙

| 日常工作 | 工具能做的事 | 產出 |
|---|---|---|
| 程序分流 | 判斷案件比較接近圖說審核、竣工查驗、變更使用併室內裝修竣工查驗或簡易室內裝修，並標示信心分數 | `procedure_stage_signal`、人工確認問題 |
| 送件前檢核 | 依程序階段整理新北市室內裝修文件 packet | 文件清單、缺件提示、source-bound references |
| 補正公文整理 | 解析已遮罩公文，拆成 atomic correction items | 補正項目清單、回覆草稿、專業確認包 |
| 消防與防火相關提示 | 標示可能涉及消防設備、防火區劃、防火門、材料證明的文件需求 | routing 結果、需要消防或建築專業確認的問題 |
| 稽核與溯源 | 每次回答保留來源、日期、gate 與人工介入狀態 | law snapshot、run metadata、acceptance output |

## 先講邊界

這不是法律判斷工具，也不是專業簽證工具。

| 會做 | 不會做 |
|---|---|
| 整理程序、文件、來源與待確認事項 | 判定案件合法或違建 |
| 依已遮罩資料與 metadata 做程序分流 | 保證審查必過 |
| 產生補正回覆草稿與專業確認包 | 出具法律意見或合規保證 |
| 標示可能相關的條文、來源 URL、authority rank、as-of date | 替代建築師、消防設備師或其他專業人員簽證 |
| 對消防、防火區劃、材料證明做文件 routing | 做消防設計結論或材料真偽判斷 |

不確定、資料不足、涉及專業裁量或低信心時，工具會 fail closed 並要求 human-in-the-loop，不會硬判定。

## 可以怎麼問 AI 助手

本機 MCP 設定完成後，可以在 Codex 或 Claude Code 內這樣問：

```text
請使用 tw-law-mcp 先跑 run_phase_acceptance。
接著根據我提供的已遮罩文件文字與檔案 metadata，判斷目前比較接近：
圖說審核、竣工查驗、變更使用併室內裝修竣工查驗、簡易室內裝修。
請輸出 procedure_stage 信心分數、需要的人工確認問題、會用到的 corpus packs、產出的 artifacts，以及不能判定的原因。
不要輸出法律意見、合規保證、消防設計結論、材料真偽結論或審查必過承諾。
```

其他常見問題：

- 「這份案件的檔案 metadata 在這裡，幫我判斷比較接近圖說審核還是竣工查驗？信心多高？還缺什麼資訊？」
- 「幫我依竣工查驗階段，產生新北市室內裝修的送件文件 packet。」
- 「這是遮罩過的補正公文，幫我拆成逐條補正項目，哪些需要建築師、消防或材料廠商確認？」

## 資料隱私原則

不要直接把以下內容貼進 prompt：

- 未遮罩姓名、地址、電話、身分證字號。
- title block、原始圖說、raw drawing、raw PDF。
- 客戶授權範圍不明的完整申請文件。

建議只提供：

- 已遮罩公文文字。
- 檔名、圖號、頁名、sheet type、文件類型等 metadata。
- 已去識別化 fixture 或測試案例。
- 人工確認答案與 acceptance output。

工具本身也以 metadata-only boundary 設計，避免 raw drawing 或 raw PDF 內容直接進入 agent prompt。

## 快速開始

```bash
git clone https://github.com/trionnemesis/cc-crossbeam-tw.git
cd cc-crossbeam-tw
python3 scripts/tw_law_mcp_stdio.py
```

- Codex App：專案設定在 `.codex/config.toml`。
- Claude Code：專案設定在 `.mcp.json`。
- 啟動後建議先執行 `run_phase_acceptance`，確認本機工具、fixtures 與 acceptance gates 正常。

## 目前狀態

- 版本：`0.3.0` prototype。
- 首發地區：新北市。
- 首發案型：室內裝修。
- 已完成到 Phase 2.1-2.6 / Step 6：split data layout、source adapter contracts、scenario MCP tools、hardened scenario matrix evaluation、two-stage contractor flow skeleton。
- 目前使用 P0 fixture corpus 與 synthetic de-identified cases 驗證流程契約；production 導入前仍需 approved real de-identified cases 與 live official-source ingestion/refresh workflow。
- 新北市以外 jurisdiction 已預留 registry，但目前 fail closed，不主動作答。

本專案的產品流程概念源自 [`cc-crossbeam`](https://github.com/trionnemesis/cc-crossbeam) 的文件審查與補正回覆流程；只借流程，不搬美國 ADU 法規。對照表見 [`docs/cc-crossbeam-feature-matrix.md`](docs/cc-crossbeam-feature-matrix.md)。

<details>
<summary><strong>開發者資訊：MCP 工具、測試與 acceptance gates</strong></summary>

## 技術形態

- Python stdio JSON-RPC MCP subset。
- Standalone MCP server first；Codex / Claude Code 是 thin wrappers。
- 封裝決策見 [`docs/ADR-0001-packaging-strategy.md`](docs/ADR-0001-packaging-strategy.md)。

## MCP 工具分類

目前 server 宣告 38 個 MCP tools：

- 法規與來源查詢：`list_law_packs`、`search_law`、`get_article`、`verify_citation`、`get_local_rule`、`build_law_snapshot`
- 程序分流：`resolve_tw_scenario`、`resolve_procedure_stage_confidence`、`resolve_procedure_requirements`
- 專業文件 routing：`check_fire_equipment_routing`、`check_fire_compartment_evidence`、`check_material_evidence`、`detect_illegal_construction_reference`
- 文件處理：`extract_file_metadata`、`parse_masked_document`、`normalize_atomic_correction_items`、`build_sheet_manifest`、`build_ntpc_submission_packet`
- 兩階段補正流程：`run_tw_corrections_analysis`、`run_tw_corrections_response`
- HITL：`build_hitl_confirmation_packet`、`apply_hitl_confirmations`
- 來源政策與 fallback：`get_source_policy`、`compare_source_policies`、`plan_web_search_fallback`
- 驗收：`run_phase_acceptance`、`run_audit_gates`、`run_source_policy_acceptance`、`run_jurisdiction_registry_acceptance`、`run_packaging_acceptance`、`run_scenario_matrix_acceptance`、`run_data_layout_acceptance`、`run_source_adapter_acceptance`、`run_fixture_pipeline_acceptance`、`run_two_stage_flow_acceptance`、`get_fixture_baseline_status`、`list_jurisdictions`

## 測試

```bash
python3 -m unittest discover -s tests
python3 scripts/run_phase_acceptance.py
```

各項 acceptance script 位於 `scripts/`，涵蓋 source policy、data layout、source adapters、jurisdiction registry、packaging、scenario matrix、fixture pipeline、two-stage flow。

## Fixture baseline

- `fixtures/g2_baseline.json`：12 份 synthetic de-identified cases、84 個 atomic correction items，用於驗證 schema、gate、HITL flow contract。
- `tw_law_mcp/data/fixtures/tw_scenario_queries.json`：台灣場景矩陣，涵蓋 `procedure`、`fire_equipment`、`fire_compartment`、`material`、`completion_packet`、`response_draft` 六類，每類至少 5 題，另含 `web_fallback`。

## 專案結構

```text
tw_law_mcp/     # MCP server core and data
scripts/        # stdio entrypoint and acceptance scripts
tests/          # unittest coverage
fixtures/       # G2 contract baseline
docs/           # GitHub Pages, ADR, feature matrix
```

實務場景主索引見 [`docs/tw-scenario-feature-matrix.md`](docs/tw-scenario-feature-matrix.md)。

</details>
