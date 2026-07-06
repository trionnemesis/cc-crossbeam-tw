# cc-crossbeam-tw

台灣建築／室內裝修審查文件助手原型，首發場景聚焦新北市室內裝修文件流程。

本專案從 `cc-crossbeam` 的文件審查與補正回覆流程映射而來，但不直接移植美國 ADU 法規邏輯。現階段先建立 `tw-law-mcp`：一個可由 Codex、Claude Code 或其他 agent host 呼叫的 deterministic、source-bound MCP 工具，用來查詢台灣／新北市室內裝修相關的 P0 法規與程序資料。

## 目前定位

- 目標使用者：建築師、室內裝修業者、代辦人員、審查文件整理者。
- MVP 地區：`{central: "TW", local: "ntpc"}`。
- MVP 案型：`室內裝修`。
- 技術形態：stdio JSON-RPC MCP subset。
- 資料狀態：P0 fixture corpus，先用來驗證工具契約、citation policy、host integration。

## 不是法律判斷工具

本專案只做來源可追溯的文件輔助與流程整理，不提供法律意見、合規保證、違章認定或審查必過承諾。Agent 回答必須保留來源、日期、適用範圍與不確定性，不能把工具輸出包裝成最終法律結論。

## 已完成能力

目前 `tw-law-mcp` 提供以下工具：

- `list_law_packs`：列出可用法規資料包。
- `search_law`：以關鍵字查詢 P0 corpus。
- `get_article`：依 citation id 取得條文或程序片段。
- `verify_citation`：驗證 citation id 是否存在。
- `get_source_policy`：取得引用與回答邊界規則。
- `resolve_procedure_requirements`：回傳室內裝修流程需求摘要。

## 與 upstream cc-crossbeam 的映射

原始 `cc-crossbeam` 是 California ADU permit assistant。本專案採用其產品流程概念，而不是法規內容：

- Corrections Letter Interpreter → 台灣版補正／退件／審查意見解析。
- Response Package → 台灣版補正回覆草稿、專業確認清單、補正狀態報告。
- Permit Checklist Generator → 送審前文件檢核清單。
- City Pre-Screening → 後續城市端初步完整性檢查。

詳細 mapping 文件見 [`docs/cc-crossbeam-feature-matrix.md`](docs/cc-crossbeam-feature-matrix.md)。

## 專案結構

```text
.
├── README.md
├── pyproject.toml
├── scripts/
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
- stdio JSON-RPC smoke test。

## 後續路線

- 匯入 versioned corpus，不再只依賴 fixture。
- 建立 `check_claim_support`，檢查回答是否有足夠來源支撐。
- 建立補正文件解析 schema。
- 加入圖說／申請文件 metadata extraction。
- 擴充新北市以外的 jurisdiction registry。
- 評估 Codex plugin／Claude Code plugin／獨立 MCP server 的封裝策略。
