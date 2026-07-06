# cc-crossbeam → cc-crossbeam-tw 功能矩陣映射

來源基準：`mikeOnBreeze/cc-crossbeam` GitHub `main`，本次檢視於 2026-07-06 clone 至 `/private/tmp/cc-crossbeam-source`。

本文件只做功能與架構映射。台灣版定位維持「審查文件 auditability pipeline」，不得輸出法律合規保證、違法認定、保證通過或替代專業簽證結論。

## 1. 產品 Flow 映射

| 原 cc-crossbeam 功能 | 原始實作位置 | 原始行為 | cc-crossbeam-tw 對應 | 遷移狀態 |
| --- | --- | --- | --- | --- |
| Flow 1: Corrections Letter Interpreter | `server/src/routes/generate.ts`, `agents-crossbeam/src/flows/corrections-analysis.ts`, `server/skills/adu-corrections-flow/` | Contractor 上傳 plan binder + corrections letter；Phase 1 解析補正、研究法規、分類、產生 contractor questions。 | `corrections-analysis` → 新北室內裝修補正/退件/審查文件解析；輸出 `document_parsed.json`, `atomic_correction_items.json`, `corrections_adjudicated.json`, `client_questions.json`, `run_meta.json`。 | Phase 1 target；目前已先落地 `tw-law-mcp` citation/source-policy 基礎工具。 |
| Flow 1 Phase 2: Response package | `agents-crossbeam/src/flows/corrections-response.ts`, `server/skills/adu-corrections-complete/` | 冷啟動讀 Phase 1 artifacts + contractor answers，產生 response letter、professional scope、corrections report、sheet annotations。 | `corrections-response` → 讀台灣版 analysis artifacts + 使用者/專業人員回答，產生補正回覆草稿、專業確認清單、補正狀態報告、圖說修改摘要。 | Phase 2 target；需等 atomic item / gate schema 穩定。 |
| Flow 2: Permit Checklist Generator | README 與 plan docs；部分由 `adu-city-research` / frontend demo 支撐 | 使用地址、ADU type、size、lot info 研究城市送件要求，產生 pre-submission checklist。 | `pre-submission-checklist` → 新北室內裝修送件前檢核表；輸入 `case_type`, `procedure_stage`, `fire_safety_equipment_change`, `partition_wall_change` 等。 | Phase 2 target；應復用 `resolve_procedure_requirements`。 |
| Flow 3: City Pre-Screening | `agents-crossbeam/src/flows/plan-review.ts`, `server/skills/adu-plan-review/`；README 標為 roadmap/open-source vision | 市府端上傳 permit submission，代理檢查 missing docs、unsigned pages、incomplete forms，產生 draft corrections letter。 | Deferred city-side review；台灣版可做「審查前文件 completeness / audit packet」，不得做主管機關式合格/違法裁判。 | Roadmap；需另定市府端產品責任與資料治理。 |

## 2. Domain / 法規知識映射

| 原 cc-crossbeam | 台灣版替換 | 保留/改寫規則 |
| --- | --- | --- |
| `california-adu` skill，包含 HCD ADU Handbook、Gov. Code 66310-66342、thresholds、decision tree。 | `taiwan-interior-renovation` P0 corpus：建築物室內裝修管理辦法、建築法室裝相關條文、新北室裝審核/查驗公開文件、source policy registry。 | 保留 skills-first / reference-pack 形式；法條不再作一般 text chunk，要進 `law_snapshot` + checksum + source policy。 |
| `ONBOARDED_CITIES`: `placentia`, `buena-park` → dedicated city skill，非 onboarded 用 web research。 | `Jurisdiction Registry`: `{central:"TW", local:"ntpc"}` + `case_type` + `procedure_stage`；後續 `tpe`, `tyc` feature flag。 | city routing 改為 jurisdiction/procedure routing；rank 5 WebSearch 只能 fallback，不支撐法定要件判定。 |
| ADU classification: contractor fix / needs engineer / already compliant。 | 三值判定：`符合要件跡象` / `缺失待補` / `需人工認定`。 | 移除 assurance 語言；專業簽證、低信心、條文支持不足一律降級人工。 |
| State law preempts city rules。 | 中央/地方層級關係提示。 | 不做最終裁判；只標示層級關係與引用，交由人工確認。 |
| City-specific municipal code research via WebSearch/WebFetch/browser fallback。 | `tw-law-mcp`: `search_law`, `get_article`, `verify_citation`, `get_source_policy`, `list_law_packs`, `resolve_procedure_requirements`。 | 將 domain lookup 從 prompt research 提升為 deterministic tool boundary。 |

## 3. File Contract / Artifact 映射

| 原始 artifact | 原始用途 | 台灣版 artifact | 變更重點 |
| --- | --- | --- | --- |
| `corrections_parsed.json` | corrections letter structured extraction。 | `document_parsed.json` | 改成台灣公文欄位：發文機關、日期、字號、主旨、說明、辦法、附件。 |
| `corrections_categorized.json` | 補正項分類與 research context。 | `atomic_correction_items.json` + `corrections_adjudicated.json` | 先 atomic normalizer，再 gate 後判定；每項保留 `source_span`。 |
| `sheet-manifest.json` | sheet ID → page mapping。 | `sheet_manifest.json` | 保留；需重校台灣室裝圖說、竣工圖、材料表、現況圖頁名慣例。 |
| `state_law_findings.json` | California state code lookups。 | `central_law_findings.json` | 每條含 law snapshot version、rank、license、checksum。 |
| `city_discovery.json`, `city_research_findings.json` | city rule discovery/extraction。 | `local_rule_findings.json` | 新北官方來源優先；授權不明時 `official_reference_only`。 |
| `sheet_observations.json` | plan sheet observations。 | `sheet_observations.json` | 保留，但不得直接變成合規/違法結論。 |
| `contractor_questions.json` | UI-ready contractor HITL questions。 | `client_questions.json` | 改成使用者/建築師/室裝專技/消防專業確認問題。 |
| `response_letter.md` | building department response draft。 | `response_draft.md` | 固定免責與禁語 linter；不得宣稱一定通過。 |
| `professional_scope.md` | architect/engineer work breakdown。 | `human_review_packet.md` / `professional_review_packet.md` | 專業簽證紅線項目只列確認清單，不替代簽證。 |
| `corrections_report.md` | status dashboard/checklist。 | `correction_summary.md` / `pre_submission_checklist.md` | 引用需通過 citation/source/claim gates。 |
| `sheet_annotations.json` | per-sheet needed changes。 | `sheet_annotations.json` | 保留，但文字改為「建議補正/需人工確認」。 |
| 無 | 無違建處理。 | `illegal_construction_reference.json` | 僅偵測附件/文字存在，不做違建認定。 |
| 無 | 無明確個資治理 artifact。 | `data_governance_state` in `run_meta.json` | 記錄 consent、raw/masked 分流、PII status、retention。 |

## 4. Backend / Orchestration 映射

| 原 cc-crossbeam 元件 | 原始職責 | 台灣版處理 |
| --- | --- | --- |
| `POST /api/generate` | validate `project_id`, `user_id`, `flow_type`；設定 processing status；pre-extract；下載 files；啟動 sandbox agent。 | 保留 endpoint pattern；input 增加 `jurisdiction`, `case_type`, `procedure_stage`, `as_of_date_basis`, `consent_record_id`。 |
| `POST /api/extract` / `extractPdfForProject` | Cloud Run 用 `pdftoppm` + ImageMagick 產生 `pages-png.tar.gz` 與 `title-blocks.tar.gz`。 | 保留 Cloud Run pre-extract；台灣公文文字先走 OCR，圖說仍產生 page PNG 與 title-block/頁名 crop。 |
| Vercel Sandbox lifecycle | 建 sandbox、裝 Claude Code/Agent SDK、下載 Supabase files、copy skills、run agent、upload outputs。 | 保留隔離與 file-contract；加入 `tw-law-mcp` 或本地 law snapshot access；主 agent 仍不得讀大圖/大型 JSON。 |
| `getFlowSkills(flowType, city)` | 依 flow + city 載入 California/Placentia/Buena Park/city research skills。 | 改為 `resolveLawPacks(jurisdiction, case_type, procedure_stage)` + `procedure_stage` registry。 |
| `FLOW_BUDGET` | 依 flow 控制 turns/cost。 | 保留；繁中 token、OCR、claim verifier 需重新校準。 |
| `messages` stream | agent progress 寫入 Supabase Realtime。 | 保留；需加 gate statistics / data governance event。 |
| `outputs.raw_artifacts` | 存所有 agent output files。 | 保留；但主 artifact schema 要改為台灣版 contract。 |

## 5. Frontend / UX 映射

| 原始 UI | 原始行為 | 台灣版對應 |
| --- | --- | --- |
| `ContractorDashboard` | 顯示 demo contractor corrections projects。 | 室裝業者/建築師/代辦案件列表；顯示 procedure stage、HITL status、data governance state。 |
| `CityDashboard` | 顯示 city-review projects。 | Roadmap：審查前 completeness / city-side prescreen；MVP 可隱藏或改成 internal QA。 |
| `ContractorQuestionsForm` | 讀 `contractor_answers`，提交後觸發 `corrections-response`。 | 讀 `client_questions`/`professional_review_packet` 對應問題；提交後觸發台灣版 response generation。 |
| `ProgressPhases` / `AgentStream` | 顯示 phase 與 agent messages。 | 保留；phase label 改成公文解析、atomic item、法源引用、gate、人工確認。 |
| `ResultsViewer` | city-review 顯示 corrections letter；contractor 顯示 response/scope/report tabs。 | 顯示補正清單、回覆草稿、人工確認清單、檢核表、run_meta/gate summary。 |
| Persona toggle | contractor / city demo 切換。 | MVP 應改為「送件端」主流程；市府端另列 roadmap，避免 scope creep。 |

## 6. Data Model 映射

| 原表/欄位 | 原語意 | 台灣版調整 |
| --- | --- | --- |
| `projects.flow_type` | `city-review` / `corrections-analysis`; `corrections-response` 為 internal flow。 | 增加或替換為 `case_type`, `procedure_stage`, `jurisdiction`; flow 保留 workflow 狀態，不承載法域語意。 |
| `projects.city`, `project_address` | city routing 與 project display。 | 改為 `jurisdiction.central`, `jurisdiction.local`, `project_address`; address 不作法域唯一來源。 |
| `projects.status` | `ready → processing-* → awaiting-answers → completed/failed`。 | 保留；新增 low-confidence procedure HITL 也走 `awaiting-answers` 或細分 `awaiting-procedure-confirmation`。 |
| `files.file_type` | `plan-binder`, `corrections-letter`, `other`。 | 增加 `document_file`, `drawing_file`, `ocr_text`, `masked_file`, `source_snapshot` 等分型。 |
| `outputs.raw_artifacts` | all JSON/MD outputs。 | 保留；新增 `law_snapshot_id`, `gate_results`, `data_governance_state` 必備。 |
| `contractor_answers` | questions/answers for Phase 2。 | 改名或語意擴張為 `client_answers` / `human_review_answers`；保留 `question_key`, `answer_text`, `is_answered` pattern。 |
| 無 | 無 consent/retention/masking state。 | 新增 consent records、raw/masked retention、PII detection/masking status、audit log。 |

## 7. Test / Validation 映射

| 原始測試層 | 原始目的 | 台灣版測試 |
| --- | --- | --- |
| `agents-crossbeam/src/tests/test-l0*` | Agent SDK smoke / city smoke。 | `tw-law-mcp` import + MCP stdio smoke；目前已建立 `tests/test_stdio_server.py`。 |
| `test-l1*` | skill invoke/read。 | Taiwan skills/law packs trigger + required references readable。 |
| `test-l2-subagent-bash.ts` | subagent/file writing capability。 | OCR/vision subagent writes contract files; main agent never reads large PNG. |
| `test-l3-mini-pipeline.ts` | analysis mini-pipeline writes categorized corrections/questions。 | 公文 parser + atomic normalizer + citation gate mini pipeline。 |
| `test-l3d-pdf-generation.ts` | PDF/deliverable generation path。 | Markdown/Docx/PDF output with disclaimer and red-line linter。 |
| `test-l4-full-pipeline.ts` | Skill 1 → answers → Skill 2 E2E。 | Flow 1 analysis → client/pro answers → response draft E2E fixture。 |
| 無 | 原系統較依賴 citation requirement。 | 新增 adversarial `claim_supported` false-accept test、source license/rank gate、PII/data governance tests。 |

## 8. Migration Sequencing

| Phase | 從原 cc-crossbeam 搬的骨架 | 台灣版新增/替換 | Exit Gate |
| --- | --- | --- | --- |
| 0: Current baseline | MCP/tool boundary not in original; repo starts with `tw-law-mcp` core. | deterministic P0 fixture, source policy, citation lookup。 | `python3 -m unittest discover -s tests`; Codex MCP listed enabled。 |
| 1: Domain extraction | Skills-first pack、city routing、file-contract outputs。 | `Jurisdiction Registry`, `procedure_stage`, P0 corpus, `law_snapshot`, `source_policy_state`。 | P0 entries have URL/rank/license/checksum; MCP contract tests pass。 |
| 2: Analysis pipeline | `corrections-analysis` two-stage contractor flow。 | 公文 parser、atomic normalizer、三值判定、7-layer gates、client questions。 | Golden set ≥12 docs / ≥80 atomic items; gate false-positive constraints pass。 |
| 3: Response/checklist | `corrections-response`, `contractor_answers`, `ResultsViewer` tab pattern。 | 回覆草稿、送件前檢核表、人工確認包、免責與禁語 linter。 | E2E fixture pass; no prohibited assertions。 |
| 4: Full app reintegration | Cloud Run + Sandbox + Supabase + Realtime。 | data governance, audit log, snapshot diff, affected fixture rerun。 | audit trail: claim → citation → source → snapshot。 |
| Roadmap: city-side | `city-review` flow。 | completeness prescreen only, not authority-like adjudication。 | Separate MFR/ADR before implementation。 |

## 9. Do Not Port Directly

- California ADU objective-standard/legal-preemption prompts as-is.
- `contractor fix / needs engineer / already compliant` labels.
- WebSearch-backed city rules as authoritative evidence.
- Any wording equivalent to compliant/illegal/guaranteed pass.
- City-review flow as MVP public promise.
- Demo-only Placentia manifest pre-injection behavior; Taiwan fixtures must be explicit and versioned.

## 10. Immediate Next Implementation Targets

1. Add `jurisdiction`, `case_type`, `procedure_stage`, `law_snapshot_id`, and `data_governance_state` to the documented schema plan before porting Supabase migrations.
2. Create Taiwan skill pack skeletons mirroring the original skill pattern:
   - `taiwan-interior-renovation`
   - `ntpc-interior-renovation`
   - `tw-corrections-flow`
   - `tw-corrections-complete`
3. Expand `tw-law-mcp` beyond fixture data into versioned corpus ingestion.
4. Port the original two-stage contractor flow only after P0 corpus and gate tests are stable.
