# Taiwan Scenario Feature Matrix

本文件是 `cc-crossbeam-tw` 後續 issue、PR 與 acceptance 的主索引。

產品定位：台灣室內裝修審查文件 auditability copilot。系統可以做 source-bound 查詢、文件完整性檢核、人工確認問題與回覆草稿輔助；不得輸出法律合規保證、違法認定、消防設計結論、材料真偽結論或保證通過。

## Scenario Matrix

| 功能區塊 | 台灣／新北場景 | Source pack | Tool boundary | Artifact | Gate | Scenario test |
| --- | --- | --- | --- | --- | --- | --- |
| 案件起始分流 | 判斷圖說審核、竣工查驗、變更使用併室裝竣工查驗、簡易室內裝修 | `tw-central-interior-core`, `ntpc-interior-procedure` | `resolve_tw_scenario`, `resolve_procedure_stage_confidence`, `resolve_procedure_requirements` | `procedure_stage_signal.json`, `client_questions.json` | 低信心一律 HITL | 「這案是竣工查驗還是圖說審核？」 |
| 送件前檢核 | 新北室裝申請前文件檢查 | `tw-central-interior-core`, `ntpc-interior-procedure` | `build_ntpc_submission_packet` | `pre_submission_checklist.md` | 文件缺漏不得補完臆測 | 「圖說審核送件前要檢哪些文件？」 |
| 補正／退件公文解析 | 解析審查意見，拆成 atomic correction items | `tw-central-interior-core`, `ntpc-interior-procedure` | `parse_masked_document`, `normalize_atomic_correction_items` | `document_parsed.json`, `atomic_correction_items.json` | 每項保留 source span | 「幫我把補正公文拆成逐項回覆清單」 |
| 消防安全設備 routing | 室裝是否變更、妨礙或破壞消防安全設備；是否需要消防局文件 | `tw-central-fire-equipment`, `ntpc-interior-procedure` | `check_fire_equipment_routing` | `fire_equipment_routing.json` | 不做消防設計結論，只判斷文件／專業確認需求 | 「有動到灑水頭或火警探測器要附什麼？」 |
| 防火區劃查詢 | 防火門、防火牆、防火樓板、挑空、昇降機道、管道間、貫穿部、防火閘門 | `tw-fire-compartment-and-egress` | `check_fire_compartment_evidence` | `fire_compartment_findings.json` | 條文支持不足進人工確認 | 「管道間維修門、防火門、風管穿越防火牆怎麼查？」 |
| 裝修材料查詢 | 耐燃一級／二級／三級、不燃材料、防火塗料、材料證明、認可通知書 | `tw-material-evidence`, `ntpc-interior-procedure` | `check_material_evidence` | `material_evidence_check.json` | 只檢查證明文件存在與對應關係，不宣稱材料真偽 | 「耐燃材料證明缺了怎麼補？」 |
| 竣工查驗包 | 竣工材料書、材料計算表、認證材料合格證明、消防局文件、防火區劃照片、竣工圖說 | `tw-central-interior-core`, `tw-material-evidence`, `ntpc-interior-procedure` | `build_ntpc_submission_packet` | `ntpc_completion_packet.md`, `photo_manifest.json` | 表單／照片缺項 fail-closed | 「竣工查驗要哪些材料表、照片、消防文件？」 |
| 變更使用併室裝 | 使用類組變更、消防設備、防火避難、室裝文件交疊 | `tw-central-interior-core`, `tw-central-fire-equipment`, `tw-fire-compartment-and-egress`, `ntpc-interior-procedure` | `resolve_tw_scenario`, `build_ntpc_submission_packet` | `change_use_interior_overlay.json` | 永遠標示需建築師／消防專業確認 | 「變更使用併室裝竣工查驗要注意哪些文件？」 |
| 回覆草稿 | 補正回覆、圖說修改摘要、專業確認清單 | Scenario artifacts + citation gates | `run_audit_gates` plus response drafting layer | `response_draft.md`, `professional_review_packet.md` | 禁語 linter：不得寫「已合規」「保證通過」「無違法」 | 「幫我寫補正回覆」 |
| Web fallback | Corpus 查無地方公告、書表或特定版本 | Source adapter registry | `plan_web_search_fallback` | `web_search_fallback_plan.json` | 只輸出 fallback plan，不直接回答 | 「查不到某地方公告時下一步怎麼做？」 |

## Source Pack Plan

| Pack | Role | Initial data policy |
| --- | --- | --- |
| `tw-central-interior-core` | 建築法、室內裝修管理辦法與室裝直接程序核心 | 中央法規採 article-level `source_unit` |
| `tw-central-fire-equipment` | 消防法與各類場所消防安全設備設置標準的文件 routing 依據 | 中央法規採 article-level `source_unit`，不輸出設計裁判 |
| `tw-fire-compartment-and-egress` | 防火區劃、防火門、貫穿部、分間牆、避難相關條文 | 中央法規採 article-level `source_unit` |
| `tw-material-evidence` | 材料證明文件 schema、認可資料與後市場查核入口 | 認可資料採 certificate-record-level 或 official reference |
| `ntpc-interior-procedure` | 新北室裝圖說審核、竣工查驗、簡易室裝、書表與線上申辦 | 採 `official_reference_only`，保留 URL、摘要、hash 與人工 snapshot evidence |

## Acceptance Matrix

`run_scenario_matrix_acceptance` 必須逐項報告：

- 每個 MVP scenario 是否有 corpus pack coverage。
- 每個 MVP scenario 是否有 tool boundary。
- 每個 MVP scenario 是否有 artifact contract。
- 每個 MVP scenario 是否有 gate。
- 每個 MVP scenario 是否有 fixture query。
- Corpus miss 是否只產生 fail-closed fallback plan。

MVP acceptance 定義：

- `procedure`, `fire_equipment`, `fire_compartment`, `material`, `completion_packet`, `response_draft` 六類 scenario 全數通過。
- 每類至少 5 個 scenario query 才能宣告 production-ready；prototype 可先以 1 題 fixture 驗證 schema。
- Citation precision 100%。
- Unsupported claim 0。
- 涉及專業簽證、材料真偽、消防設計、違建認定時 HITL 觸發率 100%。

## Implementation Order

1. 建立本文件作為主索引，避免後續 implementation scope 漂移。
2. 新增 `fixtures/tw_scenario_queries.json` 作為 TDD fixture。
3. 新增 `run_scenario_matrix_acceptance` repository API 與 `scripts/run_scenario_matrix_acceptance.py`。
4. 將 `run_phase_acceptance` 聚合新的 scenario matrix gate。
5. 逐步補足 `resolve_tw_scenario`, `check_fire_equipment_routing`, `check_fire_compartment_evidence`, `check_material_evidence`, `build_ntpc_submission_packet`, `plan_web_search_fallback`。
