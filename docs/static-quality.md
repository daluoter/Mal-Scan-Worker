# 靜態分析品質基準

更新日期：2026-10-19（Asia/Taipei）。目標是讓偵測結果、分析範圍與子檔案證據可以重現及核對。
目前一般基準為 `corpus-v4.json`（32 案、`msrs-v1.2`），PDF 密碼另用 `pdf-password-v2.json`（12 案）；
新增逐層風險預期。本次 PDF v2 原生 12／12 通過，32 份一般原生報告以最終 v4 manifest 重新核對通過。
一般原生偵測已執行；初次 manifest 的 per-case 政策斷言仍為 1.1，造成彙總失敗。
只修正斷言為 1.2，保留 fixture bytes、原始報告及初次失敗彙總，再重跑報告驗證，沒有重跑偵測器。
worker 852、backend 233、frontend 52、控制層 25 項通過；四項 PostgreSQL opt-in 與一項完整 Python fixture 跳過。
Ruff／strict mypy、前端 typecheck／lint／cloud-demo build 通過，詳見 [回饋修正紀錄](milestones/2026-10-18-pdf-feedback.json)。
以下歷史批次的通過數字不能代替本次結果。
這份基準使用合成資料與標準 EICAR 測試字串，不是實際惡意程式樣本庫，也不能據此估計真實世界的偵測率。

2026-10-17 第二批 32／32 真實引擎案例通過，共 28 個固定 fixture。worker 717 passed／3 skipped、
backend 203 passed／1 skipped、frontend 34 passed；四個 skip 均為 PostgreSQL opt-in。
Ruff、strict mypy、前端 typecheck／lint／cloud-demo build 通過。
完整報告另以加強後的 parent 圖與編碼 URL 驗收器重新核對 32 案，沒有重跑偵測器；
原始與最終 manifest 雜湊、工具版本、逐案結果見
[2026-10-17 紀錄](milestones/2026-10-17-static-quality.json)。
歷史第一批 18／18 真實引擎完整流程及一般測試結果見
[2026-10-16 紀錄](milestones/2026-10-16-static-quality.json)，不能沿用為第二批的通過證據。
兩批品質變更的正式 worker／Pages 部署結果與三份 demo 報告已核對：正常 Office、PDF action、加密 PDF。
這些報告使用當時尚無 PDF 密碼補交的版本，不能代替本批 PDF 密碼恢復驗收。
2026-10-18 PDF 程式與本機驗證完成：最終一般原生基準 32／32、獨立 PDF 密碼原生案例 12／12、
worker 839 passed／3 skipped、
backend 203 passed／1 skipped、frontend 39 passed；skip 均為 PostgreSQL opt-in。加密支援負面檢查 38 案與
最後 AES-128 原生重跑 1／1 亦通過，證據見 [本批紀錄](milestones/2026-10-18-pdf-password.json)。
PDF 密碼首批已取得使用者提供的 Job 切換與兩組原檔／解密子檔報告。
2026-10-19 四項回饋修正已完成本輪雲端人工驗收：新畫面、兩份完成 JSON 與使用者確認共同支持錯誤提示、逐檔三次及高風險呈現通過。
逐檔獨立及第三次限制依人工確認，沒有新增自動化雲端測試；最外層 ZIP 完整報告及 Pages deployment ID 未提供。
詳見 [本輪雲端驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)，其他部署可依 [Job→Worker→Pages 手冊](deploy-pdf-feedback.md)；
既有雲端驗收見 [P0 紀錄](milestones/2026-10-15-p0-acceptance.md)。

## 版本化樣本與驗收

[`worker/quality/corpus-v4.json`](../worker/quality/corpus-v4.json) 是目前一般基準，仍為 32 個案例，使用 `msrs-v1.2`。
固定 fixture bytes 與 v3 相同，本次更新子孫高風險下限相關預期，不重寫歷史 manifest。
加密 PDF 的預期改為等待密碼；其餘案例沿用已審查的行為。manifest 保存版本、每個 fixture 的 SHA-256、
生成方法、目前規則內容雜湊與案例預期。ZIP 的時間、來源權限、壓縮方法及 entry 順序固定；gzip 不寫入當前時間。
PE 與文件採有版本的生成配方，包含固定 headers、ZIP/XML 或 PDF 結構，不下載外部樣本。
fixture 的 bytes 或預期需要改變時，必須審查 diff 及更新版本，執行器不會自動接受新的雜湊。

第二批保留第一批 18 個案例並更新已變更的規則／評分預期，再新增 14 個案例：

| 類型 | 範圍 | 主要驗收 |
| --- | --- | --- |
| 正常內容 | 純文字、JSON 設定、一般網址、Java API 文件及合法程序 API 文件 | 成功的掃描、context 命中與風險命中分開檢查 |
| 測試／指標 | EICAR、PHP 字串指標、編碼 URL | 真實引擎命中、規則身份、來源與解碼證據；不執行樣本 |
| 子檔案 | 巢狀 ZIP、相同內容不同位置、ZIP／gzip 內的 EICAR | 每個 occurrence 保留身份；子檔案命中可回溯，繼承風險欄位一致 |
| PE 新增 3 案例 | 正常只讀結構、匯入／section／overlay 指標、截斷檔 | 核對 imports、headers、overlay、啟發式與 partial 原因；entry point 為零且沒有 executable section |
| 文件新增 9 案例 | 5 個 OOXML：正常、外部參照、VBA project 但無可解析來源、損壞、metadata 限制；4 個 PDF：正常、active actions、損壞、需密碼 | 核對實際頁數、XML target、巨集來源狀態、解析錯誤及受限原因 |
| Java 新增 2 案例 | 正常程序 API 文件、request＋程序執行指標 | 正常對照零 JSP 命中，指標對照保留 `jsp_webshell` 命中 |
| 失敗／限制 | 損壞 ZIP／PDF、ClamAV 缺失、YARA 空目錄／無效規則、去混淆檔案大小／候選數、深度限制 | 明確 partial、階段原因與保留證據，不能因 `infected=false` 或空命中就判定掃描成功 |

原始 [`corpus-v1.json`](../worker/quality/corpus-v1.json) 與第二批
[`corpus-v2.json`](../worker/quality/corpus-v2.json)、PDF 首批
[`corpus-v3.json`](../worker/quality/corpus-v3.json) 保留為歷史基準：固定輸入仍可重現，
舊規則／評分預期則需配合原版本使用，不應要求它在目前規則下原樣通過。
正常樣本仍可能觸發啟發式規則；基準通過代表宣告的行為與證據契約通過，沒有全面準確率保證。

## 本批修正的品質問題

第一批一般 HTTPS 網址命中 `network_iocs`，Java `getInputStream()` 文件命中 `jsp_webshell`。
規則集 `1.1.0` 保留前者的 native match 與位置，分類改為 context，不貢獻惡意風險；
後者需要 request 輸入與程序執行字串在 4,096 bytes 內共同出現，`ProcessBuilder` 分支也需要後續 start 字串。
這是有界字串共現，沒有 Java parser、taint flow 或執行證據；文件範例仍可能命中，其他語法也可能漏判。

新增正常 OOXML 對照曾只因內部 XML 的網址／domain 觀察累計到 31 分。
評分政策 `msrs-v1.1` 因此將原始 URL／domain／IP 及多類型 IOC 觀察維持零風險權重，
保留值、來源及 offset；具有額外結構或偵測證據的 findings 仍依其政策評分。
品質摘要分開列 `benign_cases_with_rule_hits`、`benign_cases_with_context_rule_hits` 與
`benign_cases_with_risk_rule_hits`，不把一般網址的 context 當作成功識別惡意程式。

真實正常 PE 對照揭露 `pefile.get_overlay()` 在沒有 overlay 時回傳 `None`，先前會使分析失敗；
目前正規化為零 bytes，正常結構保留 imports 與 headers，且不憑空產生 overlay 指標。
另外核對實際 100 MiB 大小限制的 sparse-file 測試；巨大輸入不放入小型 corpus。

文件對照修正 OOXML ZIP／XML 解析與範圍呈現：ZIP MIME 的 OOXML 仍交給 Office 分析，
relationship 依 XML 結構讀取，不把註解內範例當成外部 target；ZIP／XML 損壞、metadata 限制、
存在 VBA project 卻無可解析來源時，保留 partial 與原因。PDF 需非空密碼而無法存取內容時也為 partial，
保留 `encrypted`／`content_access=password_required`；這是第二批的歷史預期。
2026-10-18 新增的 PDF 密碼恢復會等待補交密碼，正確解鎖後建立另行掃描的子檔，
詳見 [PDF 密碼流程](pdf-password.md)。PDF 附件提取尚未提供。

## 已量測的前後差異

| 對照 | 修正前 | 本批結果 |
| --- | --- | --- |
| 一般網址文件 | 28 分／suspicious，`network_iocs` 加分 | 0 分／clean，規則仍命中，列為 context |
| Java API 文件 | 29 分／suspicious，`jsp_webshell` 命中 | 4 分／clean，不再命中 JSP 規則 |
| 正常 OOXML | 整合探測中為 31 分／suspicious | 4 分／clean，5 個 artifact 皆完整分析 |

前兩筆修正前值來自第一批紀錄；OOXML 的 31 分是本批調整 YARA 後、調整 IOC 計分前的本機整合探測，
不是先前雲端量測。PE 程序注入結構對照、Office 外部參照及 PDF active actions 仍為 84 分／suspicious，
直接 EICAR 為 100 分／malicious，ZIP／gzip 子檔命中仍繼承風險。
第二批加密 PDF 即使無命中且分數為零，靜態範圍仍為 partial，保留未取得內容的限制。
目前 v4 基準保留等待密碼要求，獨立的 PDF v2 套件再驗證補交、解密後完整掃描與逐層風險；零分仍不能取代 coverage。

## 執行完整本機基準

需要 Python 3.11、worker 的固定依賴、libmagic、實際 ClamAV scanner 與可用的病毒資料庫。
以本機 CLI scanner 為例，從 repository 的 `worker` 目錄執行：

```bash
YARA_RULES_PATH="$PWD/rules" \
CLAMAV_MODE=cli \
CLAMAV_DATABASE_PATH=/absolute/path/to/verified-clamav-databases \
SANDBOX_ENABLED=false \
poetry run python -m malscan_worker.quality \
  --manifest quality/corpus-v4.json \
  --jobs 1 \
  --output-dir /absolute/path/to/new-quality-run
```

沿用現有環境設定時，也可使用設定好的 ClamAV daemon。任一必要引擎不可用，正常案例會失敗；
失敗控制案例則實際使用不存在的執行檔、空規則目錄或語法錯誤規則，不以 mock 代替偵測器。
每個案例使用獨立 Python process、原檔及 checkpoint，避免故障控制汙染其他案例。
`--case CASE_ID` 可重複使用以定位失敗；部分選取不等於完整基準通過。
`--jobs 1` 為預設；`--jobs 2` 最多同時執行兩個獨立案例，可依 ClamAV 資料庫載入的記憶體需要選擇。

輸出目錄必須是新路徑。每個案例保留完整 report 與 runner log，根目錄的
`quality-report.json` 保存 corpus 版本、manifest／fixture／report 雜湊、耗時、
各案例 coverage／命中／失敗、已知限制與總結果。v2／v3／v4 核對 manifest 固定的規則內容雜湊，
並檢查報告中的指定結構欄位，不能以 parser 程序退出成功取代證據。
執行器核對執行前後的 manifest 身分與分析後原檔雜湊；程序退出碼 0 才表示所選案例皆通過。
這些案例只使用本機 stores，不呼叫 Cloud Run 或外部沙箱。

一般 worker CI 的 pytest 另外驗證固定樣本雜湊、原生 YARA 命中，以及能否拒絕
遺失階段、重複階段、錯誤來源身份、失敗掃描及互相矛盾的 report 欄位。
完整 ClamAV 容器基準與這些一般測試分開記錄。

## PDF 密碼流程的獨立驗收

[`pdf-password-v2.json`](../worker/quality/pdf-password-v2.json) 沿用 12 個真實加密 fixture（suite `pdf-password-v2.0.0`），
增加 `msrs-v1.2` 下每一層祖先的有效風險、本檔風險保存與身份核對預期；
舊 [`pdf-password-v1.json`](../worker/quality/pdf-password-v1.json) 與其歷史通過結果保留不變。
涵蓋 RC4-40、AES-128、AES-256 revision 5／6、空 user password、不同密碼 ZIP → PDF，
以及不由 catalog 引用的加密 stream。固定 bytes、大小與 SHA-256 可由標準函式庫重現。

每個需密碼案例核對 missing → wrong → correct、同一 artifact 的持久 checkpoint 恢復、
原檔 hash 不變、已完成 stages 不重跑、解密子檔的實際 AV／YARA 與適用階段、來源與 action 證據。
解密保存可讀的 active xref 物件，不只重寫 catalog 可到達的頁面；無法保存時保留 partial。
完成後再 resume 不新增第二個解密 occurrence，報告、持久 checkpoint 與日誌不能含測試密碼。
完整執行命令及資源／相容性邊界見 [PDF 密碼說明](pdf-password.md)。
這套原生測試與一般 32 案例分開記錄，不以一般 corpus 通過代替密碼恢復通過。

## PDF 正式回饋與風險呈現

收到的舊版完成 JSON 顯示：單一加密 PDF 本檔 4 分、聚合 29 分／低風險，解密子檔 84 分／高風險；
ZIP 內的加密 PDF 投影仍為 4 分，而解密子檔為 84 分。最外層 ZIP 完整報告未提供，不能推定 ZIP 總分。
新版政策 `msrs-v1.2` 保留 `risk.local_risk` 及來源樹 `local_score`，已驗證高風險子孫成為
PDF／ZIP 等祖先有效風險的下限；例如子檔 84 分時，包含它的祖先至少為 84 分，
不再因深度折減或未更新投影而顯示低風險。每份原始直接報告與證據仍保留，重複內容不重複計分。

高風險以紅色與文字來源提醒呈現；歷史報告由前端根據可核對身份的可見子檔提示，原始 JSON 不改寫。
此批固定 action PDF 的 84 分來自惰性 JavaScript／Launch／自動開啟結構，ClamAV／YARA 沒有命中，
不是已執行行為或已確認惡意。2026-10-19 新完成報告已核對直接上傳 PDF 與巢狀加密 PDF 子樹：
本檔分數保留為 4，有效風險及解密子檔均為 84／高風險，靜態範圍完成；兩個 PDF 節點各已用 2／剩餘 1。
父子檔的紅色呈現及逐檔獨立／三次限制另由使用者人工確認，不能從完成 JSON 反推每一步畫面或第三次拒絕。
外層 ZIP 完整報告沒有提供，不能推定其總分。

舊報告本檔 4 分來自弱 Base64 去混淆候選：一般 PDF token 的片段被解碼為
`/OpenActiok=`、`/JavaScrips=` 等字串。此批**沒有修改去混淆計分**，保留原始 4 分以供稽核；
高風險下限修正不能當成這項雜訊已解決。後續 Q-06 需加入正常 PDF token／Base64 對照，
區分可解碼片段與有意義內容，再以同批誤報／漏報證據決定調整。


## 子檔案與重複內容的證據

Portable runner 仍逐 occurrence 執行分析；自架版可能略過同一次提取中的相同內容派送。
每個來源位置都保留獨立節點，新的 `analysis_reference` 區分：

- `direct`：該節點的持久化報告與工作、SHA-256、大小及 root 身份相符；是否完成仍由 coverage 判斷。
- `inherited`：該 occurrence 沒有重新掃描；明確引用同 root、同 bytes、相同副檔名分析脈絡、已完成必要階段的直接來源。
- `unresolved`：缺少足夠的來源證據，維持 unknown／partial。

沿用節點的直接 `stage_coverage` 保持空白，來源階段在 `source_stage_coverage` 顯示。
`direct_finding_ids` 與 `inherited_finding_ids`、相應 evidence IDs 分開記錄。
來源未完成、缺少必要階段、identity 不符、跨 root 或循環引用都不能讓 duplicate 顯示完整分析。
這些引用在報告組裝時建立，不複製完整子報告，也不需要新增資料庫 migration。

父報告會彙整已驗證子檔案的 findings、IOC 與解碼證據。證據 ID 以 artifact 身份區隔，
避免不同檔案的 `ev-1` 相撞；來源 report 的直接評分證據不會因此被改寫或重複計分。
相同 bytes 的風險只計一次，選取最強、最近的有效 occurrence，不再受資料庫／提取排列順序影響。
報告保留所有 occurrence 的路徑，讓直接偵測與父檔繼承的風險可以分開查閱。

## 工具與規則內容

YARA 的引擎版本、規則集版本、規則內容 SHA-256 分開記錄。
[`worker/rules/manifest.json`](../worker/rules/manifest.json) 記錄目前 5 個檔案、15 條規則的
來源 commit、逐檔雜湊、規則分類及限制。`verified` 的範圍僅是本機檔案與原生解析出的
規則清單一致，不是作者身份簽章或準確率保證。

目前規則集版本為 `1.1.0`。repository 未提供可確認的規則授權，清單如實標為 `NOASSERTION`，不是授權許可。
外部規則來源、授權及更新／停用政策仍需在擴充規則前確認。
自訂規則目錄沒有 manifest 時仍會掃描，並明確顯示 unverified；規則語法錯誤或命名空間衝突則失敗。
EICAR 規則標為 test，`network_iocs` 為 context，其餘現有規則為 heuristic，
不將「高嚴重度」直接等同已確認惡意。

ClamAV 報告另外提供 `engine_version`、`database_version` 與 `database_timestamp`，
保留舊 `tool_version` 以相容既有報告。病毒庫所載時間不是線上更新檢查，也不保證當下最新。

## 後續擴充

前兩批品質變更已完成本機驗證與三份正式 demo 報告核對；PDF 密碼與回饋修正的本機回歸、
部署結果與 2026-10-19 雲端人工驗收分開記錄。病毒庫新鮮度、DO 清理、長期成本與真實回退仍獨立追蹤；新增工作的保留期尚未驗證。
下一批優先補 Q-06 的正常 PDF token／Base64 對照並處理本檔 4 分弱雜訊，再接續 F-02 Office 密碼。
後續增加具有來源與預期的 LNK、更多 Office／PDF 變種、文件附件，以及更大正常對照集。
增加規則或 parser 前，都應同時增加正常對照與失敗案例。
真實惡意樣本偵測率、所有格式相容性與動態沙箱仍需要各自的驗收，不包含在本批合成案例的結論內。
