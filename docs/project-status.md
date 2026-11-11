# 專案進度清單

更新日期：2026-11-12（Asia/Taipei）。這份清單集中記錄已完成、進行中與尚未完成的工作；
[路線圖](roadmap.md)說明排序，[支援矩陣](analysis-support.md)說明目前可用能力。
每一批開發、測試或部署都要更新相關 ID 的狀態、證據與剩餘條件。項目未取得完成條件的證據前，不標為完成。

狀態：**完成**表示列出的範圍已有驗證；**進行中**表示正在實作或僅有部分證據；
**待辦**表示尚未完成；**完成（程式／本機驗證）**只涵蓋已交付程式與本機測試；
**完成（限定案例）**依列出的本機／雲端人工證據結案，不擴張為所有格式或操作的完整保證。
完成一個基礎批次，不代表該格式、誤報問題或整個 P0 都已完成。

**F-11 已完成三個限定案例的雲端驗收；P0-12 已完成一次排程更新、中斷／重連復原及自動映像刪除的限定案例驗收，安裝、Monitoring 與受控告警也有使用者證據。最新 registry 缺席、GCS 建置來源到期、容量回收與成本仍待核對，維護待辦繼續追蹤。**

11/12 台北 00:23:06 使用者讀回已驗證的清理 checkpoint：`completed`、`candidate_count: 1`、`removed_count: 1`、`pending: null`。
選中與刪除皆為舊自動映像 `493fd6bd…bfc21c`；目前 `f4e433ab…f8cd68` 與回退 `4b81ba05…edc975` 保留。這是控制器保存的刪除與當時完整盤點讀回證據，接受本次自動清理案例；未另由 agent 查詢 provider。
清理計畫於台北 11/11 23:32:06 建立，該時間不是刪除完成時間。最新缺席、GCS 建置來源實際到期、儲存空間與帳單仍待驗證，見[清理驗收紀錄](milestones/2026-11-12-automatic-image-cleanup-acceptance.json)與[下一步只讀查詢](auto-update-recovery-rehearsal.md#7-確認本輪三個映像版本的最新存在狀態)。

11/9 接續環境恢復前的中斷演練工具草稿，補齊受控 parent 取消、未知回應讀回、同一候選接續與完整設定／日誌證據核對。
11/11 使用者已完成[演練手冊](auto-update-recovery-rehearsal.md)的自然更新受控中斷與接續：原 controller `d26087e7-fd27-480c-b419-52eb3c80e1a3` 已確認中斷，候選 `196af19d-17ac-49f3-a62f-0023d869356c` 沿用，由接續 controller `1f3aef61-b0df-4228-b97c-fe2b10d303f8` 完成。
結果為 `recovered`、`recovery_verified: true`、`candidate_build_reused: true`；發布 `db-20261111T152527Z-2fd604dfa556` 的映像為 `f4e433ab…f8cd68`，原目前版 `4b81ba05…edc975` 成為回退版。重連聲明保存於台北 23:30:36，通過核對保存於 23:37:35；兩者是紀錄時間，工具沒有查閱登入歷史，也不由此推定精確切換時間。
本次依使用者提供的工具摘要接受同候選中斷／重連復原，未新增 agent 直接登入 provider 的查詢。完整核對範圍與限制見[11/11 驗收紀錄](milestones/2026-11-11-automatic-update-recovery-acceptance.json)。後續清理交易已取得上述使用者讀回，實際容量回收與帳單仍待驗證；P0-12 維持進行中，P0-11 真實回退仍待辦。
本批新增 35 項離線演練測試，維運工具共 302 項通過，另略過一個選用 SDK 類別；見[本機交付紀錄](milestones/2026-11-09-automatic-update-recovery-rehearsal.json)。

P0-12 的[安裝與驗收手冊](automatic-database-updates.md)包含固定私有來源、generation 檢查點、失敗／缺心跳告警，以及只清理自動流程持有映像的保留限制。健康檢查每 12 小時進行，daily 達三天才建置，不執行分析 Job；初始安裝保持停用，GitHub 推送不啟用雲端排程。程式交付不代表實際排程、通知、儲存回收或帳單已驗證。
本批新增 107 項離線測試；維運工具共 197 項通過，另有一個選用真實 SDK 測試類別因環境未安裝而略過，見[本機交付紀錄](milestones/2026-11-04-automatic-database-updates.json)。
首次安裝的 `prepare` 已由使用者完成；`apply` 在第一個服務帳號建立受理後，因立即讀回未就緒而停止。
稍後帳號 metadata 已匹配預期；修補版加入有限次數的唯讀等待與操作名稱摘要，沿用原 plan，不重送建立。
該次帳號讀回修補交付時，完整安裝、排程與通知仍未驗收，見[安裝跟進](milestones/2026-11-04-automatic-update-installation-followup.json)。
後續使用者已取得 `installed_paused`、來源匹配且無 active／lease 的讀回；首次 probe 在容器啟動前因 PATH 找不到 Python 而失敗。
固定 SDK runtime／CA 路徑的修補已由使用者執行成功；新 probe `26b9ecd8-55e0-4025-bd0e-d7a66b60bfaf` 為 SUCCESS，
私有狀態回報 `paused_healthy`，健康時間為台北 11/4 15:22:21；目前／回退 digest 與先前一致，維護仍 disabled／idle。
停用安裝與首次健康檢查已通過；後續使用者已啟用排程，`ENABLED`／來源匹配／啟用後新心跳均有讀回，
健康時間為台北 11/4 16:45:18，`activation_heartbeat_verified: true`。該次只確認私有 checkpoint；11/5 使用者已提供完整只讀報告，`read_complete`、Monitoring 設定匹配與健康資料點入帳三項皆為 true。
兩個 log metrics、兩個 enabled alert policies 與通知管道 metadata 均匹配；健康 Build `565b3318-57d5-4b0d-b3fd-db06f003b041` 的正值資料點已讀回。
11/6 當時的發布簽章與排程更新已通過限定案例驗收；11/11 又完成上述同候選中斷／重連復原，11/12 讀回一次自動清理交易。保留期、容量回收與費用仍待驗證。
使用者已提交受控 Build `99db3d04-426e-4453-8cbf-a198b696a157`；原工具遇到合法的日誌分頁便中止，
已修正為有界追頁與提交時間範圍查詢，直接沿用原測試讀回。11/6 的使用者結果為 `failure_verified`、預期 `lease_owner_invalid`、兩個 marker 欄位皆 true，並明確確認收到告警信；此受控早停的通知鏈已通過。
後續私人摘要已為 `delivery_recorded`／`notification_delivery_verified: true`，人工確認保存於台北 11/6 12:27:38；這是保存確認的時間，並非實際收信時間。
使用者提供的同政策恢復通知畫面顯示失敗指標回到 0；只證明該告警事件回到門檻內，不代表已演練更新中斷復原或實際回退。
新目前映像 `493fd6bd…bfc21c` 已與 live Job 相符，原目前版 `4a018a2a…10b263` 成為回退版；`image_pointers_match_pre_submit: false` 的具體差異已知。
使用者於台北 11/6 13:03:26 讀回 `cloud_release_evidence_verified: true`：發布 `db-20261105T152451Z-88ed6053b825` 已 promoted，候選 Build `2f77a00d-44bf-4911-871f-8a0406ed4181` 成功，台北 11/5 23:25:03 至 23:27:33 完成。
daily 已由前一版 `28172` 更新至 `28174`（台北 11/5 14:26:24 建立），Build 完成時年齡 32,469 秒，低於兩天門檻；四項正常／EICAR 控制、三個簽章、builder／步驟／結果及 provider controls 與私人檢查點、live Job 完整設定均通過核對，見[簽章發布驗收](milestones/2026-11-06-signed-database-refresh-acceptance.json)。
台北 11/6 11:25:46 的健康狀態為 `healthy_no_update_due`，最新健康 Build 是 `78b18eed-a6bc-4d96-90be-da600b310d37`；此後續檢查不是先前更新的因果證據。見[11/6 限定驗收](milestones/2026-11-06-automatic-update-notification-acceptance.json)。
只讀工具的 `--current-release` 已取得上述使用者讀回，不重新建置或更新服務；該工具的 `cron_execution_not_classified: true` 保留為該次報告的範圍，不自動合併後續人工驗收。
後續三段查詢顯示：台北 11/5 23:23:03.416282 的 Scheduler `scheduledTime`、HTTP 200，以及同時段唯一 controller `32fc839a-aa93-4146-b6de-cb3dee8803c5` 成功；其建立時間距 `scheduledTime` 約 0.099 秒，執行窗 23:23:04–23:29:44 包含發布準備與已驗證候選建置，該發布已另讀回 promoted。
同時段人工 `RunJob` 稽核未觀察到紀錄，僅作輔助證據。上述證據交叉核對後接受為一次排程更新的限定案例；未取得直接 request ID 連結，也未額外重讀該 parent 的完整身分／來源與 `updated` marker，不擴張為完整因果追蹤。
只讀觀測工具的 27 項測試與通知工具的 25 項測試均通過，本批新增 13 項發布核對回歸；維運工具共 267 項測試通過，另有一個選用 SDK 測試類別略過。
見[觀測紀錄](milestones/2026-11-05-automatic-update-observability.json)與[通知測試交付紀錄](milestones/2026-11-05-automatic-update-notification-test.json)。
runtime 修補的本機與真實容器證據見[後續紀錄](milestones/2026-11-04-automatic-update-runtime-followup.json)。

2026-10-22 曾依使用者要求暫停功能開發與新增雲端掃描至 2026-11-01；10 月額度已有拒絕證據，
仍按 P0-08 的範圍記錄，不因此宣稱已查得管理端 counter。
10/22 的 SKU 報表已確認目前淨費用主要來自 Artifact Registry 映像儲存，Cloud Storage 另有讀寫、傳輸與儲存費用。
原始 CSV、精確金額與帳單資訊只保留在私人操作紀錄。已核對使用者提供的唯讀盤點：14 個映像版本、
沒有列出的讀取缺口，且目前正式 Job 與對應回退 checkpoint 匹配。
**第一批 7 個舊 `full-worker` Docker schema 2 manifest 清理已取得使用者執行結果並核對通過**：
`phase=completed`、無 pending、刪除完整 digest 與已審閱批次一致，版本數 14 → 7，沒有啟動掃描。
工具的前後引用核對保留目前版、必要回退版、全部 dispatcher 與整組 `engine-poc`（包含 index 的子 manifest）。
見[限定批次紀錄](milestones/2026-10-22-registry-cleanup.json)與[映像清理手冊](registry-cleanup.md)。
清理後倉庫容量讀數仍幾乎不變，尚未驗證實際容量回收或帳單節省；不能用版本數下降代替成本證據。
這是使用者提供的工具結果，沒有新增 agent 直接登入 provider 的獨立查詢。P0-07 與 P0-14 都維持進行中。

2026-11-01 00:00 UTC（台北時間 **08:00**）已越過月份邊界，但不能據此宣稱正式 counter 或病毒庫已更新。
使用者補上 11/2 UTC（台北 11/2 23:28、23:42 開始）的兩份新報告：Office 8 節點、PDF 2 節點，
輸入與子檔 occurrence 的報告身份／來源皆符合固定 fixture；**10 個節點的 ClamAV 全因 daily 過期失敗**。
兩份 `job_status=done`／`report_complete=true` 仍是 `batch_analysis.status=partial`，不當成完整靜態分析。
PDF 已取出 68-byte EICAR 附件並命中 YARA，但子檔僅有 generic YARA 25 分，父檔繼承 6 分；
不能為讓測試變紅而人工提高分數，也不能把失敗階段的 `infected=false` 當成防毒陰性。
見[本輪跟進紀錄](milestones/2026-11-03-document-embedded-cloud-followup.json)。
上述 11/2 partial 報告保留為歷史；七天新鮮度檢查維持啟用，這次未透過加分或放寬 gate 通過驗收。
11/4 使用者補上新 root 報告並確認介面修正：EICAR PDF 父子檔各 100 分、Office 根檔 0 分，10 個節點的 ClamAV／YARA 皆完成，兩份 static／batch 皆 complete。
長 URL／路徑在卡片內換行已由使用者聲明及截圖佐證；本輪沒有 Pages revision／部署 ID 的獨立查詢。
11/3 的使用者維護輸出已證明候選建置與離線正常／EICAR 控制成功；daily 28172、三份官方簽章通過。
當時更新後 Job 已 Ready、image 等於候選，但因執行範本 `client-version` 註記差異而停在 `promotion_pending`；
維護工具已補精確路徑比較與[既有 state 接續流程](deploy-report-followup.md#31-已套用候選映像卻停在-promotion_pending)。
本輪新報告的 ClamAV 確實使用 daily 28172 並完成掃描，足以結束限定案例的功能驗收；
未補上修正後 `promoted` 輸出或每次 execution 的 provider image 查核，不由報告推定這些管理端證據已取得。
完整新紀錄見[11/4 雲端驗收](milestones/2026-11-04-document-embedded-cloud-acceptance.json)；自動更新與成本／保留期不在此項結案範圍。

本批 F-03 已完成程式／本機驗證，涵蓋 PDF 附件／Office 嵌入物件：從宣告的 PDF filespec／stream、
OOXML member／relationship 與 OLE Package 取得實際 bytes，建立來源與子檔後進入共用靜態掃描。
同一來源的 aliases 與不同 occurrence 分開處理；不支援、損壞、超限或提交失敗保留 partial。
能力邊界見[文件附件說明](document-embedded.md)，更新操作見[Job 部署手冊](deploy-document-embedded.md)。
F-03 的程式／本機結果與 **F-11 正式雲端 smoke（完成，限定 3／3 案例）**分開結案，不使用其他 Office／PDF 報告代替。
已核對使用者提供的 Job 建置／映像切換與 PDF 文字附件報告：2 節點／0 分、實際報告身份／來源與子檔掃描符合固定預期，提取 1 檔／41 bytes。
10 月 EICAR 曾被公司端防毒阻擋轉移、Office 曾遭月額度拒絕；11/2 的兩案已取得新掃描報告，
當時提取身份符合預期，但所有節點的 AV 因病毒庫過期失敗。更新後，11/4 的新兩案皆完成適用掃描，F-11 累計 3／3 通過。
歷史證據見[10 月紀錄](milestones/2026-10-20-document-embedded-cloud-acceptance.json)與[11/3 跟進](milestones/2026-11-03-document-embedded-cloud-followup.json)，
本輪證據見[11/4 驗收](milestones/2026-11-04-document-embedded-cloud-acceptance.json)；
未獨立讀取雲端物件 bytes、每次 execution 映像、實際 counter 或保留期。
DO 清理、真實回退、自動病毒庫更新及成本維護照原 ID 追蹤。

本批 F-02 已完成 Office 密碼恢復的程式與本機驗證；Office 14／14、一般 40／40、PDF 12／12 原生案例通過，見[本批紀錄](milestones/2026-10-19-office-password.json)。固定 `office-password-v1.json` 為 14 個 profile，
包含 Agile AES-256、Standard AES-128、六種常見 OOXML 副檔名、外部範本、不同密碼 ZIP、
雙 Office sibling、第二組 Office 密碼與損壞／不支援對照。這是固定驗收範圍，不代表全部可接受 header 都已逐一原生驗證。
密碼續跑保留明文套件 bytes、原 artifact／checkpoint／累計預算，子檔進入共用掃描；
既有逐檔三次與錯誤回饋契約沿用。正式 Office smoke **F-10 完成（限定案例）**。
2026-10-20 已核對使用者提供的 Job 映像切換、正式 Pages 發布輸出、錯誤提示畫面與五份報告，
涵蓋三個宣告的 smoke 案例：一般 DOCX 根報告 8 節點／0 分、外部範本根報告 10 節點／父檔 15 分、
解密子檔 53 分，以及不同密碼 ZIP→Office 根報告 9 節點／6 分；另有兩份 8 節點 Office 詳細子樹。
五份報告各自宣告範圍的靜態分析皆完成，最終 ZIP root 與本輪對應 Office 子樹的身份／來源一致。
先前三份 Office 報告各已用 1／剩餘 2／上限 3；本輪 Office 錯誤紅字與 1／2 有畫面，
ZIP 已用 1 時 Office 初始仍為 0／3 依使用者人工確認。最新 ZIP 根 JSON 記錄 ZIP 已用 1／剩餘 2、
Office 已用 2／剩餘 1、工作及靜態分析完成，累計提取 8 檔／19,196 bytes，與固定樣本預期相符。
見[Office 雲端驗收紀錄](milestones/2026-10-20-office-cloud-acceptance.json)；沒有新增 agent-run 雲端掃描或獨立的每次 execution 映像／物件 bytes 查詢。
Office 三次耗盡及其他 Office 格式未在本輪雲端演練，各 root 私有 status／保留期及清理仍列 P0-18，
DO 清理、成本、真實回退及自動病毒庫更新維持原狀。F-03 PDF 附件與 Office 嵌入物件本機交付完成；正式驗收 F-11 已完成限定 3／3 案例。
2026-10-19 本機開發批次後端 233、前端 54 項通過；worker 完整回歸為 1,202 通過、3 項 PostgreSQL opt-in 跳過，
一項新增測試的 fixture 密碼預期修正後，所屬 3 項續跑測試補驗通過，共 1,203 個不同測試已有通過證據。
上述本機完整執行及補驗分開記錄；Ruff、strict mypy、lock、前端型別／lint／build 均通過。
2026-10-20 另查核 `4a81bfd` 的 Serverless、Frontend、Backend 三組 GitHub CI 全部成功，與先前本機執行紀錄分開保存。
見 [Office 密碼說明](office-password.md)及[部署手冊](deploy-office-password.md)。

本批 Q-06 PDF／Base64 雜訊修正已完成程式與本機驗證：一般 v5 原生 40／40、PDF 密碼 v2 12／12，
worker 930 passed／4 skipped，另以既有工具 PATH 補驗 7z 一案通過，剩三項 PostgreSQL opt-in 未執行。
Ruff 與 strict mypy 通過；沒有重新執行未變更的 frontend／backend 套件，不沿用舊數字充作本批結果。
弱候選保留為零分觀察；有效解碼繼續分析，高風險 PDF 對照仍為 84。使用者提供的正式 Job 建置／切換輸出，
與三份新報告已核對：0／29／84 分、靜態皆 complete，版本與固定輸入身份相符。
這是使用者提供的雲端 smoke 證據，不是新增 agent-run 自動化 provider 測試；每個 execution 的映像未獨立查詢。
見[本機證據](milestones/2026-10-19-base64-quality.json)、[雲端驗收](milestones/2026-10-19-base64-cloud-acceptance.json)
及 [Job 更新手冊](deploy-base64-quality.md)。
Q-06 整體仍為進行中；本批完成不關閉下列維護待辦。

目前 P1 兩批品質改進已通過本機驗證。使用者貼回的映像切換與 Pages 發布結果，以及三份正式 demo
報告已核對：正常 Office、PDF action、加密 PDF 的大小、雜湊、規則、評分政策與 coverage 符合預期。
這三份報告不是新的 GCP 管理端、費用或到期清理證據。
**2026-10-19 PDF 回饋修正的雲端人工驗收已通過（F-08）**：使用者確認錯誤提示、逐檔三次與父子檔高風險顯示通過，
附圖顯示首次錯誤後紅字及已用 1／剩餘 2；新 JSON 證明直接 PDF 根報告與 ZIP 內 PDF 子樹均為本檔 4／整體 84，
政策 `msrs-v1.2`、逐檔上限 3 且分析完成。外層 ZIP 完整報告未附上；次數獨立與第三次限制依使用者人工聲明記錄，
不是新增自動化雲端測試。Pages deployment ID 未單獨蒐集，更新後畫面以使用者聲明與截圖佐證。
`F-09`、`Q-08`、`UX-06`、`UX-07` 的這批限定案例一併完成驗收，詳見
[雲端人工驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)。
DO 清理、真實回退、自動病毒庫與長期成本仍待辦；新工作到期清理另列 P0-18，不因功能驗收而結案。
以下為這批程式的既有本機結果，不把人工驗收計為新增自動測試：
worker 852、backend 233、frontend 52、控制層 25 項通過；四項 PostgreSQL opt-in 與一項既有完整 Python fixture 跳過。
PDF 原生 12／12 通過；一般 32 份原生報告以修正後 manifest 重新核對通過，沒有重跑偵測器，
初次 manifest 的舊政策斷言及失敗彙總保留，詳見 [本批紀錄](milestones/2026-10-18-pdf-feedback.json)。
本表共 50 個固定 ID，本批新增 F-11 追蹤文件附件正式雲端 smoke；P0-19 繼續追蹤使用者回報的安全通知，
每完成一項即更新其證據與剩餘條件，並在該批交付訊息明列。

## 清理、回退與病毒庫更新是什麼

**到期清理**是在保留時間結束後刪除測試資料。R2 像檔案櫃，保存上傳檔、報告與 checkpoint；
Durable Object（DO）像工作登記簿，另存工作、票證與派送狀態。四筆舊驗收的指定 R2 檔案已確認不存在，
但不能因此認定 DO 登記也已刪除。API 回傳 404 只代表目前不能透過該 API 取得資料，不能單獨證明底層已刪除。
後續每批新增工作的到期清理仍要各自核對。

**回退**是在新版程式出問題時，把雲端 Job 切回先前已驗證的映像版本，例如新版無法產生報告時恢復舊版。
目前有保存版本與受保護的回退工具，也通過本機測試；還沒有在真實雲端演練「切回舊版、驗證可用、再恢復指定版」。
回退程式不會找回已到期刪除的檔案，也不等於還原資料庫。

**自動病毒庫更新**是定期下載官方病毒庫、驗證簽章、掃描正常／EICAR 控制樣本、建置並驗證新映像後，
才更新雲端 Job；失敗時保留可用版本並留下通知。目前人工流程已有證據；本批自動控制器與安裝工具已交付，正式排程仍待安裝、啟用及雲端驗收。
雲端每次掃描不下載病毒庫，七天新鮮度檢查只會阻擋過舊資料庫，不能代替自動更新。

## P0：雲端驗收與持續維護

| ID | 狀態 | 項目與已取得證據 | 完成條件／仍需補齊 |
| --- | --- | --- | --- |
| P0-01 | 完成 | 正式 API 巢狀 ZIP、不同密碼 ZIP／7z、錯誤後正確密碼續跑；子檔與累計預算已核對 | 限 [P0 驗收](milestones/2026-10-15-p0-acceptance.md)所列格式與案例；更多變種見 F-04 |
| P0-02 | 完成 | 正式 20,000,000-byte 檔案大小／雜湊及適用掃描、超限 metadata 拒絕 | 20 MB 去混淆受 10 MB 上限限制，預期為 partial；未宣稱所有階段完成 |
| P0-03 | 完成 | 已用 ticket 重放遭拒、錯誤 owner 無法讀取工作 | 這些負面案例已驗證；其他不確定派送情況見 P0-04 |
| P0-04 | 進行中 | client 保存 POST 意圖、可重連查詢，已有密碼恢復與執行關聯證據 | 補齊刷新／斷線／不確定派送的端到端證據，核對沒有未授權的額外 execution |
| P0-05 | 完成 | 四筆早期驗收工作的 28 個 R2 指定前綴皆空，工作／報告 API 到期撤權 | 限列出的前綴與觀察時點；不是整個 bucket 或之後新工作的清理證明 |
| P0-06 | 待辦 | **DO 工作狀態實體清理**尚未取得管理端證據 | 核對到期工作資料列／相關狀態實際刪除，與 R2 檔案清理分開驗證 |
| P0-07 | 進行中 | **保留政策與映像盤點**：首批 7 個舊 `full-worker` 清理已核對 completed／無 pending、版本數 14 → 7，見[10/22 批次](milestones/2026-10-22-registry-cleanup.json)。11/12 另讀回自動流程刪除 1 個已登記舊版的 completed checkpoint，目前／回退版保留，見[本次紀錄](milestones/2026-11-12-automatic-image-cleanup-acceptance.json) | 已接受列出批次的版本刪除；最新缺席、實際容量回收、長期保留運作、R2 lifecycle 與 GCP 建置來源設定／實際到期仍待核對。持續保留現行參照、必要回退映像及完整 index 依賴 |
| P0-08 | 進行中 | 日／月 execution 額度已有程式與設定；本輪取得正式月額度拒絕畫面，Office root 顯示 failed／execution_admission_limit，見[部分驗收](milestones/2026-10-20-document-embedded-cloud-acceptance.json) | 尚需每日限額、實際 counter、密碼續跑／不確定派送計數與 provider 證據；截圖不能單獨證明確實用滿預設 40 次。全站共用 UTC 月份，換裝置或隔天不重置 |
| P0-09 | 完成 | **人工簽章病毒庫更新與映像切換**：官方簽章、正常／EICAR 離線控制、digest、Job 與執行映像已核對 | 按時持續維護；此項完成不代表已有自動排程 |
| P0-10 | 完成 | **回退工具與本機測試**：保留舊映像／設定，受保護的 image-only 切換與檢查 | 工具交付完成；真實雲端回退是獨立的 P0-11 |
| P0-11 | 待辦 | **真實雲端回退演練**尚未執行 | 在受控時段切回已驗證映像、核對設定與掃描，再恢復指定版並留證據 |
| P0-12 | 進行中 | **自動官方簽章病毒庫更新**：固定來源控制器、私人 generation 檢查點、失敗／缺心跳告警、限定自動映像清理與分階段安裝工具；每 12 小時檢查、daily 達三天才建置，每 UTC 日／月最多 1／12 次新候選意圖、自動持有版本上限四個，不執行分析 Job；見[安裝手冊](automatic-database-updates.md) | 停用安裝、runtime 修補、啟用心跳、Monitoring、受控告警收信及一次排程更新已通過限定驗收。11/11 另取得[同候選復原](milestones/2026-11-11-automatic-update-recovery-acceptance.json)，11/12 讀回[一次自動刪除交易](milestones/2026-11-12-automatic-image-cleanup-acceptance.json)。最新 registry 缺席、GCS 建置來源實際到期、容量回收與費用仍待驗證；排程已啟用；真實映像回退另列 P0-11 |
| P0-13 | 完成 | 一份月內 TWD 專案帳單已核對歸屬，費用極低但非精確零 | 僅該報表期間；不是最終月結或長期免費承諾，原始財務資料保持私有 |
| P0-14 | 進行中 | **長期成本與儲存費控制**：10/22 SKU 報表已確認映像儲存為當期主要淨費用；首批 7 個舊 `full-worker` 清理結果已核對，但倉庫容量讀數仍幾乎不變，原始財務資料不公開 | 容量回收及後續儲存 SKU／帳單節省仍未驗證；補齊每次工作／每月維護、建置來源、映像、儲存、日誌、secrets、抵用額種類及最終月結，觀察多個期間；版本數或映像顯示大小加總不能代替成本證據，不宣稱零費用 |
| P0-15 | 待辦 | Cloudflare 實際用量與費用仍待獨立核對 | 核對 Workers／DO／R2／Pages 用量及可用額度，連同 GCP 判斷成本 |
| P0-16 | 完成 | 共用核心、前端、控制層與 dispatcher 的持續整合已建立並執行 | 新改動持續通過相關 CI；不等於正式 provider 驗收 |
| P0-17 | 待辦 | 仍有 advisory 的開發／部署相依工具需持續審查 | 依影響做相容升級，保存 audit 差異與回歸結果，不直接強制升級所有套件 |
| P0-18 | 待辦 | 第二批三筆正式 demo 工作、前後兩批 PDF 密碼工作與前次兩個 PDF root 與本次三個 Base64 smoke root 及本輪 Office smoke 工作的到期清理尚未核對 | 每批／每個 root 到期後分別檢查指定 R2 前綴與存取撤回；Office root 的 status／retention_expires_at 尚未提供，包含本輪新增 ZIP root `94d643f0-0f74-45a6-9d3c-2f8dc16d8653`，不從完成報告推算；F-11 的文字附件 root `57dd5d67-9941-49d4-9692-7586e9ab3c39`、拒絕 root `0f2e9ed9-9504-4628-af8d-deb91e8cdc3c`，及 11 月新 root `d7979017-8a36-4668-9418-e910e697daa3`／`15bdb16d-a8a6-422d-bdc2-a05d597841c1`，以及 11/4 新驗收 root `04f8568f-a775-453b-b205-b055e78a8f4a`／`6434b517-4659-459e-b2cd-aa8b369cb174` 也未提供私有 status／retention_expires_at；不從報告時間推算，完成、失敗或 partial 都不等於物件已刪除。不能沿用四筆早期驗收的結果，DO 清理仍另列 P0-06 |
| P0-19 | 進行中 | **GitGuardian 通知核對**：已將 `95396c1`／PDF acceptance 第 172 行精確定位為合成 fixture profile，屬非憑證資料誤報，見[核對紀錄](security-notes.md) | 程式碼分類完成；GitGuardian 平台單筆 False positive 標記尚未操作。其他通知仍逐筆審查；真實憑證另須撤銷／輪替，不能以 Gitleaks 零發現取代核對 |

## P1：靜態證據、規則與品質

| ID | 狀態 | 項目與已取得證據 | 完成條件／仍需補齊 |
| --- | --- | --- | --- |
| Q-01 | 完成 | 第一批 18 案例、子檔證據、同 root 重複內容引用、風險一致性、工具／規則版本呈現 | [第一批紀錄](milestones/2026-10-16-static-quality.json)限定的基準；未宣稱所有格式已完整 |
| Q-02 | 完成 | 第二批 32 案例／28 fixture，含 3 PE、9 Office／PDF、2 Java 新對照；32／32 原生案例通過 | [第二批紀錄](milestones/2026-10-17-static-quality.json)與[品質基準](static-quality.md)所列範圍 |
| Q-03 | 完成 | 已量測的網址／Java API／正常 OOXML 風險誤報調整；context、原始 IOC 與風險偵測分開 | 規則 `1.1.0`、評分 `msrs-v1.1`；一般觀察保留證據而不單獨加分，其他誤報見 Q-06 |
| Q-04 | 完成 | 兩批品質變更的 worker／Pages 部署與三份正式 demo 報告核對 | 使用者部署輸出與報告證據；這三個新工作的到期清理、帳單不是此項結論 |
| Q-05 | 進行中 | YARA 來源、分類、逐檔雜湊、版本及限制已有 manifest | 規則授權仍為 `NOASSERTION`；擴充前補齊可確認的授權、來源及更新／停用政策 |
| Q-06 | 進行中 | **更多格式品質與雜訊改善**：PDF 名稱／弱 Base64 批次本機 40／40＋PDF v2 12／12；Job 切換及三份雲端報告 0／29／84 分已核對。11/4 正常 Office 的三個 XML 子檔仍各有弱 XOR 觀察 +4 分 | [既有雲端驗收](milestones/2026-10-19-base64-cloud-acceptance.json)限三個固定案例；Office XML 雜訊另需正常／有效 XOR 對照，與 YARA 零分 context 分開處理。其他格式與真實來源樣本仍待擴充，合成對照不能估計真實準確率；新工作的保留期另列 P0-18 |
| Q-07 | 待辦 | 更大 corpus 的時間／記憶體與資料回退比較 | 固定輸入、工具／規則版本與執行條件，核對 coverage、證據及性能變化 |
| Q-08 | 完成（限定案例） | **解密子檔風險逐層回傳**：`msrs-v1.2` 保留本檔分數，已驗證高風險子孫作為有效風險下限 | 本機 v4／PDF v2 與回歸通過；[雲端人工驗收](milestones/2026-10-19-pdf-feedback-acceptance.json)的直接根／內層 PDF 子樹皆本檔 4、整體 84，外層 ZIP 顯示依使用者聲明；限所列案例 |

## P1：格式深度、密碼與子檔

| ID | 狀態 | 項目與已取得證據 | 完成條件／仍需補齊 |
| --- | --- | --- | --- |
| F-01 | 完成（限定格式／案例） | **PDF 使用者密碼恢復**：RC4／AES、缺密碼→錯誤→正確、原檔與解密子檔、持久 checkpoint 與累計預算已有本機驗證；直接 AES-128 與 ZIP 內 AES-128 已由使用者完成人工 smoke | 本機格式範圍見 [原生紀錄](milestones/2026-10-18-pdf-password.json)，雲端限定案例見 F-08；不支援 crypt filter 保留 partial，不代表所有 PDF 變種均已正式測試 |
| F-02 | 完成（程式／本機驗證） | **Office 使用者密碼解密／恢復**：現代 OOXML、原始明文 bytes 子檔、共用掃描、既有密碼／checkpoint／預算契約；固定 suite 14 個 profile | [本批紀錄](milestones/2026-10-19-office-password.json)：Office 14／14、一般 40／40、PDF 12／12 原生案例，另有 57 組真實加密演算法測試。完整掃描固定案例與演算法單元覆蓋分開記錄。正式雲端另列 F-10；舊式 DOC／XLS／PPT 加密、IRM 不支援，詳見 [能力邊界](office-password.md) |
| F-03 | 完成（程式／本機驗證） | **PDF 附件提取與 Office 嵌入物件深化**：宣告 PDF 附件位置、有界解碼、OOXML member／內部 relationship、OLE native／Package payload 與來源子檔整合 | [本批紀錄](milestones/2026-10-20-document-embedded.json)：附件原生 12／12、worker 1,379 通過／3 PostgreSQL opt-in 跳過；PDF 密碼 12／12、Office 密碼 14／14，更多回歸範圍見紀錄。來源、實際 bytes／hash、掃描、密碼及逐 occurrence 預算已核對，範圍見[能力邊界](document-embedded.md)；正式雲端另列 F-11 |
| F-04 | 進行中 | ZIP／7z 巢狀、不同密碼、同名 entries 與 budget 已有案例 | 補更多損壞／深度／加密變種與 RAR 外部解壓器相容性，未知／缺工具有明確原因 |
| F-05 | 待辦 | **PE／LNK／scripts 深度分析**；已有基礎 PE 結構及腳本啟發式 | 增加資源、overlay、捷徑與去混淆衍生檔的正常／異常對照、來源與限制，樣本不執行 |
| F-06 | 待辦 | 郵件、ELF／Mach-O、ISO、APK 等專用能力 | 按需求逐格式定義 parser／extractor、資源邊界與成功／失敗案例；現有通用掃描不等於完整支援 |
| F-07 | 待辦 | 大檔去混淆處理與限制評估 | 以實測決定 streaming／分段或維持限制；不為了通過 20 MB 驗收直接放寬安全上限 |
| F-08 | 完成（限定案例） | **PDF 回饋修正正式 demo 人工驗收**：先前 Job／Worker 發布輸出，加上新畫面、兩份新 JSON 與使用者明確人工通過聲明 | [驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)：錯誤紅字、逐檔三次、父子檔高風險；兩個 PDF 報告可獨立核對，外層 ZIP／第三次限制為人工聲明；Pages ID 未單獨蒐集；到期清理、費用與維護不在此項結案範圍 |
| F-09 | 完成（限定案例） | **每個加密檔案獨立三次補交**：接受派送的正確與錯誤密碼均計本檔；本機 workerd／SQLite、持久化與耗盡後其他節點續跑已有測試 | 新 JSON 各自 PDF 已用 2／剩餘 1／上限 3；ZIP 不扣內層 PDF 及第三次限制依使用者人工通過聲明記錄，完成 JSON 不能重播該歷史；見 [F-08 紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json) |
| F-10 | 完成（限定案例） | **Office 密碼正式 demo smoke**：Job／Pages 發布、三個宣告案例的完整根報告（正常 DOCX 8 節點／0 分、外部範本 DOCX 10 節點／父檔 15 分與子檔 53 分、不同密碼 ZIP→Office 9 節點／6 分），加上兩份 Office 詳細子樹、錯誤紅字畫面與逐檔初始次數的人工確認已核對 | [Office 雲端驗收紀錄](milestones/2026-10-20-office-cloud-acceptance.json)限所列 DOCX／ZIP 案例：最終 ZIP 1／2、Office 2／1、累計提取 8 檔／19,196 bytes，身份、明文 hash、來源與適用掃描符合固定預期。Office 三次耗盡及其他格式未在本輪雲端演練；各 root 的 status／保留期／清理另追 P0-18，每次 execution 映像與物件 bytes 未獨立查詢 |
| F-11 | 完成（限定案例，3／3 通過） | **PDF 附件／Office 嵌入檔正式 demo smoke**：歷史文字附件加上 11/4 新 Flate EICAR 與 Office 嵌入 PDF，三個宣告案例通過。新 PDF 2 節點／父子各 100 分、68-byte EICAR 子檔實際 AV／YARA 命中；Office 8 節點／根檔 0 分、7 次提取／2,226 bytes，10 個新節點的適用掃描皆完整 | [11/4 驗收紀錄](milestones/2026-11-04-document-embedded-cloud-acceptance.json)：固定輸入及 occurrence 身份／來源、daily 28172、static／batch complete 已核對。限所列案例，不代表所有 PDF／Office 變種；每次 execution 映像、物件 bytes 與修正後 promoted state 未獨立查詢，新 root 保留期仍追 P0-18 |

## P2：效能、狀態與報告體驗

| ID | 狀態 | 項目與已取得證據 | 完成條件／仍需補齊 |
| --- | --- | --- | --- |
| UX-01 | 待辦 | 上傳／派送／容器啟動／掃描／保存的分段時間 | 可核對時間點、cold／後續執行與少量可比較基準；既有單次 3 分 58 秒不是 SLO |
| UX-02 | 待辦 | **排隊狀態細分** | 依可取得證據區分準備／分析／保存，刷新與不確定結果保留實意，不顯示虛構百分比 |
| UX-03 | 待辦 | Python import、AV 載庫、YARA compile、R2 發布與 polling 主要瓶頸 | 同輸入比較時間、記憶體與費用，再選擇優化，持續通過恢復與品質驗收 |
| UX-04 | 待辦 | 執行資源／常駐引擎等效能方案的成本比較 | 有前後量測與成本依據，不以增加資源直接取代分析 |
| UX-05 | 進行中 | 摘要、來源樹、證據／版本、partial 原因與 JSON 下載已有介面；本批長 URL／路徑換行修正已由使用者確認，截圖顯示 Office 證據卡片內容未越界 | 本機前端 62 項測試、型別／lint／cloud-demo 打包及 Chromium 18 組寬度驗證通過，JSON 下載內容不變；[11/4 紀錄](milestones/2026-11-04-document-embedded-cloud-acceptance.json)記錄換行人工驗收。Pages revision 未單獨取得，partial 提示正式人工過程、大型 artifact tree 與其他等候狀態仍需可用性驗收 |
| UX-06 | 完成（限定案例） | **錯誤密碼明確提示**：目前 artifact 顯示紅色錯誤、檔案路徑與剩餘次數，保留既有成果 | UI／transport 回歸通過；使用者截圖直接顯示「密碼不正確」、已用 1／剩餘 2，並確認人工驗收通過；新完成報告記錄已用 2；見 F-08 |
| UX-07 | 完成（限定案例） | **高風險報告與節點醒目呈現**：紅色摘要／來源節點與來源說明，本檔與包含子檔的有效風險分開 | 前端 52／52；新報告直接根／內層 PDF 子樹皆本檔 4／整體 84，使用者確認父子檔紅色顯示通過；高風險不等於已確認惡意；見 F-08 |

## P3：自架動態分析

| ID | 狀態 | 項目與已取得證據 | 完成條件／仍需補齊 |
| --- | --- | --- | --- |
| D-01 | 完成 | 配置後的啟用腳本、CAPE API preflight、獨立 worker 與本機 HTTP 串接／恢復測試 | 限工具與本機測試；腳本不安裝 CAPE、建立 VM 或驗證 guest snapshot |
| D-02 | 待辦 | **真實 CAPE／guest 驗收**，需部署者提供伺服器與隔離基礎設施 | 一個命令啟用後驗證 guest、detonation、靜態＋真實動態報告與失敗狀態 |
| D-03 | 待辦 | 真實 task ID、重啟 polling、不確定提交與 provider 失敗恢復 | 不盲目重送、不以 mock 代替真實結果；可讀既有靜態成果 |
| D-04 | 待辦 | process／file／registry／network、截圖／PCAP 產物整合 | 真實來源、下載權限、完整度及同一工作關聯可核對 |
| D-05 | 待辦 | 多 task 聚合、動態掉落檔回送靜態、artifact／guest policy | 前述實機驗收後再實作並加入邊界與失敗測試 |

後續批次應引用上述 ID，例如 `F-01` 完成時記錄測試、適用加密方式及部署狀態；
`P0-06`、`P0-11`、`P0-12`、`P0-14` 不會因新的格式功能完成而自動結案。
