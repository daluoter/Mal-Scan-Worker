# P0：正式 v2 驗收與維護工具

日期：2026-10-15（Asia/Taipei）。延續[首筆良性檔里程碑](2026-10-15-cloud-demo.md)，本輪直接透過正式 Worker API 驗證三個工作，並新增可持續維護的工具。可機讀的允許欄位證據見 [JSON 紀錄](2026-10-15-p0-acceptance.json)，不含 ticket、owner capability 或正式憑證。

## 正式 API 結果

| 案例 | 工作 ID | 結果 |
| --- | --- | --- |
| 重複內容、不同路徑的 ZIP → ZIP → 文字檔 | `6a0910bf-ed13-4de9-b6bf-e0d7ff9cd2a0` | 5 個節點、4 files／368 bytes 提取預算；static complete |
| AES ZIP → 不同密碼、加密標頭 7z → 文字檔 | `04cfe4ec-4f30-4ad9-9b1b-d2dc8f0f3687` | 初次等待、錯誤外層、正確外層、正確內層；3 個節點，static complete |
| 20,000,000-byte 文字檔 | `192e3653-2995-4b10-b9fe-e34a1d453dfe` | 大小／SHA256、ClamAV／YARA／IOC 通過；static partial，保留去混淆大小限制 |

三份最終報告均為 `job_status=done`、`report_complete=true`，動態分析明確 disabled。這些欄位與 static coverage 分開看待；20 MB 案例不宣稱所有靜態階段完整完成。

密碼案例保存每個階段的 immutable report snapshot，核對 root attempt 一致、累計提取不減少、完成的必要 stages 時間戳不變，並在最後使用滿三次補交額度。兩種壓縮格式都由正式已部署映像處理；本機 reducer／stub 不作這份遠端證據。

同輪負面檢查：

- 20,000,001-byte 票證 metadata 回傳 400／`invalid_upload_metadata`，未傳送超限檔案。
- 錯誤 owner capability 回傳 404／`job_not_found`。
- 已消耗 ticket 在原有效期內回傳 409／`upload_credential_used`，重放僅送 1 byte。

Client 共建立 3 個工作，取得 6 次原始上傳／密碼續跑的接受回覆；對 replay 另保守記錄一個可能執行意圖，因此 journal 為 7。這不是從 GCP 控制面取得的實際 execution 計數；額外執行與帳單仍需獨立 metadata／用量證據。

## 20 MB 發現的實際限制

目前 `DEOBFUSCATION_MAX_FILE_SIZE=10000000` bytes。20 MB 報告的去混淆階段以
`File too large for deobfuscation (20000000 bytes)` 略過，static 明確為 partial；其餘必要掃描正常。
驗收工具只接受這個已宣告的大小限制，不放過其他工具失敗、缺少階段或無法解釋的 skipped。

後續可依實測評估大檔去混淆的 streaming／分段處理與資源預算；本輪保留既有防護及真實 coverage，沒有為了驗收直接放寬上限。

## 維護交付與本機驗證

- 可續跑 client：每次 POST 前保存私有意圖、ticket 與 capability，不自動重送；重新連線先 GET 既有工作。
- `maintain-demo.py`：保存現行映像／設定、唯一非同步 build、候選 digest／離線控制驗證、image-only promotion 及受保護 rollback。
- Cloud Build `engine-controls`：非 root、network none、唯讀 root filesystem 驗證三份官方簽章、daily freshness、ClamAV／YARA 的正常與 EICAR 控制；失敗不發布映像。
- 唯讀 inventory：GCP 執行、資源、建置、Registry、Secret metadata，及選用的特定工作 structured log 關聯；不將時間包絡當成 billed usage。
- R2 retention verifier：到期加二十分鐘後，七個 root prefixes 都須有效 HTTP 200 空清單才判定 absence；無寫入／刪除操作。

新引擎控制模組已用保留的完整映像，透過實際 `python -m malscan_worker.runtime.engine_controls` 執行通過。容器為 UID 10001、2 CPU／4 GiB、network none、read-only、128 MiB tmpfs；使用該保留映像的 ClamAV 1.4.3／DB 28152、YARA 4.5.4。這驗證控制程式可在真實 runtime 運作，並非新雲端映像已建置或切換的證明。

本輪測試：

| 範圍 | 結果 |
| --- | --- |
| Worker 完整回歸 | 548 passed、3 PostgreSQL opt-in skipped；Ruff 與 strict mypy 79 source files 通過 |
| 操作工具 | 系統標籤修正後 56 passed，包含維護 23、metadata 17、retention 16 |
| 驗收 client | 17 項真 loopback HTTP 測試＋1 項真 ZIP／7z 共用核心測試通過 |
| 真實容器離線控制 | 官方簽章、daily 年齡、正常／EICAR AV 及 YARA 全部通過 |

## 正式雲端維護更新

同日後續已由已登入原專案的 Cloud Shell 完成建置與映像切換；本段依使用者貼回的
`build_verified`、唯讀 Job 診斷及最終 `promoted` 輸出記錄，與前述本機容器證據分開。

- Cloud Build：`a8b1f551-5176-43ec-96f0-1e728a41071c`，最終 SUCCESS。
- 候選 digest：`sha256:361ce60bfeb1e285471ee3e8dbaba9d458f4d5e5f15297d9058a73c1d5fd57f6`，Registry 讀回一致，Job Ready。
- ClamAV 1.4.3／DB 28153、YARA 4.5.4；三份官方病毒庫簽章及四項正常／EICAR 控制通過。daily 在控制驗證時約 21 小時，版本號不代表全球最新版本宣告。
- 更新時的 `lastUpdatedTime`／template `nonce` 引發舊工具誤判；`7149eaa` 僅排除這兩個指定標籤路徑，保留舊檢查點指紋及其他設定保護。既有檢查點透過 `status` 核對為 `promoted`。

切換後另建立一筆 49-byte 良性文字檔工作 `1975bcf6-2e5b-41dd-a1c0-ca6b2e026e30`，
透過正式 API 驗證為 done／report complete／static complete。檔案大小、SHA256、
單一節點、提取預算及必要階段皆通過；ClamAV 未偵測感染、YARA 無命中，工具及規則版本
與建置控制報告一致，動態分析 disabled。這是新的一筆上傳與執行意圖，獨立於前述三案例計數。
公開報告不含執行映像 digest，該次 execution 與映像的控制面對應仍待 GCP 證據。
此工作的 R2 清理應在 **2026-10-16 15:36（Asia/Taipei）之後**另行核對。

## 原三個驗收工作的保留期驗證

2026-10-16 已由使用者在已登入原專案的 Cloud Shell 執行唯讀 R2 prefix verifier，
原三個工作在到期加二十分鐘後，七個指定前綴各自取得有效 HTTP 200 空清單：

| 案例 | 觀察時間（Asia/Taipei） | R2 結果 |
| --- | --- | --- |
| 巢狀 ZIP | 10:10:22 | 7 個前綴皆空，verified absent |
| 密碼 ZIP／7z | 10:14:10 | 7 個前綴皆空，verified absent |
| 20 MB | 10:14:13 | 7 個前綴皆空，verified absent |

合計 21 個前綴的相關物件已確認不存在；此結果限定於列出的 root 前綴與觀察時點，
不推論整個 bucket 為空或精確刪除時間。另以原 owner capability 查詢正式 API，
三個工作的 jobs／reports 路由皆取得 404／`job_not_found`，確認到期撤權；
這六次公開 API 查詢與上述 R2 管理端證據分開記錄。
DO 資料列刪除、bucket lifecycle 設定及費用仍未觀察，也不包含較晚到期的 49-byte 工作。

## 尚待遠端完成

1. 取得並審查已收集的完整 GCP metadata JSON、關聯這三個工作及核對實際執行清單；目前已收到讀取全部成功的摘要。成功 log 缺席不能證明沒有執行。
2. 雲端建置、控制報告、Registry digest 及 image-only promotion 已完成；原映像 digest 保留於檢查點。受保護回退流程有離線回歸測試，實際 GCP 回退尚未驗證，也未建立自動更新排程。
3. 核對 Billing／抵用／幣別及 Cloudflare 用量；尚不宣稱零費用。
4. 原三個工作的 R2 前綴清理與到期撤權已驗證；49-byte 工作仍待 **2026-10-16 15:36（Asia/Taipei）之後**核對。DO row 實體刪除與 lifecycle 設定仍需獨立管理端證據。

精確命令與斷線恢復方式見[操作手冊](../cloud-demo-operations.md)。這一階段仍在進行，未以本機測試取代缺少的雲端身分、時間條件或帳單證據。
