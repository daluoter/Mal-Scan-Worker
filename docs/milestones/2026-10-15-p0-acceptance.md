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
| 操作工具 | 50 passed，包含維護 17、metadata 17、retention 16 |
| 驗收 client | 17 項真 loopback HTTP 測試＋1 項真 ZIP／7z 共用核心測試通過 |
| 真實容器離線控制 | 官方簽章、daily 年齡、正常／EICAR AV 及 YARA 全部通過 |

## 尚待遠端完成

1. 在已登入的 Cloud Shell 收集 GCP metadata、關聯這三個工作；核對實際執行清單。成功 log 缺席不能證明沒有執行。
2. 用新工具完成一次真正的 Cloud Build → 控制報告 → Registry digest → image-only promotion；保留原映像並驗證回退流程。目前沒有在 GCP 執行此更新，也未建立自動排程。
3. 核對 Billing／抵用／幣別及 Cloudflare 用量；尚不宣稱零費用。
4. 三個工作的 R2 實體清理最早應在 **2026-10-16 09:58（Asia/Taipei）之後**核對。公開 404 只驗證撤權；DO row 實體刪除與 lifecycle 設定仍需獨立管理端證據。

精確命令與斷線恢復方式見[操作手冊](../cloud-demo-operations.md)。這一階段仍在進行，未以本機測試取代缺少的雲端身分、時間條件或帳單證據。
