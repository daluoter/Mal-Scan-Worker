# P0：正式 v2 驗收與維護工具

日期：2026-10-15（Asia/Taipei）。延續[首筆良性檔里程碑](2026-10-15-cloud-demo.md)，本輪直接透過正式 Worker API 驗證三個工作，並新增可持續維護的工具。可機讀的允許欄位證據見 [JSON 紀錄](2026-10-15-p0-acceptance.json)，不含 ticket、owner capability 或正式憑證。

**2026-10-16 更新：本輪核心雲端驗收批次與四筆 R2 保留期核對完成。** 人工映像更新、
新映像執行與目前 TWD 專案月報也已有證據。完整 P0 維運出口仍有待辦，可與下一階段
靜態證據／偵測品質工作並行；沒有將尚未觀察的項目標為通過。

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

Client 共建立 3 個工作，取得 6 次原始上傳／密碼續跑的接受回覆；對 replay 另保守記錄一個可能執行意圖，因此 journal 為 7。這些 client 意圖與 GCP execution 計數分開看待；後續控制面核對見下方，額外執行與帳單仍需獨立證據。

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
| 操作工具 | 取證投影修正後 64 passed：維護 23、metadata 21、真 SDK 投影 4、retention 16 |
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
公開報告不含執行映像 digest；後續新版 GCP 取證已補齊該次 execution 與映像的對應，見下方。
此工作已於 **2026-10-16 22:58（Asia/Taipei）**完成七個 R2 前綴核對，結果皆空。

## 四個驗收工作的保留期驗證

2026-10-16 已由使用者在已登入原專案的 Cloud Shell 執行唯讀 R2 prefix verifier，
四個工作在到期加二十分鐘後，七個指定前綴各自取得有效 HTTP 200 空清單：

| 案例 | 觀察時間（Asia/Taipei） | R2 結果 |
| --- | --- | --- |
| 巢狀 ZIP | 10:10:22 | 7 個前綴皆空，verified absent |
| 密碼 ZIP／7z | 10:14:10 | 7 個前綴皆空，verified absent |
| 20 MB | 10:14:13 | 7 個前綴皆空，verified absent |
| 切換後 49-byte 小檔案 | 22:58:39 | 7 個前綴皆空，verified absent |

合計 28 個前綴的相關物件已確認不存在；此結果限定於列出的 root 前綴與觀察時點，
不推論整個 bucket 為空或精確刪除時間。另以原 owner capability 查詢正式 API，
四個工作的 jobs／reports 路由皆取得 404／`job_not_found`，確認到期撤權；
這八次公開 API 查詢與上述 R2 管理端證據分開記錄。
DO 資料列刪除與 bucket lifecycle 設定仍未觀察。

## 上傳的 GCP 取證檔案核對

使用者提供的完整檔案收集於 2026-10-15 11:02:52（Asia/Taipei），早於後續維護建置與
49-byte 測試。原三個工作有 6 筆成功摘要，分別對應到 1、4、1 個不同 execution，
皆可在該次 Job execution 清單找到；密碼流程的中途 partial 與 20 MB 的 partial 保留。
清單共 7 筆，均記錄成功完成；另一筆為先前的瀏覽器良性檔測試 `hrcmh`。
這個有限時間窗與成功摘要不構成「絕無額外執行」的證明。

該版取證的容器與建置映像陣列欄位因 gcloud 投影格式而遺漏，7 筆 execution 都被排除於
資源包絡計算。當中的 vCPU／GiB 秒數為 0 代表缺少計算資料，不能解讀為零用量或免費。
schema v2 修正陣列投影，完全缺少資源時改回傳 null／unavailable，另保留 execution 自身映像；
Artifact Registry 大小則避開 describe 的顯示處理，改用固定名稱 list。
修正以真實 Google SDK formatter 離線測試驗證，後續已取得已登入 Cloud Shell 的新版取證。

新版檔案收集於 **2026-10-16 11:51:06（Asia/Taipei）**，13 項讀取皆成功。
四個指定工作共關聯 7 次 execution，加上先前瀏覽器驗收，清單共 8 次成功執行。
全部取得各自的容器資源與映像；資源包絡 coverage 為 complete、排除筆數為 0。
其中 49-byte 工作對應 `malscan-v2-static-demo-dm5pr`，執行映像確為已切換的
`sha256:361ce60bfeb1e285471ee3e8dbaba9d458f4d5e5f15297d9058a73c1d5fd57f6`。
現行 Job 也為該映像並 Ready，使用 1 task／parallelism 1／2 CPU／4 GiB／900 秒／重試 0。

這 8 次 start-to-completion 的資源時間包絡為 2,853.325398 vCPU-seconds、
5,706.650796 GiB-seconds，包含平台等待，仍不等於 billable usage。
映像倉庫回傳 1,671,658,885 bytes（約 1.67 GB／1.56 GiB），共 8 個版本；
此為當時儲存快照，不是每月儲存用量或帳單。官方[Artifact Registry 定價](https://cloud.google.com/artifact-registry/pricing)
的免費儲存級距為每帳單帳戶 0.5 GiB-month，以上部分為 US$0.10／GiB-month；
仍須核對實際入帳期間、其他專案共用額度及抵用額，未宣稱零費用。

後續已核對使用者提供的服務 CSV、專案分組截圖及 `gcloud currencyCode`：
月內報表的專案為 `malscan-v2-poc`、幣別為 TWD，折抵後目前費用極低且非精確零。
原始財務附件與精確金額保留於私有操作紀錄，不收入公開證據；優惠來源與最終月結仍未確認。

## 尚待遠端完成

1. 持續觀察 Cloudflare 用量／配額、每次工作及每月維護成本、抵用額類型與最終月結；目前專案月報已核對，未將資源時間包絡當成帳單。
2. DO row 實體刪除與 lifecycle 設定仍需獨立管理端證據；GCP 來源 bucket 與映像倉庫的保留／清理設定也須分開檢視。
3. 原映像 digest 保留於檢查點；受保護回退流程有離線回歸測試，實際 GCP 回退尚未驗證，也未建立自動更新排程。

精確命令與斷線恢復方式見[操作手冊](../cloud-demo-operations.md)。本輪驗收批次完成，P0 持續維護出口尚未全部結案；下一個開發優先項目見[靜態品質路線圖](../roadmap.md#2-讓靜態結果更值得信任)。
