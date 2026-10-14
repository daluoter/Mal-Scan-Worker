# Serverless v2：首筆雲端分析里程碑

整理日期：2026-10-15（Asia/Taipei）。此里程碑保存共用分析核心、可部署的雲端 demo、自架入口及首次真實瀏覽器驗收；並非完整產品正式版或所有格式驗收完成的宣告。

## 已完成的交付

- 自架 queue worker 與單次 portable runner 共用靜態分析 stages，報告保留 artifact tree、來源關係、各階段 coverage、工具與規則版本。
- ZIP／7z 等支援格式可遞迴提取；補交密碼沿用 checkpoint，保留完成的階段與 root 累計預算。
- 重複派送、舊 attempt 寫入、提取超時與取消有明確邊界；已持久化的部分成果可先閱讀。
- 雲端使用 Cloudflare Pages、Worker／SQLite Durable Objects、private R2、Cloud Run dispatcher 與 Cloud Run Jobs；Cloud Run 執行同一完整靜態核心。
- Google 派送使用附掛 service account 的短期 metadata token，Worker 不保存 Google service-account 私鑰。HMAC 驗證及 Durable Object 一次性 claim 控制同次派送重放。
- dispatcher 明確標識 `MalScanWorker-dispatcher/1.0`，修復預設 Python HTTP client 在 Cloudflare 回呼前遭 `1010` 攔截的問題。
- 自架動態分析保留 CAPE provider、獨立 worker 與啟用腳本；雲端 demo 預設並固定停用動態分析。

## 首次真實雲端驗收

使用者從正式 [Cloudflare Pages demo](https://malscan-v2-demo.pages.dev) 上傳 `hello.txt`，並下載完整 JSON 報告。以下依使用者提供的報告及 Cloud Shell 執行紀錄整理；不將本機 stub 測試混作真實雲端驗收。

| 項目 | 觀察結果 |
| --- | --- |
| 工作 ID | `f9e7d95c-1c74-4624-8b15-ffab0ba533b1` |
| Cloud Run execution | `malscan-v2-static-demo-hrcmh` |
| 原檔 | `hello.txt`，13 bytes，`text/plain` |
| 原檔 SHA256 | `9f644cce75d5118a6d1c5da13a24d43e13ac057e082821fbcbcb10ce71a44789` |
| 報告契約 | `mswr-report-v3`／`mswr-analysis-v1` |
| 完成狀態 | `job_status=done`、`report_complete=true`、static `complete` |
| 動態分析 | `disabled` |
| 報告分析耗時 | 29.331 秒，其中 ClamAV 13.144 秒 |
| 引擎／規則 | ClamAV `1.4.3`、病毒庫 `28153`；YARA Python library `4.5.4` |

報告規則 SHA256 為 `3f7fa8d5c76e4b5532848d70797adf93841aabce288401fcd10446141c199091`，與目前內建 5 檔、15 條 YARA 規則相符。這是基礎規則集，沒有宣稱已涵蓋大型社群規則庫。

ClamAV 回報病毒庫日期為 `Wed Oct 14 06:24:15 2026`。這表示此次載入資料庫的標頭日期，並非掃描時間或官方此刻最新版的證明。雲端映像於建置時更新病毒碼，掃描時不執行更新；目前七日 freshness gate 需要後續維護機制。

### 啟動時間基準

實際執行發生於 **2026-10-14 23:08–23:12（Asia/Taipei）**，對應下列 UTC 紀錄：

| 事件 | UTC |
| --- | --- |
| 建立 execution | 2026-10-14 15:08:02.491454 |
| 映像匯入完成 | 2026-10-14 15:08:13.088878 |
| 資源就緒 | 2026-10-14 15:08:13.217232 |
| `status.startTime` | 2026-10-14 15:08:25.458499 |
| 平台回報 `Started` | 2026-10-14 15:10:58.286610 |
| `Completed` | 2026-10-14 15:12:00.566362 |

建立到完成 **238.075 秒**；資源就緒到 `Started` **165.069 秒**；映像匯入 **10.597 秒**。平台的 `3m35.1s` 從 `status.startTime` 起算，與建立到完成的四分鐘並不衝突。

這份紀錄證明主要延遲位於分析前的啟動準備，但尚不足以歸因於特定 Google 平台內部步驟、容量、映像快取或網路。介面目前將準備時間包含在「排隊」；29.331 秒的報告耗時不含此段等待。單筆資料也不能代表後續延遲分布或計費時間。

## 驗證範圍

提交前重新執行的回歸結果：

| 範圍 | 結果 | 邊界 |
| --- | --- | --- |
| Backend | 127 passed、1 skipped；Ruff／strict mypy 通過 | 此次未啟用 PostgreSQL opt-in migration case |
| Worker | 542 passed、3 skipped；Ruff／strict mypy 通過 | 原生 7z 已納入；3 個 PostgreSQL opt-in cases 未在此次重跑 |
| Frontend | 20 passed；typecheck、lint、cloud-demo build 通過 | production dependency audit 為 0 個已知弱點；開發工具另有待更新項目 |
| Cloudflare control | 23 passed、0 skipped | 包含 workerd／SQLite／R2、跨語言 HTTP claim 及保留的真實容器報告 fixture；Google API 使用本機 stub |
| Dispatcher | 17 passed | 包含實際本機 HTTP User-Agent 檢查；不呼叫雲端 Jobs API |

先前真 PostgreSQL、HTTP／MQ 與三個全新容器的 S3 密碼恢復驗收仍保留為獨立證據，見[驗證紀錄](../v2-validation.md)。本次沿用已驗證的容器成果作為跨 runtime fixture，沒有以重新啟動一次普通文字掃描代替所有整合測試。

## 尚未納入這次里程碑的驗收

- 正式 v2 雲端的巢狀壓縮、不同子檔密碼、錯誤密碼後恢復與完整 20 MB 上限流程。
- 正式部署的重放／斷線／結果不確定恢復、到期實際清理與長期配額觀察。
- 真實帳單與帳戶共用額度；免費額度是 demo 的成本目標，尚未證明零費用。
- CAPE 真實 guest、snapshot 還原、detonation、網路隔離與產物回填。
- 完整的格式相容性、第三方規則品質、誤報／漏報評估，以及尚未支援的解密或提取能力。

舊 PoC 的 20 MB 上傳、R2 下載與 AV／YARA 驗收，和此次新版應用程式的端到端驗收分別記錄。後續依[專案路線圖](../roadmap.md)推進，不將所有待辦視為已完成。
