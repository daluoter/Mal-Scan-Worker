# v2 實作與驗收紀錄

里程碑日期：2026-10-15（Asia/Taipei）。本文件區分本機可重現測試、先前引擎 PoC 與新版雲端應用的實際驗收，避免將其中一種證據當成全部部署能力。部署拓撲與操作見[Cloud Run 指南](../deployment/cloud-run/README.md)，首份正式網頁報告見[雲端里程碑](milestones/2026-10-15-cloud-demo.md)。

## 已實作

- 共用靜態 stage executor、`mswr-report-v3`、逐階段／子檔 coverage、部分報告與工具／規則版本。
- recursive archive／document artifacts、來源 ordinal、不同層密碼續跑、完成階段 checkpoint。
- 累計 root files／bytes、原子 reservation、attempt deadline、可終止提取子程序、過期回填 fencing。
- portable local／S3 runner、私有 HMAC checkpoint、全新容器恢復、immutable signed report／status。
- Cloudflare SQLite Durable Objects／R2 控制面、ticket／ownership、配額、派送與到期清理。
- 前端 self-host／cloud-demo 模式、partial polling、子檔密碼、真實動態資料與明確失敗狀態。
- CAPE 持久化 submitting／task ID、未知提交與多 task 核對、唯讀 preflight 與啟用腳本。

## 驗證結果

| 範圍 | 結果 | 邊界 |
| --- | --- | --- |
| Backend | 本輪 127 passed、1 skipped；Ruff／strict mypy 26 source files 通過 | 未啟用本輪 PostgreSQL opt-in；先前有 PostgreSQL 的完整驗證為 128 passed，包含 migration 007 roundtrip |
| Worker | 本輪 542 passed、3 skipped；Ruff／strict mypy 78 source files 通過 | 本輪使用原生 7z，跳過 3 個 PostgreSQL opt-in；先前有 PostgreSQL 的驗證為 544 passed、1 skipped，isolated budget case 另外通過臨時 DB 驗證 |
| Frontend | 20 passed；typecheck／lint／self-host build／cloud-demo build 通過 | 正式 Pages 已使用實際 API URL 重建發布；React Router 已修補，production dependency audit 為 0 |
| Cloud control／cross-runtime | 帶 runner fixture 的完整 Node suite 23 passed | 真 workerd／SQLite／R2；Python 映像 report gate、真 HTTP dispatcher／DO claim；Google Jobs API 使用本機 stub |
| Keyless dispatcher | 17 個 Python unit／本機 HTTP cases 通過 | metadata／claim／Jobs 單次呼叫、重播／錯誤拒絕、明確 client User-Agent；不呼叫 Google 或 Cloudflare |
| 原生 HTTP／MQ 整合 | 巢狀 AES／不同密碼／錯誤後恢復、來源重複節點、EICAR 通過 | 使用本機 PostgreSQL、RabbitMQ、MinIO、ClamAV；原始 fixtures 在記憶體產生 |
| 全映像／S3 | 3 個全新容器通過，最終 static=complete、dynamic=disabled | 2 CPU／4 GiB；真本機 MinIO S3 API，沒有使用 mock runner |

原生巢狀案例在等待內層密碼時仍可 HTTP 200 讀取部分報告；AV／YARA／file-type／IOC 的
completed timestamps 保持不變。密碼重試後 root durable accounting 為 2 files／304 bytes，
GET report 會更新累計值並保留各 attempt 自己的 deadline，`deadline_active=false` 表示該次已結束。

完整映像案例經過「root 等密碼 → inner 等不同密碼 → 完成」，每次使用全新容器，從 S3 恢復。
最後 3 個 artifact reports、2 個提取檔／300 bytes；報告與 checkpoint 不含測試密碼，private
control 驗證讀取後被刪除。自身隨機測試 buckets 已清理。本機 image config ID 為
`sha256:c68556066d9443cf701fefa9faeb6b8296b0e610d80622ad537489b979f10467`。
部署時依 [Cloud Shell 指南](../deployment/cloud-run/README.md)取得 registry 的完整 image digest。

該映像報告記錄 ClamAV `1.4.3/28152`（daily CVD 2026-10-13）及 YARA `4.5.4`，規則 SHA256
`3f7fa8d5c76e4b5532848d70797adf93841aabce288401fcd10446141c199091`。原生 ClamAV 為
`1.5.4/28152`。這些是各次執行的實際版本；舊 PoC 的版本紀錄保持原樣。

## 重現與目前環境的證據

Python 3.11.16；Node 24.19。從各 component 目錄執行 pytest／Ruff／mypy，以載入自身設定。
backend／worker 使用 `--asyncio-mode=auto`；`MALSCAN_TEST_POSTGRES=1` 啟用有自身 fixture cleanup
的 attempt／migration 測試。budget 的 `MALSCAN_TEST_POSTGRES_URL` 必須指向 disposable DB，
不能使用主開發資料庫。

完整容器／S3 及 cross-runtime fixture 命令見 [Cloud Run 文件](../deployment/cloud-run/README.md)
與 [Cloudflare 文件](../deployment/cloudflare/README.md)。本機工作區的原始 XML／JSON／日誌不是
repository 內的可攜驗收產物；重現時應保存自己生成的報告與 exit status，不依賴特定 `/workspace`
路徑。一般 `npm test` 在未提供 Python runner fixture 時會明確 skip 該 opt-in case；需要完整
跨 runtime 證據時，先執行 `verify-local-image.py` 再提供其結果目錄。

建置時曾發現並修正 nonroot package 權限、早期 disabled metadata 與 IOC 對 backend 設定的
遺留依賴。一次服務重啟干擾及本機磁碟不足造成的測試不列入成功證據；清理舊測試映像與未用
建置快取後，重新執行的完整案例才是上列驗收。容器 build 另有 nonroot import 檢查。

## 正式雲端應用里程碑

使用者已在自己的 Cloud Shell 部署並從正式 Pages origin 上傳 `hello.txt`（13 bytes），下載新版
`mswr-report-v3` 報告。job `f9e7d95c-1c74-4624-8b15-ffab0ba533b1` 為 `done`、
`report_complete=true`，靜態分析完成，動態分析明確為 `disabled`。這是完整 v2 應用流程，
不同於舊的 upload-only／engine-only PoC。

| 已取得證據 | 結果 |
| --- | --- |
| 正式入口 | `https://malscan-v2-demo.pages.dev`，經 `malscan-v2-demo-control` API |
| Dispatcher | keyless，修正明確 User-Agent 後 revision `malscan-v2-dispatcher-00003-z2d` Ready；health 為 ok |
| Cloud Run execution | `malscan-v2-static-demo-hrcmh`，成功完成 |
| 平台總耗時 | 2026-10-14 23:08:02.491 → 23:12:00.566（Asia/Taipei），238.075 秒 |
| 啟動觀測 | 映像匯入約 10.6 秒；ResourcesAvailable → Started 165.069 秒 |
| Report 分析時間 | 29.331 秒，其中 ClamAV 13.144 秒；不含開始前的平台等待 |
| 工具版本 | ClamAV `1.4.3`／daily DB `28153`（資料庫日期 2026-10-14）；YARA Python `4.5.4` |
| 規則版本 | 5 個檔案、15 條內建規則；SHA256 `3f7fa8d5c76e4b5532848d70797adf93841aabce288401fcd10446141c199091` |

此處的「排隊」曾包含平台準備執行環境的時間；目前介面尚未將所有等待細分。單次四分鐘的
基準不代表固定延遲或服務 SLA。ClamAV 資料庫版本是該次實際載入的版本，不表示現在的官方
最新版；建置時更新並拒絕超過七天的 daily CVD，尚未建立自動更新排程。

## 尚待實際部署與產品完善

後續 P0 已實測正式 API 的巢狀 ZIP、不同密碼 ZIP／7z、錯誤後恢復、20 MB 與超限／owner／ticket
拒絕，見[P0 驗收紀錄](milestones/2026-10-15-p0-acceptance.md)。20 MB 必要掃描通過，去混淆因
10,000,000-byte 上限而略過，static 為 partial。該輪 Worker 回歸為 548 passed、3 PostgreSQL
opt-in skipped，操作工具 50 passed，client 17 HTTP＋1 archive/core case 通過；真容器離線
控制也通過，並非已在 GCP 建置更新映像。

實際 GCP 執行計數、斷線與不確定派送管理核對、保留期實體清理、真正的更新／回退、
實際免費用量／Billing 與 live CAPE guest／detonation 仍待驗收。這些項目的本機測試與先前
PoC 成果不取代正式部署驗收。雲端 demo 固定 static，保留動態擴充於 self-host。
部署由使用者已授權的 Cloud Shell 執行；本機開發環境沒有替代使用者 GCP 身分呼叫遠端資源。

靜態 coverage complete 是宣告支援範圍內的完成狀態，不能保證所有格式／加密方法、零漏報或
完整反編譯。加密 Office／PDF、ISO 提取、ELF／Mach-O／郵件／APK 深度支援、重複節點的證據
共用、動態多 task 聚合／掉落檔再分析與全面的誤報／漏報 fixture corpus，仍需逐項完善。
目前真實限制見 [支援矩陣](analysis-support.md)。

開發環境的安裝／啟動設定已保存為設定草稿。儲存並發布後，下一個任務仍需啟動服務並驗證
還原；沒有以本機測試宣稱 fresh-task restoration 已完成。
