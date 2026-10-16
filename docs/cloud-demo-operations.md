# 雲端 demo 驗收與維護

更新日期：2026-10-15（Asia/Taipei）。這份操作手冊實作[路線圖第一項](roadmap.md)：正式 v2 驗收、病毒庫更新、到期清理與成本取證。首次良性檔成功與本輪進階驗收分開記錄；工具準備完成不表示遠端驗收全部通過。

## 目前工具與權限邊界

| 工具 | 使用環境 | 行為 |
| --- | --- | --- |
| [驗收 client](../deployment/acceptance/README.md) | Python 3.11+；準備 fixtures 使用 worker 依賴 | 固定正式 API，以最多 3 個工作驗證巢狀／密碼／20 MB；有意圖檢查點及防重送 |
| [maintain-demo.py](../deployment/cloud-run/maintain-demo.py) | 已登入原專案的 Cloud Shell | 保存基準、非同步建置、驗證候選映像；明確執行 promote 才更新既有 Job 的 image |
| [collect-demo-evidence.py](../deployment/cloud-run/collect-demo-evidence.py) | 已登入原專案的 Cloud Shell | 唯讀 GCP 執行／資源／建置／Registry／Secret 版本 metadata；不讀 Secret payload 或原始 log 內容 |
| [verify-demo-retention.py](../deployment/cloud-run/verify-demo-retention.py) | 同上，需既有 R2 Secret 讀取權 | 僅在記憶體讀來源／結果 R2 憑證，列出指定工作的七個 prefixes；不寫入或刪除物件 |

這些工具使用現有 project `malscan-v2-poc`、region `us-central1`、Job `malscan-v2-static-demo`，不建立新的 service account、Google 私鑰或測試管理 API。GitHub CI 只執行離線工具測試。

操作狀態、fixture、capability 與基準 Job JSON 放在 repository 外的持久化 HOME 目錄，並使用私有檔案權限。Cloud Shell 重連後讀既有檢查點；不要再建立一輪同樣工作。驗收 client 的 `campaign.json` 含 owner capability 與 ticket，不能貼到聊天、提交 Git 或收入公開附件。

## 1. 正式 v2 驗收

詳細步驟見[驗收 client 文件](../deployment/acceptance/README.md)。三個工作分別驗證：

1. 同內容位於不同來源路徑的 ZIP → ZIP → 文字檔，保留 5 個 artifact 節點及 4 份提取額度。
2. 外層 AES ZIP、內層不同密碼的加密標頭 7z；初次等待 → 錯誤外層密碼 → 正確外層密碼 → 正確內層密碼，共 4 次執行。
3. 恰好 20,000,000 bytes 的正常文字檔，檢查原檔大小與 SHA256。

本輪已觀察到 20 MB 檔案的 ClamAV／YARA／IOC 正常完成，但去混淆預設上限是
10,000,000 bytes，因此該階段略過且 `analysis.static.status=partial`。此案例應驗證
「上傳、必要掃描與限制如實呈現」，不能記成所有靜態階段完整完成，也不為了測試通過而
直接放寬分析資源限制。

附加負面檢查包含超限 metadata 拒絕、錯誤 owner capability 與已消耗 ticket 拒絕。正常流程合計 6 次 execution；client 對 replay 另保守記錄一個可能執行意圖，最多 8 個意圖。預設配額以 **UTC 日／月**計算；台北時間的每日邊界為 08:00。

密碼錯誤的 POST 200 只表示派送接受，後續須從報告確認 `password_required`／`wrong_password`。每個 root 最多補交三次密碼，不能為每個子檔重置次數。最終驗證會核對 static coverage、artifact 路徑／hash／大小、累計 files／bytes 與完成 stage 時間戳，不能只看工作 done。

上傳或派送回應遺失時，先 `inspect` 已保存的工作。工具不會因 429、超時或結果不確定而建立替代 ticket／execution。公開 API 的拒絕結果與 GCP execution 清單是不同層的證據，應一併保存。

## 2. 更新病毒庫及保留回退版本

目前映像在建置時以官方 FreshClam 更新，並驗證 main／daily／bytecode 三份資料庫簽章；daily 的七天新鮮度檢查也在執行期保留。沒有自動每日更新排程。

新增的 Cloud Build `engine-controls` 步驟會在發布前，用候選完整映像的預設非 root 使用者、關閉網路及唯讀 root filesystem 執行：

- 三份資料庫的 `sigtool --info` 簽章驗證及 daily 年齡檢查。
- ClamAV 正常檔無命中、標準 EICAR 測試字串有命中。
- 真實內建 YARA 規則對正常檔無命中、EICAR 規則有命中。
- 保存工具版本、各資料庫日期／版本、規則 SHA256 及驗證模組 SHA256。

任一控制失敗，Cloud Build 不進行映像發布。重建也可能更新套件或引擎，因此它的證據記錄不限於病毒碼序號。

從已同步這次程式碼的 repository root 執行：

```bash
python3 deployment/cloud-run/maintain-demo.py prepare
```

`prepare` 唯讀既有 Job，保存現行 immutable image、設定指紋及 source fingerprint，並輸出唯一的 `state_dir`。將該路徑保存為自己的 Shell marker，重連時重新讀取，例如：

```bash
printf '%s\n' '/home/YOUR_USER/.malscan-v2-operations/maintenance/db-TIMESTAMP-ID' \
  > "$HOME/malscan-v2-maintenance-state-path.txt"

python3 deployment/cloud-run/maintain-demo.py submit \
  --state-dir "$(cat "$HOME/malscan-v2-maintenance-state-path.txt")"
```

請以 `prepare` 實際輸出取代範例路徑。`submit` 只提交一次非同步 Cloud Build；使用唯一 release 並先保存提交意圖。若回應遺失，後續 `status` 依 release 查既有 build，不重送建置。

```bash
python3 deployment/cloud-run/maintain-demo.py status \
  --state-dir "$(cat "$HOME/malscan-v2-maintenance-state-path.txt")"
```

只有最終 SUCCESS、指定離線控制步驟成功、Registry digest 一致、Cloud Logging 中本次控制報告完整，才會成為 `build_verified`。若日誌尚未到齊，可重查 status；不要直接略過控制。

候選完成後更新既有 Job：

```bash
python3 deployment/cloud-run/maintain-demo.py promote \
  --state-dir "$(cat "$HOME/malscan-v2-maintenance-state-path.txt")"
```

promote 再次驗證候選、daily 年齡及既有設定未變，只以 `--image` 更新；保留 service account、Secret versions、環境變數與資源限制。它不啟動分析工作、不修改 Worker 或前端。gcloud 更新前後會比較設定，但沒有原子 etag 條件；更新期間應避免另一個操作同時修改 Job。

若更新回應不確定，使用 status 核對既有狀態，不要重跑更新。已成功 promote 且現行設定仍一致時，可明確執行 `rollback` 回到保存的上一個 digest。舊映像的病毒庫也會變舊；回退不取代新鮮度檢查，七天 gate 仍可能讓其 ClamAV 階段失敗。

設定比對只排除已確認會隨更新改變的兩個系統標籤：Job 的
`metadata.labels["run.googleapis.com/lastUpdatedTime"]`，以及
`spec.template.metadata.labels["client.knative.dev/nonce"]`。其他使用者標籤、
環境變數、Secret 參照、資源限制及 service account 仍須一致。
舊版若因這兩個標籤而停在 `promotion_pending`，更新維護工具後執行 `status`
即可重新核對並記錄 `promoted`；此步驟只讀取雲端設定，不重新提交更新。
既有 `job-before.json` 與 v1 檢查點指紋的驗證方式保留，無須修改檢查點或重建映像。

先完成一次人工建置／驗證／切換／回退流程，再依實際建置、映像保留及執行費用決定更新頻率與自動排程。
七天限制從 daily CVD 的產生時間起算，不是映像建置時間。更新應在資料庫年齡達五天前安排，
預留失敗修復時間；單純每七天建置一次可能在兩次建置間遇到過期。

## 3. 保存 GCP 用量與成本證據

```bash
python3 deployment/cloud-run/collect-demo-evidence.py \
  --days 30 \
  --output "$HOME/demo-cloud-evidence-20261015.json"
```

可額外重複提供最多四個 `--job-id ROOT_UUID`，以唯讀 Logging 查詢關聯指定工作的成功摘要、
execution／dispatch ID 與時間。該查詢只取指定結構化欄位；失敗、中斷、尚未送達或缺少的日誌
仍不可用來證明沒有額外 execution。

工具只保存允許的 metadata，輸出檔為 0600 且不覆寫舊結果。權限不足時保留部分結果及明確的 unknown；不讀 Secret payload，不開啟工作，不清理 Registry／bucket，也不修改 IAM。

execution 的 start／completion、資源設定與推算的 wall-clock resource envelope **不是 Google 的 billable usage**。歷史工作不能套用目前 Job 的 CPU／記憶體反推帳單。

schema v2 修正 gcloud 陣列投影，以 `containers[]`／`results.images[]` 保留容器與建置映像；
execution 同時保留自身的映像參照。Artifact Registry 大小改以固定名稱的 repository list
讀取，避免 describe 的顯示處理移除原始 bytes；未回傳大小時明確標為未觀察。
資源包絡的 `coverage` 分為 complete、partial、unavailable、no_executions。
有 execution 卻完全缺少資源欄位時，CPU／記憶體時間回傳 `null`，不能讀成零用量；
`collection_complete` 只表示讀取成功，CLI 摘要會另列 `resource_envelope_coverage`。
舊版檔案可繼續作為當時的執行 metadata 證據，缺少的資源欄位應以新版重新取證。
投影回歸測試會使用已安裝的 gcloud SDK，或 `MALSCAN_GCLOUD_SDK_LIB` 指定的 SDK lib；
只在本機格式化含私有欄位標記的 fixture，不呼叫 Google API。未安裝 SDK 時這四項測試略過。

實際費用仍須在 [Google Cloud Billing Reports](https://console.cloud.google.com/billing) 選擇帳單帳戶、專案及驗收日期，檢查 Cloud Run、Cloud Build、Artifact Registry、Secret Manager、Logging 與 Storage 的費用／抵用／幣別。Cloudflare Workers／DO／R2 用量另由該帳戶 Dashboard 核對。報價、免費額度、啟動秒數、預算告警都不能代替帳單；帳單也可能延遲入帳。

## 4. 到期撤權與實體清理

正式 demo 保留期目前是 24 小時。公開 jobs／reports 在到期後回傳 404，僅能證明 owner 存取已撤回。DO 排程在 expiry 加二十分鐘的 grace 後才清理 R2；bucket lifecycle 是另一個保護層，並非固定 root 到期時刻的精確清理證據。

依已保存的 `job_id` 與 status 中的 `retention_expires_at`，在到期加二十分鐘後從 Cloud Shell 執行：

```bash
python3 deployment/cloud-run/verify-demo-retention.py \
  --job-id ROOT_JOB_UUID \
  --retention-expires-at 'ACTUAL_ISO_TIMESTAMP_WITH_TIMEZONE' \
  --output "$HOME/retention-ROOT_JOB_UUID.json"
```

工具以既有來源唯讀及結果 R2 Secret 的固定 v1 憑證簽名 metadata-only GET，分別列出：

- 來源 bucket：`uploads/<root>/`、`manifests/<root>/`。
- 結果 bucket：`controls/<root>/`、`statuses/<root>/`、`reports/<root>/`、`checkpoints/<root>/`、`artifacts/<root>/`。

七個 prefixes 都得到有效 HTTP 200 空清單才是 `verified_absent`。權限、網路、轉址、404 或 XML 格式錯誤為 unknown。未到 grace 結束前預設不讀憑證或發請求，回報 `not_due`；`--observe` 可提前觀察存在情況，但不會提前 PASS。

R2 空清單仍不證明 DO row 已移除或 lifecycle 已設定。DO 實體資料需另以 Cloudflare 管理介面可用的狀態檢查方式核對；在取得證據前保留待驗證，不加入公開測試／管理 endpoint。
