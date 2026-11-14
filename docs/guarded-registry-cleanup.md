# 自動更新啟用後的限定舊映像清理

更新日期：2026-11-14（Asia/Taipei）。本輪完整私人盤點已審查：只有 3 個舊 `full-worker` Docker schema 2 版本符合候選條件；目前版、回退版、dispatcher 及整組 engine-poc 保留。見[精簡審查紀錄](milestones/2026-11-14-legacy-registry-review.json)。這是候選審查，尚無本輪刪除或費用節省結果。

使用新入口 `guarded-registry-cleanup.py`，由原 setup plan 驗證已核准來源。原六個控制器檔案及雲端 bundle 保持原樣；清理入口不替換自動更新來源、不建置新映像、不執行分析 Job。最後恢復原排程的啟用流程另見第四節。
以下在原已登入的 Cloud Shell 執行；操作期間不要同時部署、建置、改標籤或另外啟動維護流程。每次盤點前後及每次刪除前均會核對，但供應商讀取與刪除並非原子操作，也沒有取得跨服務的全域鎖。

## 1. 更新本機工具並暫停排程

沿用原來源與 setup plan，不重新 prepare 安裝，也不重新下載或修改私人 bundle：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  git fetch origin main
  git checkout --quiet --detach origin/main
  if ! git diff --quiet c907187c5c87a32b7cd25828ed98041b2f779c13 -- \
    deployment/cloud-run/auto_update.py \
    deployment/cloud-run/auto_state.py \
    deployment/cloud-run/auto_retention.py \
    deployment/cloud-run/maintain-demo.py \
    deployment/cloud-run/cleanup-registry.py \
    deployment/cloud-run/prune-registry.py; then
    echo '已核准的控制器檔案有差異；停下核對，不接續暫停或清理。'
    exit 1
  fi
  test -f deployment/cloud-run/guarded-registry-cleanup.py

  python3 deployment/cloud-run/setup-auto-update.py pause \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

暫停會將 Scheduler 停在 `PAUSED`、coordinator 停用，並暫停原計畫的兩個維護告警。它**不會取消已在執行的控制器**。只有 `controller_in_flight: false`、`controller_lease_present: false` 才接續；若仍有工作，稍後執行以下只讀查詢，不手動刪 lease 或修改 state：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/setup-auto-update.py status \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

## 2. 產生私人限定計畫

使用維護者已審查的 `registry-inventory.json` 及其 SHA256。完整路徑與 hash 由私人操作紀錄取得，不放進公開文件或 Git。
原盤點需在 24 小時內，期限依私人報告的觀測時間計算。超過期限或狀態改變時，先依[只讀盤點](registry-current-inventory.md)取得並重新審查，不能改時間戳或換成未審查檔案。

`prepare` 會在已暫停狀態取得新完整盤點，要求候選集合與已審查報告完全一致，並核對引用、標籤與保護集合。它不會因新盤點而擴大刪除清單，也不會刪除映像。

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  if [ -e "$HOME/malscan-v2-legacy-cleanup-path.txt" ]; then
    echo '本輪計畫路徑已保存；請沿用原批次 check，不重新 prepare。'
    exit 1
  fi
  read -r -p '已審查 registry-inventory.json 完整路徑: ' V2_LEGACY_INVENTORY
  read -r -p '維護者核對的原檔 SHA256: ' V2_LEGACY_INVENTORY_SHA
  V2_LEGACY_ROOT=$(mktemp -d "$HOME/malscan-v2-legacy-cleanup.XXXXXX")
  V2_LEGACY_OPERATION="$V2_LEGACY_ROOT/operation"
  python3 deployment/cloud-run/guarded-registry-cleanup.py prepare \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")" \
    --inventory "$V2_LEGACY_INVENTORY" \
    --inventory-sha256 "$V2_LEGACY_INVENTORY_SHA" \
    --output "$V2_LEGACY_OPERATION"
  printf '%s\n' "$V2_LEGACY_OPERATION" > "$HOME/malscan-v2-legacy-cleanup-path.txt"
)
```

私人計畫、原計畫綁定與清理 journal 保存在 HOME；不要搬進 repository、上傳公開 issue 或刪除後重新開始。
若 `prepare` 失敗，不接續 `apply`；保留固定錯誤摘要及已建立目錄供核對。

## 3. 執行同一批次並確認結果

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/guarded-registry-cleanup.py apply \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")" \
    --operation-dir "$(cat "$HOME/malscan-v2-legacy-cleanup-path.txt")"
)
```

每個 DELETE 前都會檢查原 setup plan、來源、live Job、Scheduler 暫停設定、coordinator generation、目前／回退版與 lease。任何偏離都停止；盤點每次從遠端 current checkpoint 建立新的私人暫存 HOME，不使用真實 HOME 的過時人工 checkpoint。

送出刪除前先保存 pending 意圖。斷線、逾時或 provider 回應不確定時，先執行同一批次的 `check`：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/guarded-registry-cleanup.py check \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")" \
    --operation-dir "$(cat "$HOME/malscan-v2-legacy-cleanup-path.txt")"
)
```

`check` 不送 DELETE，但會將已確認的缺席寫回本機 journal。若 pending 版本已不存在，可以確認完成；若仍存在，不能自動重送或清空 journal。
即使最後一個 guard 在送出前失敗，也可能留下保守的 uncertain 記錄，需要核對後處理。
若只是兩次刪除之間中斷，`check` 確認 `pending_intent_present: false`、`phase: partial` 且原計畫仍有效，才可沿用原批次接續 `apply`。pending 仍存在或結果不確定時停下核對；計畫過期後只先 `check`，不修改期限。

只有結果為 `phase: completed`、`pending_intent_present: false`、`removed_count: 3` 才接受這批刪除。將最後摘要提供維護者核對；未取得結果前，不把本輪標成完成。

## 4. 完成後恢復原排程

確認上一步完整完成後，再明確執行原 setup 的啟用流程；工具不會在錯誤處理或結束時自動恢復：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/setup-auto-update.py enable \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

啟用會恢復原維護告警與 Scheduler，並提交一次 activation controller Build；它可能依資料庫年齡執行正常維護，不執行分析 Job。稍後用第一節的 `status` 確認 `ENABLED`、`automatic_updates_enabled: true` 及新的 `activation_heartbeat_verified: true`。
若清理未完成或結果不確定，保持原批次與暫停狀態供核對，不自行刪檢查點或另開批次繞過。

刪除版本後，背景 layer 回收、容量統計與帳單入帳可能不同步。後續重新讀回容量並比較相同期間的儲存 SKU；保留正式／回退映像仍可能計費，版本數下降不等於已驗證節省。GCS 來源的七天期限與其餘兩個保存物件，仍依[既有私人基準](build-source-expiry-readback.md)獨立追蹤。
