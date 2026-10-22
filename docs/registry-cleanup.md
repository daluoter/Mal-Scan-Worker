# 舊映像盤點與成本清理

更新日期：2026-10-22（Asia/Taipei）。本階段處理 `P0-07` 保留政策及 `P0-14` 成本，
暫停新功能、雲端掃描與不必要的建置。既有部署、月 execution 額度及測試資料保留政策不在此步修改。

本月 SKU 報表已確認映像儲存是主要淨費用來源，另有少量 Cloud Storage 操作、傳輸與儲存費。
原始帳單、精確金額、帳單帳戶資料與私人盤點檔均不加入 Git。降低未來留存量不能撤銷已產生的費用，
保留正式及必要回退映像也不保證儲存帳單為零。

## 1. 先取得現況

在已登入的 Google Cloud Shell 執行以下步驟。這份工具只讀取部署與 Registry metadata、
以及本機維護 checkpoint 的必要身份欄位；不讀 Secret payload，不下載分析檔，不啟動 Job、建置或更新服務。

```bash
(
  set -e
  umask 077

  V2_COST_SOURCE=$(mktemp -d "$HOME/malscan-v2-cost.XXXXXX")
  git clone --quiet --depth=1 \
    https://github.com/daluoter/Mal-Scan-Worker.git "$V2_COST_SOURCE"
  cd "$V2_COST_SOURCE"
  git rev-parse HEAD
  pwd > "$HOME/malscan-v2-cost-source-path.txt"

  V2_REGISTRY_REPORT="$HOME/registry-inventory-$(date -u +%Y%m%dT%H%M%SZ).json"
  python3 deployment/cloud-run/cleanup-registry.py inspect \
    --output "$V2_REGISTRY_REPORT"
)
```

輸出檔使用私人權限，且不覆寫已存在檔案。將摘要及產生的 JSON 交給維護者核對；
不要另外提供環境變數、登入設定、服務帳戶金鑰或 Secret payload。
Cloud Shell 斷線後，`$HOME` 下已完成的報告與來源路徑紀錄可沿用，不必重新部署應用程式。

工具將部署引用與 Registry 版本分開整理。未直接引用的版本只列為**尚未分類**，
不是「可以刪除」：仍需核對回退、映像 index 與其子 manifest 關係、執行中的工作及其他使用者。
缺權限、逾時、清單截斷、部署格式不符或本機回退狀態不足，都保留為明確缺口。
成功保存報告不代表清理條件已滿足。

## 2. 核對後產生限定批次

`cleanup-registry.py` 維持唯讀。新增的 `prune-registry.py` 將已核對報告轉為私人計畫，
只有明確執行 `apply` 才刪除計畫內的完整 digest；不設定自動清理政策。清理前依序核對：

1. 保留現行 Cloud Run Job、服務 revision、執行中工作引用的映像；舊 PoC Job 若仍存在，也先保留其引用。
2. 由目前映像與對應維護 checkpoint 確認必要的前一版回退 digest，不只依建立時間猜測。
3. 核對 OCI index／manifest 與共享內容關係；沒有被直接引用不代表其子 manifest 沒有用途。
4. 將其餘版本逐一列成限定 package 與完整 digest 的刪除批次，重新查核引用後再執行並記錄結果。
5. 重新盤點版本與倉庫大小，並待帳單更新後比較儲存 SKU。共享 layer、背景回收與帳單延遲可能使
   版本數減少和儲存費下降不同步；不能把映像顯示大小直接加總成可節省金額。

不使用「刪除整個 repository」、「刪除全部未標籤映像」或單憑日期的一次性大量刪除。
自動清理政策應等本次保護集合與實際結果核對後，再先以 dry-run 驗證。
參考官方 [Artifact Registry 清理政策](https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy)。

Cloud Build 來源 bucket 是另一項費用：待映像批次處理後，另外盤點來源物件、lifecycle 與 soft delete，
再決定保留期限。本步不刪除來源 bucket、R2、DO、Secret 或 Cloud Run 資源。

### 10/22 第一批

已收到使用者在已登入 Cloud Shell 產生的盤點。清單共 14 版，讀取沒有缺口，
正式 Job 與已 promoted 的維護 checkpoint 相符。第一批只處理 `full-worker` package 的舊版：

| 處理 | digest 前綴 | 備註 |
| --- | --- | --- |
| 保留 | `03099c77e41e` | 正式 `malscan-v2-static-demo` Job |
| 保留 | `aad2b4e3d03c` | 與目前正式版相符的前一版回退紀錄 |
| 刪除 | `0e81e655f561` | 舊 full-worker |
| 刪除 | `361ce60bfeb1` | 舊 full-worker |
| 刪除 | `69fe7ceb9624` | 舊 full-worker |
| 刪除 | `776c6fa1f460` | 舊 full-worker |
| 刪除 | `861b6ffdb13f` | 舊 full-worker |
| 刪除 | `9b5c2663f7a9` | 舊 full-worker |
| 刪除 | `e7029d90fb3b` | 舊 full-worker |

兩個 `demo-dispatcher` 版本及整組三個 `engine-poc` 版本保留。engine 的 OCI index、
子 manifest 與 attestation 不因未被 Job 直接引用而刪除；本批不需要更動它們。
盤點中 full-worker 各版皆為 Docker schema 2 image manifest；有新的 index／未知 media type 時，工具停止。
表格只方便人工辨識，實際計畫保存並使用完整 URI／digest，不能用前綴代替。

**本批版本清理已取得使用者結果並核對完成**：`phase=completed`、無 pending、七個完整 digest
與已審閱批次完全一致，版本數 14 → 7；沒有啟動掃描。見[限定批次紀錄](milestones/2026-10-22-registry-cleanup.json)。
這是使用者提供的 operator 輸出，不是 agent 另行登入 provider 查核；輸出未另外列出完整保留身份表，
保留條件由工具前後的完整引用／版本比對支持。**這批已完成，不再重新 prepare／apply。**

即時倉庫讀數僅減少 25,795 bytes，仍約 4.24 GiB，尚未證明大量容量回收或帳單節省。
官方[映像管理說明](https://cloud.google.com/artifact-registry/docs/docker/manage-images)指出：
刪除映像不會立即刪除其 layer，未被引用的 layer 每日清理。這能說明為何需要後續觀察，
但不能據此斷言此倉庫已完成回收或必定於某時刻降至零費用。
版本顯示大小合計不等於可回收或可省下的帳單空間，保留正式／回退映像仍可能產生儲存費。

### 首批已執行的步驟（留存供核對）

先取包含 `prune-registry.py` 的新版來源；不要重建容器或重新部署應用程式。
在已登入的 Cloud Shell、沒有其他部署／建置／映像標籤修改同時進行的時段執行：

```bash
(
  set -e
  umask 077

  V2_PRUNE_SOURCE=$(mktemp -d "$HOME/malscan-v2-prune.XXXXXX")
  git clone --quiet --depth=1 \
    https://github.com/daluoter/Mal-Scan-Worker.git "$V2_PRUNE_SOURCE"
  cd "$V2_PRUNE_SOURCE"
  pwd > "$HOME/malscan-v2-cost-source-path.txt"

  V2_PRUNE_PLAN="$HOME/registry-prune-plan-$(date -u +%Y%m%dT%H%M%SZ).json"
  python3 deployment/cloud-run/prune-registry.py prepare \
    --inventory "$HOME/registry-inventory-20261022T022930Z.json" \
    --inventory-sha256 9adad28fe2610b438b77f9a4ac29818528fb2bbb70e7c7da880c0e433a05c944 \
    --plan "$V2_PRUNE_PLAN"
  printf '%s\n' "$V2_PRUNE_PLAN" > "$HOME/malscan-v2-registry-prune-plan-path.txt"

  V2_PRUNE_STATE="$HOME/.malscan-v2-operations/registry-cleanup/$(date -u +%Y%m%dT%H%M%SZ)"
  printf '%s\n' "$V2_PRUNE_STATE" > "$HOME/malscan-v2-registry-prune-state-path.txt"
  python3 deployment/cloud-run/prune-registry.py apply \
    --plan "$V2_PRUNE_PLAN" --state-dir "$V2_PRUNE_STATE"
)
```

`prepare` 先核對這份已審閱報告的 SHA256，再產生有時效、不可覆寫的本機計畫，
且限制為沒有部署／回退引用、早於保留版本的 full-worker Docker schema 2 版本。
`apply` 會重新讀取雲端引用與版本，核對原始 metadata、tags、保護集合與回退紀錄；
只允許本批已確認刪除的 digest 缺席。任何新版本、標籤移動、引用改變、讀取缺口或受保護版本缺失都停止。
它不以最新清單重新擴充刪除對象。

每次刪除都使用完整 digest URI，寫入私人檢查點後才送出。逾時、斷線或結果不確定時，
讀回確認缺席才記錄完成；若目標仍存在，不自動再送一次刪除。
各次 API 讀取不是跨服務原子快照，執行期間須保持部署、建置與標籤修改暫停。

若中斷，沿用已保存的計畫與狀態，**不要重建一份計畫開始另一批**：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-cost-source-path.txt")"
  python3 deployment/cloud-run/prune-registry.py apply \
    --plan "$(cat "$HOME/malscan-v2-registry-prune-plan-path.txt")" \
    --state-dir "$(cat "$HOME/malscan-v2-registry-prune-state-path.txt")"
)
```

也可以把上述 `apply` 改為 `check`，只讀回並核對同一批的狀態，不送出新的刪除。
計畫超過時效後只能先 `check`，不得修改計畫時間戳或建立另一批繞過尚未核對的狀態。

把工具最後輸出的結果與新的盤點交給維護者核對。若停止在不確定狀態，先核對雲端結果，
不刪除檢查點或自行強制續跑。最終刪除與後續儲存 SKU 的改善證據分開記錄。

### 完成後的唯讀複查

10/22 首批已完成。待下一輪每日 layer 清理與容量統計更新後，建議 10/23 下午或之後，
沿用同一計畫與檢查點執行 `check`。它不送出刪除，計畫超過 24 小時仍可查核：

```bash
(
  set -e
  set -o pipefail
  umask 077
  cd "$(cat "$HOME/malscan-v2-cost-source-path.txt")"
  python3 deployment/cloud-run/prune-registry.py check \
    --plan "$(cat "$HOME/malscan-v2-registry-prune-plan-path.txt")" \
    --state-dir "$(cat "$HOME/malscan-v2-registry-prune-state-path.txt")" \
    | tee "$HOME/registry-prune-check-$(date -u +%Y%m%dT%H%M%SZ).json"
)
```

回傳 `registry-prune-check-*.json`，比對版本仍為 7、無 pending 與新的 `observed_repository_size_bytes`。
若資料未變，先核對完整剩餘 digest、共享 layer、provider 用量／儲存指標與入帳時間，
不能為了降低顯示數字而刪除保護映像。實際減少的倉庫容量與實際帳單節省仍分開記錄。

## 3. 11/1 的恢復順序

目前暫停新功能開發與正式掃描；[完整開發清單](project-status.md)及[路線圖](roadmap.md)繼續保留。
正式 demo 使用全站共用的 UTC 月份，2026-11-01 00:00 UTC（台灣時間 **08:00**）起進入新月份；
實際 counter 與可用額度仍應查核，不手動放寬或重設限制。

恢復前先檢查 ClamAV daily 的官方產生時間。最近已知版本為 10/20，到了 11/1 將超過七天 gate；
若無更新，僅恢復月額度並不足以完成防毒分析。必要時依[維護手冊](cloud-demo-operations.md)
做一次受控、官方簽章與離線控制通過的映像更新，再更新保護 digest；不放寬新鮮度檢查。
這次更新應納入已確認的映像保留與建置成本管理。

接著先完成 `F-11` 剩餘兩案：`pdf-flate-eicar.pdf`、`office-embedded-pdf.docx`。
使用有權處理這些測試檔的個人環境，不繞過公司防毒；失敗或已消耗票證的舊工作不重用，重新上傳建立工作。
完成報告、身份與範圍核對後，再續作原有格式品質與後續功能。新工作的到期清理另追 `P0-18`。

`P0-06` DO 清理、`P0-11` 真實回退、`P0-12` 自動病毒庫更新、`P0-14` 長期成本及
`P0-15` Cloudflare 費用不因這份工具或一次刪除而結案。
