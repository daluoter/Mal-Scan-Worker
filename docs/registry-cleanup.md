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

## 2. 核對後才列出刪除批次

目前工具**沒有刪除、套用政策或修改標籤的操作**。取得新報告後，依序處理：

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
