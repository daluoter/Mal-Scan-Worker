# 雲端 demo 的可恢復驗收

這套小型 client 只驗證現有正式 demo，固定使用
`https://malscan-v2-demo-control.daluoter.workers.dev` 與正式 Pages Origin。
它不部署資源，不讀取 Google／Cloudflare 管理憑證，也不產生惡意程式。

## 案例與用量

| 案例 | 輸入與預期結果 | 正常新增 executions |
| --- | --- | ---: |
| `nested` | ZIP 的 `one/inner.zip` 與 `two/inner.zip` 內容相同，各包含一個文字檔；保留 5 個節點、4 次子檔配額與各自路徑 | 1 |
| `passwords` | 外層 AES ZIP、內層含加密標頭的 7z，密碼不同；先等待、錯誤外層密碼、正確外層密碼、正確內層密碼 | 4 |
| `20mb` | 恰好 20,000,000 bytes 的正常文字檔；來源大小／SHA256 一致、AV／YARA／IOC 完成，去混淆因 10 MB 限制略過並明確記為 partial | 1 |

同一 campaign 最多建立 3 個正常工作，最多保留 8 次可能執行意圖。
正常案例共 6 次，單次 replay 保守地再記一次意圖。quota／429／不確定回應都不會建立替代工作。
這是 client 的成本邊界；仍須核對 Google Cloud 的實際 execution 清單。
不要以新目錄重跑 campaign 來繞過已保存的限制。

`guards` 額外測試 20,000,001-byte **票證 metadata** 被拒絕、錯誤 capability 回傳 404、消耗過的 ticket 回傳 409。
超限案例不傳送大檔；replay 只送 1 byte，票證消耗檢查須先於大小驗證。
票證只有五分鐘有效期，請在第一次 upload 回覆後立刻執行 guards，先不要等待掃描完成。
過期回傳 403 無法證明 ticket 已消耗；client 會停止而非當成通過或另建工作。

## 準備

在 repo 根目錄執行。只有離線 fixture 準備需要 `pyzipper`、`py7zr`，可直接使用已設定的 worker virtualenv。
CLI 本身及其他操作只依賴 Python 3.11+ 標準程式庫，沒有背景安裝行為。

```bash
worker/.venv/bin/python deployment/acceptance/cloud_acceptance.py prepare \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015"
```

`prepare` 不發出網路請求，不覆蓋既有 campaign。資料夾須放在 repository 外。
`campaign.json` 內含私有 capability 與短效 upload ticket；目錄為 0700、檔案為 0600，
每次 POST 前以 fsync／atomic replace 保存意圖。**不要上傳、貼出或提交整個 campaign.json**。
Client 輸出只有公開工作 ID、狀態、數量與驗證結果，沒有 capability／ticket／密碼。
固定測試密碼是公開 synthetic fixture 資料，和正式憑證無關。

## 依序驗收

先檢視離線預演；省略 `--run` 的 mutating command 不會發出請求。

```bash
python3 deployment/acceptance/cloud_acceptance.py start \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested
```

第一次巢狀檔上傳與立即防重放檢查：

```bash
python3 deployment/acceptance/cloud_acceptance.py start \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested --run
python3 deployment/acceptance/cloud_acceptance.py guards \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested --run
```

`inspect` 每次只讀現有狀態及可用報告，不提交工作。冷啟動時可間隔約 30 秒手動執行，直到 `done`。

```bash
python3 deployment/acceptance/cloud_acceptance.py inspect \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested
python3 deployment/acceptance/cloud_acceptance.py verify \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested
```

再以 `start --case passwords --run` 上傳密碼案例，以 `inspect --case passwords` 讀取部分報告。
每次都等現有工作回到 `password_required`，再執行下一步：

```bash
python3 deployment/acceptance/cloud_acceptance.py password \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --value wrong --run
# inspect passwords；等 password_required，確認 password_attempts=1
python3 deployment/acceptance/cloud_acceptance.py password \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --value outer --run
# inspect passwords；等 password_required，確認 password_attempts=2
python3 deployment/acceptance/cloud_acceptance.py password \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --value inner --run
# inspect passwords；等 done，再 verify --case passwords
```

最後用同樣的 `start`、`inspect`、`verify` 操作 `--case 20mb`。
驗證會比較本機原檔、雲端來源大小／SHA256、全部節點的父子路徑／hash／大小／數量、artifact tree、
累計檔案／bytes 預算、已宣告的靜態 coverage、動態關閉，以及密碼恢復前後已完成階段的開始／結束時間。
巢狀與密碼案例須完整；20 MB 案例只允許已知的去混淆大小限制，報告須保留 `static.status=partial`、
`File too large for deobfuscation (20000000 bytes)`，client 會輸出 `full_static_analysis_verified=false`。
這個案例通過上傳完整性與必要掃描驗收，不代表該檔已完成全部靜態分析。其他缺漏不會因此一起放行。
錯誤密碼的 HTTP 200 只代表派送接受；必須取得後續 `wrong_password` 部分報告才算成功證據。

## 中斷、失敗與到期

Cloud Shell 重連後保留相同目錄，直接 `inspect` 現有工作。
`start` 在 upload 已嘗試後一律拒絕再次 POST，即使上次回覆遺失或 server 回傳 429／503。
Ticket 回覆遺失時可能沒有可恢復的工作 ID；此時保留 journal，透過管理端配額／儲存清單核對，不能自動補發 ticket。
沒有自動重試、redirect、另一個 endpoint、改用其他 capability 或重新建立 campaign 的 fallback。

超過之前 `inspect` 保存的 `retention_expires_at` 後：

```bash
python3 deployment/acceptance/cloud_acceptance.py expiry \
  --state-dir "$HOME/.malscan-v2-acceptance/p0-20261015" --case nested
```

目前公開 API 透過 ownership gate 對過期工作回傳 **404**，不會透露工作是否存在。
這只能證明公開存取已撤回；`expiry` 永遠保留 `r2_deleted_verified=false`。
實際 R2 前綴為空、DO 狀態已清除、Job 沒有額外 execution 與費用，仍須獨立的管理端證據。
不要把公開 404／410 或 lifecycle 設定當成已刪除證據。

## 本機測試

標準程式庫邊界測試使用真實 loopback HTTP server，沒有外部網路與雲端 mutation：

```bash
python3 -m unittest discover -s deployment/acceptance -p test_cloud_acceptance.py -v
```

實際 ZIP／7z、checkpoint、budget 與已完成 stage 保存測試：

```bash
worker/.venv/bin/python -m unittest discover \
  -s deployment/acceptance -p test_fixture_runtime.py -v
```

後者使用真正共用核心與 extractor，只有昂貴的 AV stage 以計數器代替；它不是病毒偵測品質或雲端執行證據。
未使用 worker 環境時此項明確 skip，不影響標準程式庫的 HTTP 測試。
