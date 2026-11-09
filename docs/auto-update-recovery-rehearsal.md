# 自動更新中斷與重連演練（P0-12）

更新日期：2026-11-09（Asia/Taipei）。本頁使用 `rehearse-auto-update-recovery.py`，沿用已安裝的私人自動更新計畫。
程式與本機測試交付、真正雲端中斷／接續驗收分開記錄；目前尚未取得本演練的雲端通過證據。

**現在先做第 1 步 `prepare`。真正演練時，需在更新開始前啟動監看，捕捉更新進行中的狀態。**
先前依 daily `28174` 推算的 **11/8 23:23 已過**。目前雲端可能已完成後續自然更新，需由新的 `prepare` 讀回，不能沿用舊基準或日期。
以摘要的 `target_tick_at_taipei` 作為目標時間、`recommended_watch_at_taipei` 作為開始監看的時間；若映像或設定再變動，工具會停止核對。
工具沒有替你預約未來執行，當天仍需在 Cloud Shell 手動開始監看。

| 時機 | 你要執行的命令 | 會做什麼 |
| --- | --- | --- |
| 現在 | `prepare` | 只讀核對，保存私人演練紀錄與目標時間 |
| 目標更新前約三分鐘 | `watch-and-interrupt` | 等待本次自然更新，核對後取消一個維護 controller |
| 確認中斷、關閉並重連後 | `status`，再 `resume --confirm-reconnected` | 查回原紀錄，最多建立一個接續 controller |
| 接續提交後 | `status` | 讀回同一候選、Job 與復原結果 |

## 這次要驗證什麼

11/6 台北 15:19 的只讀基準已通過：目前映像為 `493fd6bd…bfc21c`、回退版為 `4a018a2a…10b263`，
daily `28174` 建立於台北 11/5 14:26:24。三天門檻為台北 11/8 14:26:24，下一個符合門檻的排程是當晚 23:23。
這是 11/6 當時的推算，並非 11/9 的最新雲端狀態。真正演練前會重新核對並重新計算下一個符合門檻的排程。

Cloud Shell 視窗關閉時，雲端更新程序仍可能繼續執行。因此這次包含兩份證據：

1. 工具受控取消一個已核對的維護 controller，保存其 campaign 與候選 Build，驗證真正中斷後可接續。
2. 操作者關閉／重連 Cloud Shell，沿用同一份私人紀錄查詢及接續，保存明確的人工確認。

工具只會選取本輪已核對的維護 controller；候選映像 Build 與分析 Job 保留各自原有流程。
它不強迫病毒庫提前到期，也不修改原 plan、核准來源、全域 enabled state 或 lease。
接續的標準 controller 仍會依原政策執行更新與有界清理。
本演練與 P0-11 的實際映像回退分開驗收，清理／保留期與費用也繼續各自追蹤。

## 1. 現在：準備私人演練紀錄

先依本批交付訊息更新本機來源至包含演練工具的 commit，再執行：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py prepare \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

這個 `prepare` 讀取已核准來源、健康狀態、目前 Job 與排程，並在原 plan 目錄建立私人 `recovery-rehearsal.json`。
它不取消工作、不提交新 Build，也不重新安裝自動更新資源。
原本的 plan、來源 bundle、操作 journal 與全域 state 繼續使用。

預期為 `phase: prepared`。保存摘要顯示的目標排程與監看時段；今天先完成這一步即可。
重複執行會沿用同一份紀錄，不能用另建計畫來清除未知的操作結果。
若已有舊的演練紀錄且 `window_has_passed: true`，先保留並提供摘要，不能將它當作新計畫使用。
若回報 `recovery_prepare_too_close_to_due_tick`，代表距離下一個到期排程不足五分鐘；本機不會建立這份演練紀錄，待該次正常更新結束後再重新準備。

## 2. 演練當天：在更新前開始監看

在 `recommended_watch_at_taipei` 顯示的時間開啟 Cloud Shell（通常是目標排程前三分鐘），執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py watch-and-interrupt \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

輪詢等待上限為 15 分鐘，網路讀回另需時間；取消前會再次確認仍在目標排程前五分鐘至後二十分鐘內。
開始後會先顯示 `phase: armed`、`waiting_for_natural_candidate: true`；這是等待摘要，需繼續等待命令返回最後結果。
工具等待自然更新，重新核對原基準、維護鎖 owner、controller 身分／固定來源、campaign 與候選 Build。
候選 Build 尚為 `QUEUED`／`PENDING` 時繼續等待；整體為 `WORKING`、建立時間不超過 90 秒且各項檢查通過時，才會先保存取消意圖，再對綁定的 controller 發出一次取消請求。
Build 的細部步驟狀態未必即時更新，本演練不宣稱精確停在某個 Docker 子步驟。

取消有競爭時序：若更新已正常完成或候選／campaign 已離開預期狀態，工具會保留紀錄並停止。
`missed_window` 表示未成功捕捉中斷時機，不算復原驗收通過，也不會因而再建立一筆接續 Build。

## 3. 查詢中斷結果，再關閉／重連

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py status \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

`cancel_pending` 表示取消意圖已保存、結果仍待讀回；使用同一個 `status` 查詢，不重送取消。
`interrupted` 才表示已確認原 controller 為 `CANCELLED`，且原 campaign 與候選 Build 仍可識別。
工具不會手動刪除 lease；接續程序會先確認舊 owner 已終止，再使用原有的條件式接管機制。

取得 `interrupted` 後，關閉 Cloud Shell 視窗，再重新開啟並登入同一帳號。
回來先執行本節相同的 `status`，確認仍是同一份紀錄、campaign 與候選 Build。
若監看期間先發生斷線，回來也先查 `status`；保留原紀錄，依目前階段接續。

## 4. 重連後：接續同一個候選

實際完成上一節的關閉／重連後，再執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py resume \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")" \
    --confirm-reconnected
)
```

`--confirm-reconnected` 保存的是操作者已重連的明確聲明，不代表工具讀取了瀏覽器或登入歷史。
工具核對舊 controller 已取消、同一個 campaign／候選仍在、核准來源與允許的 Job 狀態相符，且沒有其他工作持有維護鎖。
它先保存唯一接續意圖，再最多建立一個使用原核准來源的 controller Build。
接續請求的排隊 TTL 為五分鐘，並要求距下一次 Scheduler 派送超過三十分鐘；不以修改排程或停用告警取得演練時段。
來源、候選或 Job 狀態不符時停止，不手動改寫原 campaign 或全域 phase。

若建立回應遺失，原意圖與唯一 tag 用於查回結果，不會因再次輸入命令而直接重送建立。
接著使用第 3 節的 `status` 讀回同一筆演練；候選 Build 尚未完成時可稍後再查。

## 5. 完成條件與異常處理

只有工具核對到 `phase: recovered`，並完成同一候選、controls、Job 與接續 controller 的證據核對後，才記錄本次復原通過。
驗收包含：

- 原維護 controller 的取消結果已確認，未知結果沒有自動重送。
- 原 campaign 與候選 Build 身分保留，同一發布沒有多出第二個候選建置。
- 接續使用已核准來源與原檢查點；新映像、目前／回退指標及 Job 完整設定符合預期。
- 候選的官方簽章與離線控制通過，接續 controller 的健康輸出與本次演練相符。
- 依精確候選 Build 再讀實際 controls，並確認完整 Job 設定只改變預期映像；平台產生的既有已知 metadata 使用相同比較規則。
- 操作者重連的人工確認與雲端接續證據分開保存。

`prepared`、`armed`、`cancel_pending`、`resume_pending`、`resume_submitted` 都不是已通過。
`missed_window` 或固定錯誤碼也不能當作復原成功；保留安全摘要供核對。
原 plan、bundle、journal 與演練 sidecar 保持在 Cloud Shell HOME；全域 coordinator state／lease 繼續保存在原私人 GCS bucket。
公開紀錄只使用審查後的 metadata 與 hash。

演練預期最多多用一個接續 controller Build，候選映像沿用自然更新的一次建置。
這些維護工作不呼叫分析 Job 的 execute API，不消耗 demo 掃描 execution 額度；Cloud Build 及相關儲存／日誌仍有各自計費方式，不承諾零費用。
