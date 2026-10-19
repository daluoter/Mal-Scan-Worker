# PDF 密碼恢復與解密子檔

更新日期：2026-10-19（Asia/Taipei）。F-01 PDF 密碼恢復及 F-09／Q-08／UX-06／UX-07 回饋修正，
已完成本輪 F-08 雲端人工驗收。使用者確認錯誤提示、逐檔三次及父子檔高風險顯示通過；
新畫面可見紅色密碼錯誤訊息及已用 1／剩餘 2，兩份新完成 JSON 另核對本檔 4 分／整體 84 分、
解密子檔 84 分、逐檔已用 2／剩餘 1 與完成的靜態掃描。
逐檔獨立及第三次限制依使用者人工確認；未新增自動化雲端測試，也未提供最外層 ZIP 完整報告或 Pages deployment ID。
範圍與限制見 [2026-10-19 雲端驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)。
首批本機結果見 [PDF 密碼紀錄](milestones/2026-10-18-pdf-password.json)。

本次依正式畫面與 JSON 回饋修正錯誤提示、每檔三次、紅色高風險及祖先風險。
目前雲端完成報告使用評分政策 `msrs-v1.2`；四項修正的程式／本機結果與上述人工驗收分開記錄。
worker 852、backend 233、frontend 52、控制層 25 項通過；四項 PostgreSQL opt-in 與一項完整 Python fixture 跳過。
PDF v2 原生 12／12 通過，一般 32 份原生報告以最終 v4 manifest 重新核對；
初次 per-case 政策斷言仍為舊版而失敗，修正為 1.2 後重新驗證保存的原生報告，沒有重跑偵測器。
完整結果及限制見 [本批紀錄](milestones/2026-10-18-pdf-feedback.json)，
分列進度清單 `F-09`、`Q-08`、`UX-06`、`UX-07`。
其他部署依 [回饋修正部署手冊](deploy-pdf-feedback.md)以 **Job → Cloudflare Worker → Pages** 順序更新；
舊版已結束的報告不會自動重算。

## 使用者會看到什麼

需要非空密碼的 PDF 先顯示 `password_required`。已完成的原檔掃描與部分報告仍可查看，
但 `report_complete=false`，不能把零命中當成內容已分析。輸入錯誤密碼會保留同一等待中的檔案節點，
並顯示 `wrong_password`；輸入正確密碼後從 checkpoint 繼續。

外層 ZIP 與內層 PDF 可以使用不同密碼。頁面列出正在等待的來源節點，應對該節點輸入密碼；
外層已解開不表示內層 PDF 也可讀。CLI 同樣以 artifact ID 指定內層文件。
空 user password 可讓 parser 直接讀取的加密 PDF 會自動產生解密子檔，不要求輸入空字串。
有效 user／owner password 可由 `pypdf` 解鎖；本功能使用提供的密碼，不嘗試猜測密碼。

新版雲端以**每個加密檔案各三次被接受的密碼補交**計算，正確與錯誤都計次；被拒絕且沒有保留派送的請求不計次。
例如外層 ZIP 正確提交一次後，ZIP 為已用 1／剩餘 2；新出現的內層 PDF 為已用 0／剩餘 3。
PDF 錯誤一次後為已用 1／剩餘 2，再正確一次為已用 2／剩餘 1。不是一個 root 共用三次。
某檔耗盡時，其他仍在等待的檔案可以使用各自剩餘額度。

每次接受密碼會派送一次續跑，仍受全站每日 20／每月 40 次 execution 限制；新上傳每日 10 個不變。
因此每檔還有次數，也可能因全站 execution 額度不足而暫時無法續跑。等待時先查詢既有工作，避免重送。
新計數由更新後的 Cloudflare Worker 啟用；舊版 root 共用總數保留為歷史值，不猜測應分配給哪個檔案。
舊工作首次轉換後從逐檔 0 開始計算後續提交一次，反覆查詢／部署不會再重設；既有日／月 execution 歷史不會清零。
密碼不是命令列參數，也不會放入可下載報告、耐久 checkpoint 或一般 parser 日誌。
雲端仍透過既有私有短期 control 物件傳遞密碼，沒有新增公開密碼儲存位置。

## 原檔與解密子檔分開分析

原始加密 PDF 保持不變，保留原大小與 SHA-256。成功解鎖會建立一個新的 `decrypted.pdf` 子檔：

| 欄位 | 意義 |
| --- | --- |
| `extraction_source=format-analysis`、`archive_type=pdf` | 由 PDF 格式分析衍生 |
| `origin_path=pdf-decrypted` | 解密來源，而非一般附件 |
| 子檔的 `parent_id`、SHA-256、大小 | 對應加密來源與實際重新序列化 bytes |
| 加密父檔的 `content_access=decrypted_child` | 父檔已產生待分析子檔，不代替子檔的掃描結果 |
| `decrypted_child.artifact_ids`、`analysis_state` | 追蹤子檔派送；沒有有效派送不能宣稱內容已分析 |

子檔重新執行檔案型別、ClamAV、YARA、IOC、去混淆及適用格式階段。
JavaScript／Launch 等結構證據從解密內容取得，保留在子檔並聚合回父報告；不執行 action。
解密保留文件 catalog 與可讀的 active xref 物件，包括沒有被 catalog 引用的 stream，
避免只複製可見頁面而漏掉需由 ClamAV／YARA 掃描的內容。物件讀取失敗或超出界限會保留 partial。
這個範圍不包含已被新版取代的歷史 revision 或任意尾端 bytes；衍生檔不是原始 bytes，
不宣稱重寫後保留原文件數位簽章效力或所有特殊 PDF 功能。

續跑保留同一原檔／artifact 身份與累計預算，已完成的原檔 stages 不重跑。
完成後再次 resume 不應重建第二個解密 occurrence。
portable runner 可從保存在結果 store 的 checkpoint 恢復；本機 disposable cache 遺失也不應要求重新上傳。
自架 queue worker 使用相同 PDF 分析與子檔契約。

## 為什麼加密父檔和解密子檔的分數不同

加密原檔的直接分析主要看到密文與外層結構，解密子檔才提供可讀的 JavaScript／Launch／自動開啟證據。
因此兩者的**本檔分數**可以不同，但整體報告與祖先節點必須反映其包含的高風險內容。

使用者提供的舊版報告中，單一加密 PDF 本檔為 4 分、聚合後 29 分／低風險，解密子檔則為 84 分／高風險；
ZIP 內 `locked.pdf` 的報告仍為 4 分，而其 `decrypted.pdf` 為 84 分。
該次沒有提供最外層 ZIP 完整報告，不能據此推定 ZIP 的總分。
這反映舊版祖先聚合／節點投影的缺漏，不能解讀成加密檔比較安全。

新版 `msrs-v1.2` 保留原始直接分析於 `risk.local_risk`，並讓已驗證高風險子孫成為祖先有效風險的下限。
對本次固定樣本，解密子檔為 84 分時，包含它的 PDF 與 ZIP 有效風險至少為 84 分／高風險；
來源樹另保留 `local_score` 等欄位，讓使用者看出本檔 4 分與整體 84 分的差別。
這不是為父檔杜撰另一個直接命中，也不會因重複內容多次加上同一份證據。
本輪新報告已核對直接上傳 PDF 及 ZIP 內加密 PDF 子樹皆為本檔 4 分／有效 84 分；
最外層 ZIP 的總分沒有新完整報告可核對，不以子樹報告代替。

高風險使用紅色摘要／節點與來源提示，不只靠顏色辨認。
歷史 JSON 不會改寫；新版前端可根據報告中已核對身份的可見子檔顯示風險提醒，並明示舊分數與有效呈現的差別。
`84／高風險` 在本次合成 PDF 來自惰性 action 結構，ClamAV／YARA 未命中；
**高風險不等於已確認惡意**，也不等於已執行 JavaScript 或驗證危害行為。


## 資源與能力邊界

PDF 輸入處理上限為 50 MiB；解密輸出還受單檔、整次提取與 root 累計 bytes／files、深度及時間窗限制。
writer 每次擴大輸出前先預留累計額度，失敗已用 high-water 額度不會自動退回。
parser 在 Linux 獨立 process group 執行，逾時或取消時停止並清理未完成的私有暫存輸出。
這些限制不取代容器的記憶體上限，亦不宣稱可解析所有巨大、損壞或特殊加密文件。

實際 fixture 涵蓋 Standard security handler 的 RC4-40、AES-128、AES-256 revision 5／6。
不支援的加密、損壞檔、缺少 crypto backend 或資源限制會保留 sanitized error 與 partial，
不以錯誤密碼或 clean 隱藏 parser 失敗。嵌入檔使用不同於一般 stream 的加密篩選器（`EFF != StmF`，
例如附件為 AES、一般 stream 為 Identity），以及 `/EncryptMetadata=false` 目前不支援；
這兩種設定在要求密碼前檢查，回報 sanitized unavailable／partial，不產生明文子檔。
stream 明確指定 `/Filter /Crypt`（包含 `/Name /Identity`）的 override 也尚未支援；
此檢查需要成功解鎖後、建立解密子檔前執行，因此可能先要求密碼，隨後回報 unavailable／partial，
不產生解密子檔，也不轉成反覆輸入錯誤密碼的流程。預設 metadata 加密的固定對照不受上述限制影響。
RC4 與 revision 5 僅作舊格式相容性測試。
Office 解密與 PDF 附件提取仍是獨立待辦；附件描述不等於附件已掃描。

## 本機 CLI

需要 Linux、Python 3.11、固定 worker 依賴（含 `pypdf`／AES crypto backend）、libmagic 及可用掃描引擎。
從 repository 的 `worker` 目錄執行，沿用既有的 ClamAV／YARA 環境設定：

```bash
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/locked.pdf \
  --output-dir /absolute/path/new-analysis

poetry run python -m malscan_worker.runtime \
  --file /absolute/path/locked.pdf \
  --output-dir /absolute/path/new-analysis \
  --resume --ask-password
```

`--ask-password` 會隱藏輸入根 PDF 的密碼；不是把密碼寫在 shell 歷史中。
若等待的是壓縮檔內的 PDF，查看報告的 `password_required_artifacts` 與來源樹，改用：

```bash
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/nested.zip \
  --output-dir /absolute/path/new-analysis \
  --resume --password-artifact ARTIFACT_ID
```

不要更換原檔、output-dir 或已保存的 checkpoint 來處理等待狀態。
程序退出成功只表示狀態與成果已保存，仍應核對 `job_status`、`report_complete`、static coverage 與子檔證據。

## 可重現驗收

目前一般基準改用 [`corpus-v4.json`](../worker/quality/corpus-v4.json)，仍為 32 案例；
原有加密 PDF 預期由舊版本的 partial 改為等待密碼，新政策為 `msrs-v1.2`，原 v1／v2／v3 manifest 保留歷史預期。
獨立 [`pdf-password-v2.json`](../worker/quality/pdf-password-v2.json) 定義 12 個真實加密案例（suite `pdf-password-v2.0.0`）：
RC4／AES 正常與惰性 action、空 user password、不同密碼 AES ZIP → AES PDF，
以及 active xref 中沒有被 catalog 引用的加密 stream。固定 bytes 沿用首批；本次以新政策與逐層風險預期重新跑完原生 12／12，不能沿用首批數字代替。
另有 user／owner password、輸出限制、逾時／取消與派送失敗等回歸測試。

固定 fixture 的 salts／keys／IVs 已凍結為版本化 bytes，生成時只需 Python 標準函式庫，
逐筆核對大小與 SHA-256。公開測試密碼只供這些合成 fixture 使用，不能當成真實文件的密碼建議。
完整本機驗收另需真實引擎，從 `worker` 目錄執行：

```bash
YARA_RULES_PATH="$PWD/rules" \
CLAMAV_MODE=cli \
CLAMAV_DATABASE_PATH=/absolute/path/to/verified-clamav-databases \
SANDBOX_ENABLED=false \
poetry run python -m malscan_worker.quality.pdf_password_acceptance \
  --manifest quality/pdf-password-v2.json \
  --jobs 1 \
  --output-dir /absolute/path/to/new-pdf-password-run
```

也可用 `--jobs 2`，或重複 `--case CASE_ID` 定位案例；選取部分案例不等於整套通過。
驗收會核對 missing → wrong → correct、持久 checkpoint 恢復、既有 stage 不重跑、原檔未改寫、
解密子檔全套掃描、action 與來源證據、完成後 resume 不新增 occurrence，以及 JSON／日誌沒有測試密碼。
結果寫入新的輸出目錄，不能用先前批次的通過數字替代本批結果。合成案例不提供真實世界偵測率。
