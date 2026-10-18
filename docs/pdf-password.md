# PDF 密碼恢復與解密子檔

更新日期：2026-10-18（Asia/Taipei）。本批已加入 PDF 密碼等待、補交與解密子檔流程，
程式與本機驗證已完成；正式 demo 尚未部署本批。
進度清單 [F-01](project-status.md) 記為完成（程式／本機驗證），F-08 另追蹤雲端部署與正式 smoke。
一般原生基準 32／32、獨立 PDF 密碼案例 12／12 通過；worker 839 passed／3 skipped、backend 203 passed／1 skipped、frontend 39 passed，
四項 skip 均為 PostgreSQL opt-in。最終加密支援檢查另核對 38 個負面案例，並重跑 AES-128 原生案例 1／1 通過；
證據與版本見 [2026-10-18 紀錄](milestones/2026-10-18-pdf-password.json)。
部署方式見[PDF 更新手冊](deploy-pdf-password.md)。舊版已結束的 partial 報告不會自動補做解密；
Job 與 Pages 都部署本批後，請以新的上傳工作測試此功能。

## 使用者會看到什麼

需要非空密碼的 PDF 先顯示 `password_required`。已完成的原檔掃描與部分報告仍可查看，
但 `report_complete=false`，不能把零命中當成內容已分析。輸入錯誤密碼會保留同一等待中的檔案節點，
並顯示 `wrong_password`；輸入正確密碼後從 checkpoint 繼續。

外層 ZIP 與內層 PDF 可以使用不同密碼。頁面列出正在等待的來源節點，應對該節點輸入密碼；
外層已解開不表示內層 PDF 也可讀。CLI 同樣以 artifact ID 指定內層文件。
空 user password 可讓 parser 直接讀取的加密 PDF 會自動產生解密子檔，不要求輸入空字串。
有效 user／owner password 可由 `pypdf` 解鎖；本功能使用提供的密碼，不嘗試猜測密碼。

雲端沿用每個 root 最多三次密碼補交，以及每日／每月 execution 額度。
一次補交會派送一次續跑，等待時先查詢既有工作，避免重送；外層與內層的補交共用同一 root 次數。
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

目前一般基準改用 [`corpus-v3.json`](../worker/quality/corpus-v3.json)，仍為 32 案例；
原有加密 PDF 預期由舊版本的 partial 改為等待密碼，其他歷史預期仍保留在 v1／v2。
獨立 [`pdf-password-v1.json`](../worker/quality/pdf-password-v1.json) 定義 12 個真實加密案例（suite `pdf-password-v1.1.0`）：
RC4／AES 正常與惰性 action、空 user password、不同密碼 AES ZIP → AES PDF，
以及 active xref 中沒有被 catalog 引用的加密 stream。12／12 原生案例通過，版本、雜湊與逐案結果由本批驗證紀錄保存。
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
  --manifest quality/pdf-password-v1.json \
  --jobs 1 \
  --output-dir /absolute/path/to/new-pdf-password-run
```

也可用 `--jobs 2`，或重複 `--case CASE_ID` 定位案例；選取部分案例不等於整套通過。
驗收會核對 missing → wrong → correct、持久 checkpoint 恢復、既有 stage 不重跑、原檔未改寫、
解密子檔全套掃描、action 與來源證據、完成後 resume 不新增 occurrence，以及 JSON／日誌沒有測試密碼。
結果寫入新的輸出目錄，不能用先前批次的通過數字替代本批結果。合成案例不提供真實世界偵測率。
