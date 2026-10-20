# Office 密碼恢復與解密子檔

更新日期：2026-10-20（Asia/Taipei）。F-02 已完成程式與本機驗證；正式 Office smoke **F-10 完成（限定案例）**。
已核對使用者提供的 Job 映像切換、Pages 正式發布輸出、Office 錯誤提示畫面與五份報告，
涵蓋一般加密 DOCX、外部範本 DOCX、不同密碼 ZIP→Office 三個宣告的 smoke 案例。
三份完整根報告各為 8／10／9 節點，分數為 0／15／6；另有兩份 8 節點 Office 詳細子樹，
五份宣告範圍內的靜態分析皆完成，見[Office 雲端驗收紀錄](milestones/2026-10-20-office-cloud-acceptance.json)。
錯誤紅字與 Office 已用 1／剩餘 2 有畫面；ZIP 已用 1 時 Office 初始仍為 0／3 依使用者確認。
最終 ZIP 根 JSON 記錄 ZIP 已用 1／剩餘 2、Office 已用 2／剩餘 1，累計提取 8 檔／19,196 bytes；
最終 ZIP 根與本輪對應 Office 子樹的身份、明文 hash、來源及適用掃描符合固定樣本預期。
驗收不涵蓋其他 Office 格式或本輪未演練的三次耗盡；各 root 的 status／保留期及清理另列 P0-18。
發布順序見 [Job→Pages 手冊](deploy-office-password.md)，各項證據與維護條件見[進度清單](project-status.md)。

## 支援範圍

功能使用提供的使用者密碼，解開 OLE 容器內含 `EncryptionInfo`／`EncryptedPackage` 的現代 OOXML。
不嘗試猜密碼、不呼叫 Office／LibreOffice 轉檔，也不執行巨集、DDE、外部範本或嵌入程式。
`msoffcrypto-tool==6.0.0` 由既有 lock 的間接依賴改為明確固定的直接依賴；原有 101 個依賴版本不變。

| 範圍 | 程式可接受的限定 header | 固定加密 fixture 實際覆蓋 |
| --- | --- | --- |
| Agile | AES-CBC，package key 128／256 bits，SHA-256／384／512；單一 password key encryptor，要求 HMAC 驗證 | AES-256；DOCX／XLSX／PPTX、DOCM／XLSM／PPTM、外部範本 DOCX 與巢狀 ZIP |
| Standard | AES-ECB 128／192／256 bits、SHA1，限定 CryptoAPI header／provider | AES-128 DOCX |
| 不支援 | 舊式二進位 DOC／XLS／PPT 加密、IRM／DRM、其他 cipher／hash／key encryptor、不能識別的 package type | 固定不支援與損壞對照應為 partial，不要求重試密碼 |

另有 57 組真實加密演算法測試：54 組 Agile（package AES-128／256 × SHA-256／384／512，
再交叉 password key 的 AES-128／192／256 × SHA-256／384／512）及三組 Standard AES-128／192／256。
這些測試核對解密明文，不等於每組都已跑過完整原生掃描流程；完整流程使用表中 14 個固定 profile。
模板／投影片放映等 content type 可被辨識，本批固定文件類型只涵蓋表中六種，不宣稱所有 Office 版本均已驗收。

Agile 必須通過密碼 verifier、資料 HMAC 與 package 驗證才建立子檔。**Standard 沒有認證完整性保護**；
密碼 verifier、ZIP CRC 與結構檢查可以發現部分損壞，不能提供 HMAC 等級的防竄改保證。
HMAC／CRC 失敗、損壞 XML、parser 失敗與工具缺失皆為 unavailable／partial，只有密碼 verifier
確認失敗才顯示 `wrong_password`。不支援格式保留 `unsupported`，不讓使用者反覆輸入密碼。

## 等待、錯誤與續跑

初次分析仍保存原檔已完成的 hash／ClamAV／YARA 等成果；讀不到加密內容時進入 `password_required`，
保留部分報告與 `report_complete=false`。輸入密碼後是非同步續跑，POST 接受只代表派送接受。
分析確認不正確後，同一 artifact 顯示 `wrong_password`、紅色錯誤訊息、檔案路徑與剩餘次數。
正確密碼從持久 checkpoint 繼續，已完成的原檔 stages 不重跑，不建立新 root。
空密碼可解鎖的套件會自動產生子檔，不要求使用者輸入空字串。

沿用現有**每個加密 artifact 各三次被接受的密碼補交**契約；正確與錯誤均計次，沒有接受派送的拒絕不計次。
ZIP 使用一次不扣內層 Office；兩個 Office sibling 也各自計算。密碼只送往指定的等待節點，
不把外層 ZIP 密碼或第一份文件密碼套用到其他文件。某一節點耗盡不應阻擋其他仍有次數的節點。
所有續跑仍計入 demo 每日 20／每月 40 次 executions；新工作仍為每日 10 個，沒有提高額度。
這是既有控制契約在 Office 的沿用。先前三份 Office 報告各記錄已用 1／剩餘 2／上限 3；
本輪 Office 錯誤紅字與 1／2 有畫面，ZIP 已用 1、Office 初始仍為 0／3 依使用者人工確認。
最終 ZIP 根 JSON 記錄 ZIP 1／2、Office 2／1，且工作及靜態分析完成；相關身份與本輪對應 Office 詳細子樹一致。
F-10 按這三個宣告 smoke 案例結案，沒有在本輪雲端演練 Office 三次耗盡；各 root 實際保留期與清理仍列 P0-18。

報告會保留原始加密父檔及獨立的解密子檔。成功子檔來源為 `office-decrypted`，
`content_access=decrypted_child`，並記錄明文 SHA-256／大小；加密資訊的 `integrity` 在 Agile 成功時為
`hmac_verified`，Standard 為 `zip_crc_only_no_authenticated_integrity`。
資源限制另有 `resource_limited`／`limit_reason`，不能由空偵測清單推定解密完成。

## 明文保存與掃描

解密輸出是原加密包內的 OOXML ZIP **完整明文 bytes**，不重存 XML、不重新壓縮，也不只複製主文件可達內容。
每個 member 都讀過 CRC，檢查重複／歧義名稱、路徑、compression method、content types 與主文件 relationship。
未由主文件引用的 binary／embedding members 仍保留。輸出副檔名由 package content type 決定，
例如 `.bin` 上傳內含 XLSM 也命名 `decrypted.xlsm`，不信任使用者副檔名。
這是套件 bytes 保存，不是原 Office 簽章效力或全部文件功能的相容性承諾。

子檔以新 artifact 身份進入共用 ClamAV／YARA、檔案型別、格式／文件、IOC 與適用靜態階段，
支援的嵌入物件再受同一 root 預算遞迴分析。macro-enabled content type 會保留正確格式資訊；
有 VBA project 但來源不可解析仍可為 partial，不以解密成功取代內容 coverage。
父檔保留本檔風險及直接證據，`msrs-v1.2` 的有效風險可繼承已驗證高風險子孫；高風險不等於已確認惡意。
完成後再 resume 不新增第二個解密 occurrence；原加密檔 hash 不改變。

密碼只用於當次解密。不得把真實密碼放進命令列、檔名、報告、日誌或 checkpoint；
測試會檢查公開 fixture 密碼未出現在輸出。第三方 crypto debug 輸出在 parser 子程序內關閉，
錯誤保留可解讀的 sanitized 原因，不回傳 password-derived material。

## 資源邊界

加密輸入上限為 50 MiB。明文輸出取 50 MiB 與既有單檔／單次提取上限的較小值，
寫出前先向 root 預留 file／bytes，並保留 high-water reservation；失敗或續跑不重發額度。
demo 仍限制 20,000,000-byte 原檔、整棵樹累計 20 檔／100,000,000 bytes／深度 3，
不是每一個文件各有一份新預算。CLI 預設整樹 100 檔／500,000,000 bytes／深度 3。

OLE／ZIP member 最多 4,096；加密 metadata 最多 64 KiB、package metadata XML 最多 1 MiB、
metadata XML 深度最多 32；主文件 XML 另限 20 MiB、250,000 nodes、深度 256。
Agile spin count 最多 1,000,000；package member 累計展開檢查另受 100 MiB
與既有單次提取上限的較小值限制。這些解析上限不取代容器記憶體上限。
保守的 CFB 配置檢查可能將少數非典型但有效的容器拒為 partial，保留原因供後續相容性樣本擴充。
metadata、密碼衍生、解密與 package 驗證都在 Linux 可強制終止的 parser process group；
超時／取消終止 parser，清除未完成私有暫存，保留已完成報告及未完成原因。

## 本機 CLI

需要 Linux、Python 3.11+、固定 worker 依賴、libmagic 與可用 ClamAV／YARA。從 `worker` 目錄執行：

```bash
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/locked.docx \
  --output-dir /absolute/path/new-office-analysis

poetry run python -m malscan_worker.runtime \
  --file /absolute/path/locked.docx \
  --output-dir /absolute/path/new-office-analysis \
  --resume --ask-password
```

隱藏提示用於根文件；內層 ZIP 中的 Office 使用報告 `password_required_artifacts` 所列的 artifact ID：

```bash
poetry run python -m malscan_worker.runtime \
  --file /absolute/path/nested.zip \
  --output-dir /absolute/path/new-office-analysis \
  --resume --password-artifact ARTIFACT_ID
```

保留同一原檔、output-dir 與 checkpoint；結束碼 0 只表示狀態與成果已保存，仍需核對
`job_status`、`report_complete`、static coverage、解密子檔及未完成原因。

## 可重現驗收

[`office-password-v1.json`](../worker/quality/office-password-v1.json) 的 14 個 profile 保存固定密文／明文大小與 SHA-256。
生成模組只用 Python 標準函式庫還原已凍結 bytes，包含 Agile AES-256、Standard AES-128、六種文件格式、
外部範本、不同密碼 ZIP、雙 Office sibling、第二組 Office 密碼與損壞／不支援對照。
公開的 `quality-office-only`、`quality-office-second-only`、`quality-office-archive-only` 與
`quality-office-incorrect-only` **只供這些合成 fixture 使用**，不是正式密碼或密碼建議。
fixture 內巨集旗標、binary parts 與 `.invalid` 範本皆是惰性測試資料，不開啟文件或取得遠端內容。

完整原生驗收需要真實 ClamAV、可用病毒庫與 YARA。一般單元／runtime 測試的 scanner transport stub
用於檢查派送與恢復，不能替代原生 AV 證據。本批 Office 14／14、一般 v5 40／40、PDF v2 12／12 均重新執行並通過，
見[本批驗證紀錄](milestones/2026-10-19-office-password.json)；
一般 v5 corpus 與 PDF v2 suite 各自執行，不改寫歷史 milestone 或以舊通過數字代替本批結果。
驗收檢查 missing→wrong→correct、已完成 stage 不重跑、明文逐 byte 相符、子檔全套掃描、
原檔不變、完成後 resume 不重複 occurrence、預算與時間邊界，以及輸出未洩漏 fixture 密碼。
合成 fixture 通過不提供真實世界偵測率，也不代表正式雲端已發布。

從 `worker` 目錄執行完整 14-profile 原生驗收；輸出目錄必須尚不存在：

```bash
CLAMAV_MODE=cli \
CLAMAV_DATABASE_PATH=/absolute/path/to/verified-clamav-databases \
YARA_RULES_PATH="$PWD/rules" \
poetry run python -m malscan_worker.quality.office_password_acceptance \
  --manifest quality/office-password-v1.json \
  --output-dir /absolute/path/to/new-office-password-run \
  --jobs 1
```

驗收器每個 attempt 的測試預算為 30 檔／5,000,000 bytes／300 秒、最大深度 4，
每個 case 最長 600 秒，與正式 demo 的設定分開。包含 OOXML 內部 XML、VBA binary 與多個提取來源的
嵌入物件 occurrence；相同 bytes 可以共用儲存物件，但來源節點與掃描身份各自核對。
外部範本對照的解密子檔為 53／中風險，加密父檔繼承 15／低風險、本檔 0。
它未達高風險下限，不用來取代 PDF v2 的 84 分高風險傳遞驗收。
