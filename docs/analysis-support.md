# 靜態分析支援範圍與資源預算

本文件描述目前程式可執行的能力與限制。格式 handler 或分析器存在，並不表示已涵蓋該格式的所有版本、加密方式或損壞情況；報告的 coverage 與未完成原因才是該次分析的證據。

## 格式能力

| 格式 | 目前分析／提取能力 | 密碼與依賴 | 主要限制 |
| --- | --- | --- | --- |
| 一般檔案 | 檔案型別／hash、ClamAV、YARA、IOC、去混淆候選 | 需要可用的 ClamAV 和 YARA 規則 | 沒有專用格式分析器，不代表其他階段沒有分析；無規則／工具失敗不能當成已掃描未命中 |
| Windows PE | headers、imports／exports、sections、entropy、resources、TLS、debug、overlay、packer clues 與啟發式 | `pefile` | 100 MiB 處理上限；overlay／resources 結構偵測不等於將所有內容提取為遞迴子檔；沒有程式執行或保證完整反編譯 |
| Office OLE／OOXML／RTF | 巨集、外部關聯、DDE／Equation Editor 等跡象、支援的嵌入物件提取及遞迴子檔 | `oletools` | 加密 Office 解密與補交密碼尚未提供；parser fallback／ZIP／XML 失敗、metadata 限制或 VBA project 存在但來源不可解析時為 partial |
| PDF | pages、metadata、actions／JavaScript、forms、嵌入檔描述及啟發式；解密後衍生子檔重新掃描 | `pypdf`／AES crypto backend；使用者提供的密碼可補交並從 checkpoint 續跑；RC4-40、AES-128、AES-256 R5／R6 有固定 fixture | 輸入上限 50 MiB；等待密碼、不支援加密、解析／資源限制保留未完成原因。`EFF != StmF`、stream 的 `/Filter /Crypt` override（含 `/Name /Identity`）或 `/EncryptMetadata=false` 目前不支援；建立明文子檔前回報 unavailable／partial，不建立子檔或反覆要求錯誤密碼。原始加密檔與解密子檔分開；PDF 附件尚未提取掃描。詳見 [PDF 密碼流程](pdf-password.md) |
| Windows LNK | 目標／參數等結構與啟發式 | `LnkParse3` | 不解析所有 shell extension，不執行捷徑 |
| Scripts | 支援副檔名與語法模式的指標、去混淆、IOC、啟發式 | 相應 Python 分析器 | 不執行 scripts；解碼候選不代表已完整還原程式 |
| ZIP | 逐檔 streaming 解壓、來源檔案樹、遞迴分析 | ZIP 傳統密碼；AES fallback 需要 `pyzipper` | 以實際 extractor 回應判斷加密方式可用性；不支援的方法或損壞內容要留下未完成原因 |
| 7z | bounded streaming writer、逐出現位置的子檔與遞迴分析 | `py7zr` 0.22；支援庫可處理的密碼／加密 headers | bounded writer 使用版本限定的 compatibility bridge；未知版本回報 unavailable，不能偷偷改用無界解壓 |
| RAR | 逐檔 streaming 解壓與遞迴分析 | `rarfile` 及可用的外部解壓器，例如 `unrar`／`unar`／`bsdtar` | 可處理的 RAR／加密版本依外部工具而定；缺工具或損壞檔案不能當成乾淨 |
| TAR、gzip、bzip2 | TAR 常規檔、gzip／bzip2 單一展開檔的 streaming 提取，再進遞迴分析 | Python 標準庫；無密碼參數 | symlink／special entries 不作可執行檔提取；`.tar.gz` 等透過多層子檔分析 |
| ISO | 格式辨識 | — | handler 尚為 stub，回報不支援，沒有 ISO 提取能力 |
| ELF、Mach-O、郵件、APK 等 | 通用階段仍可適用 | — | 尚無宣告完整的專用深度分析／子檔提取能力 |

已加入的 budget 驗收包含真實 ZIP／7z 提取、7z encrypted headers 密碼恢復、同名不同內容來源保留、巢狀 ZIP 共享累計 bytes、並發 reservation、retry high-water idempotency、PostgreSQL row-lock 累計，以及 timeout／取消後 parser 和外部 helper 停止寫入。RAR 的外部工具與所有加密變種、其他格式的全面相容性，仍需各自的實際 fixture 驗收。

2026-10-17 的第二批品質 corpus 新增 3 個 PE、5 個 OOXML、4 個 PDF 對照，已包含在 32／32 真實引擎通過案例中。
正常 PE 無 overlay 的回傳值已修正；OOXML 即使被辨識成 ZIP 仍進入 Office 分析，
外部關聯以 XML 結構解析，註解內文字不作 active target。合成 PE 沒有 executable section，
文件的指標內容也不執行。這批樣本不能代表所有真實 PE、Office 或 PDF 版本，
來源、預期及未完成原因見[靜態品質基準](static-quality.md)。這兩批的正式 worker／Pages 部署與三份 demo 報告已核對。

2026-10-18 的 PDF 密碼恢復程式與本機驗證已完成，一般原生基準 32／32 與獨立密碼案例 12／12 通過；
首批已取得使用者提供的 Job 切換與兩組原檔／解密子檔報告，證明實際解密掃描。
正確密碼產生獨立的解密 PDF 子檔，原檔 hash 不變，子檔重新執行實際 ClamAV／YARA 與適用靜態階段。
解密保留可讀的 active xref 物件，包括 catalog 無法到達的物件；不可讀物件、超限或派送失敗不能顯示內容已完成分析。
不支援的 `EFF != StmF` 與 `/EncryptMetadata=false` 在要求密碼前檢查；stream 的明確 `/Crypt` override
則在成功解鎖後、clone 前檢查。支援方式與限制見 [PDF 密碼說明](pdf-password.md)，
首批本機結果見 [2026-10-18 紀錄](milestones/2026-10-18-pdf-password.json)。
本次回饋修正改為每個加密檔案各三次被接受的密碼補交，正確亦計次；ZIP 使用一次不扣內層 PDF 額度，
仍受全站每日 20／每月 40 次 execution 限制。錯誤訊息在非同步分析確認後顯示，不以 POST 接受代替密碼正確。
2026-10-19 使用者人工確認錯誤提示、逐檔三次及父子檔高風險呈現通過，F-08 在本輪範圍完成。
新畫面及兩份完成 JSON 核對 `msrs-v1.2`、本檔 4 分／整體 84 分、解密子檔 84 分與逐檔已用 2／剩餘 1。
逐檔獨立及第三次限制依人工確認，沒有新增自動化雲端測試；最外層 ZIP 完整報告及 Pages deployment ID 未提供。
詳見 [雲端驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)；其他部署的更新順序與正式設定保存見 [回饋部署手冊](deploy-pdf-feedback.md)。

去混淆階段預設 `DEOBFUSCATION_MAX_FILE_SIZE=10000000` bytes。大於此上限的原檔仍可完成
ClamAV／YARA 等適用階段，但去混淆會以大小限制原因略過，static coverage 因此為 partial。
正式 v2 的 20,000,000-byte 文字檔已觀察到此行為；上傳大小上限與各分析器的處理上限分開看待。

## URL 觀察與選用衍生物

IOC 一律保留 URL／domain／IP 與可取得的 offset，不會因此下載或執行 URL。只有明確設定
`SANDBOX_ENABLE_URL_SUBMISSION=true` 才為觀察到的 URL 建立合成 `.url` shortcut 子檔；
這不是從 URL 取得的遠端內容。此選項共用 portable／queue artifact ports、root 預算與深度，
每份來源最多 50 個，遺漏／配額／派送失敗留下 partial 與原始 IOC；相同合成檔進入 ancestor
會停止循環。動態 URL detonation 還需要已啟用且可用的 sandbox provider。

評分政策 `msrs-v1.2` 延續零風險 IOC 原則，不因原始 URL／domain／IP 或多種類型觀察而單獨加分；
規則集 `1.1.0` 的 `network_iocs` 命中也保留為零風險權重的 context。
一般網址仍可出現在報告與來源證據中；額外結構、偵測或衍生內容依各自規則判斷，沒有目的地信譽查詢。

自架版同一提取內的重複內容保留獨立來源節點，但可省略重複派送。報告以 `analysis_reference`
引用同 root、相同 SHA-256／大小且已完成必要階段及子樹的直接來源；沿用節點不宣稱重新掃描，
來源階段與證據 IDs 分開呈現。來源缺失、失敗或不完整時仍為 unknown／partial。
Portable runner 逐 occurrence 分析並保留各自報告。父報告會聚合已驗證子檔案的 findings 與證據，
相同內容保留全部位置但風險只計一次，詳見[品質基準](static-quality.md)。

`msrs-v1.2` 另外將已驗證的高風險子孫作為各祖先有效風險下限；解密子檔 84 分時，
加密 PDF 及包含它的 ZIP 有效風險至少為 84 分／高風險。本檔直接分析與原始證據保留，
報告 `risk.local_risk` 及來源樹 `local_score` 分開顯示；高風險不是已確認惡意。
歷史報告不重寫，前端可對可核對身份的可見高風險子檔顯示醒目提醒。
Q-06 本批將缺乏佐證的 Base64 解碼保留為不加分觀察，PDF 名稱不再僅因可解碼便產生 4 分。
候選 JSON 保留內容、offset／length、canonical 標記與分類原因；`techniques_found` 僅列可評分技術，
`observed_techniques` 包含觀察。可讀文字、已知檔案標頭或 decoder-call 脈絡仍保留分析，
包括缺 padding／非標準 pad bits 的有效內容；這些佐證不等於執行或惡意證明。
候選去重與優先排序受既有數量、大小及協作時間限制約束，未處理完的內容保留 partial。
政策 `msrs-v1.2` 與 YARA 規則未改版；舊報告維持原分數。本批 Job 切換與三案新報告已核對，
正常 PDF 名稱 0、編碼網址 29、active PDF 84，詳見[雲端 smoke 紀錄](milestones/2026-10-19-base64-cloud-acceptance.json)。
詳見[品質基準](static-quality.md)與 [Job 更新手冊](deploy-base64-quality.md)。


## root 累計與時間窗

`analysis_budgets` 保存 root 工作的 max files／expanded bytes；`budget_reservations` 保存穩定的 job＋提取來源＋出現位置身份及已保留的 high-water marks。所有子工作使用同一 root 的 PostgreSQL row lock 更新額度；portable runner 使用相同契約的 in-memory adapter，並將 reservations 寫入 checkpoint。

檔數與 bytes 是**整棵 artifact tree 的累計提取額度**，不是原始上傳大小，也不是每個子檔重新取得一次配額。同內容出現在不同位置仍需保留来源；同名 ZIP／7z entries 使用不同磁碟目標避免互相覆寫。重試相同 immutable output 不重複扣額，較大的 high-water mark 只扣增加部分。預先保留的宣告大小與失敗／中止提取的已用額度不自動退回，以避免並发或重試擴大可寫出的總量。

deadline 是**每次 execution attempt 的共用時間窗**：該 attempt 所有 stages 共用它；portable 同一次 run 的遞迴子檔也共用它。佇列中的另一個 execution attempt 或密碼補交後的 resume 開新時間窗，保留原 root 的 files／bytes。新時間窗不延長已經在跑的舊 attempt。它不是整棵樹從第一次上傳到最後完成的絕對 wall clock 上限，等待密碼或佇列閒置不會讓下一次有效恢復一開始就過期。

`ROOT_BUDGET_MAX_FILES`、`ROOT_BUDGET_MAX_BYTES`、`ROOT_BUDGET_TIMEOUT_SECONDS` 決定 root limits；單次解壓還有 `EXTRACTION_MAX_FILES`、`EXTRACTION_MAX_BYTES`、`EXTRACTION_MAX_SINGLE_BYTES`、`EXTRACTION_MAX_RATIO`、`EXTRACTION_TIMEOUT` 及深度限制。既有 root 的累計 limits 在建立時固定，之後更改設定不會放寬已存在工作的額度。

## 提取邊界與未完成報告

archive、Office／RTF 提取與 PDF 解密在 Linux 的獨立 process group 中執行。parent 在寫出前接收 reservation，原子更新 root budget；已預扣的大小涵蓋後續 streaming chunks。超出 deadline 或外層 stage 被取消時，parent 終止 parser 及同一 process group 的外部 decoder helpers。這個邊界可以停止提取，不依賴 `wait_for(to_thread(...))` 的表面 timeout。

OOXML 嵌入檔先保留宣告大小，再以限制讀取；關聯 XML 有獨立 parse cap。第三方 parser 的 internal allocations、metadata 解析和其他分析器的記憶體，仍需 worker／container 的記憶體上限；提取 bytes budget 不是 parser heap 上限。Linux process boundary 是目前支援的執行環境，未提供 Windows／其他平台相同的強制終止能力。Stage／budget checkpoint 可以恢復持久化成果，但終止時尚未完成的 output 不會被誤稱已分析。

配置額度不足、超時、深度截斷、parser 或子工作提交失敗，應留下 partial／limited coverage 及原因，保留已有證據。檔案損壞、格式不支援、工具不可用與等待密碼，也不能替換為 clean。來源循環或重複內容可以免去重複派送，但來源節點與原因仍需呈現在檔案樹。
