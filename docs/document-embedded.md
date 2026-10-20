# PDF 附件與 Office 嵌入檔案

更新日期：2026-10-20（Asia/Taipei）。F-03 已完成程式／本機驗證；正式雲端驗收另外追蹤 F-11。
本頁只宣告下列提取範圍，驗證結果見[進度清單](project-status.md)及[品質基準](static-quality.md)。
F-11 已核對使用者部署輸出與 PDF 文字附件報告，1／3 通過；另兩案仍待正式證據，見[本輪紀錄](milestones/2026-10-20-document-embedded-cloud-acceptance.json)。

這項功能將文件裡實際包含的檔案取出，建立有來源的子檔，再執行相同的 ClamAV、YARA、IOC、
格式分析與適用的文件分析。例如 PDF 附有 ZIP，ZIP 再包含 Office 文件，報告會保留各層關係。
文件、巨集、附件與內嵌程式都不執行；外部路徑及網址只作觀察，不取得遠端內容。

## PDF 的宣告範圍

- catalog 的 `/Names /EmbeddedFiles` 名稱樹，包含 `/Kids` 分支。
- catalog 與 page 的 `/AF` associated files。
- page 的 `/FileAttachment` annotation 所指向的 filespec。
- filespec `/EF` 中實際存在的嵌入 stream；支援沒有 filter，或單一 `FlateDecode`／`Fl` 且 predictor 為 1 的內容。

成功提取保留解碼後的完整 bytes、SHA-256、大小、安全檔名與 `pdf-attachment/…` 來源。
同一個 filespec／stream 被不同位置引用時，保留 reference aliases；不同實際 stream 即使檔名或內容相同，
仍有各自的來源 occurrence，不會以檔名互相覆寫。附件名稱與外部路徑都不是可信的磁碟目標。

不支援的 filter／filter chain／predictor、損壞或缺失 stream、外部檔案參照及資源截斷會留下原因與 partial。
這批沒有宣告提取 catalog 無法到達的任意孤立附件物件、PDF Portfolio 的所有變種、RichMedia 或所有 PDF filter。
「PDF 可解析」不代表所有附件內容都已取得；以 `attachment_extraction`、`embedded_files` 及子檔 coverage 為準。

加密 PDF 先沿用既有的[密碼流程](pdf-password.md)，正確解鎖後由 `pdf-decrypted` 子檔提取附件。
附件本身若為需要密碼的 PDF、Office 或壓縮檔，再對該檔案等待補交；每個加密檔案各用既有三次額度。

## Office 的宣告範圍

OOXML 除了既有 `.bin` 嵌入物件，還尋找 `word/embeddings/`、`xl/embeddings/`、`ppt/embeddings/` 下的常規檔，
以及內部 `package`／`oleObject` relationship 指向的套件 member，因此不再只靠 `.bin` 副檔名決定是否提取。
關聯 target 需要能安全解析到目前 ZIP 裡唯一的檔案；外部關聯不下載，缺失、歧義或無法解析會保留未完成原因。

OLE Compound File 的支援提取限明確識別的 `\u0001Ole10Native` 內嵌 Package payload 與原始 `Package` stream。
會先核對有界的 container、stream 與 native metadata，再保留 payload 原始 bytes 及 hash。
原始路徑只是來源描述，不能要求分析器開啟使用者電腦或伺服器上的其他檔案。
linked native object、未識別的 OLE 應用程式格式、截斷或歧義資料不會被假裝還原成功。

例如 OOXML 裡的 OLE `.bin` 先成為包裝子檔，該子檔被分析時才產生真正的 Package 內容，
不把內容直接攤平到最外層文件。每多一層仍受深度限制；已到上限時，報告保留 limited／partial。
本批不更改[Office 密碼解鎖](office-password.md)的演算法或已驗收的加密格式範圍。

既有 format、document 與 archive 階段可能各自觀察同一份 OOXML member，報告保留不同來源的 occurrence。
Portable runner 逐 occurrence 分析；自架佇列路徑保留同批 duplicate／cycle 記錄與來源原因。
重複記錄本身不是完成證據，必須另有可核對的掃描結果才能當作已分析的內容引用。
相同內容的存在位置不能被抹去，重複來源亦不代表多份不同惡意程式。

## 如何讀報告

提取、提交子工作與掃描完成是三件事：

1. 提取項目記錄 stream／member 的來源、hash、bytes 與結果，或未提取原因。
2. `extracted_outputs` 與相應 feature 記錄 `analysis_state`、已建立的 `artifact_id`；`submitted` 只代表已送入分析流程。
3. 子檔的 stage coverage 與最終報告才證明實際完成哪些掃描。派送失敗、等待密碼或限制不當成 clean。

PDF 使用 `attachment_extraction`／`embedded_files`；Office 使用 `embedded_extraction`，列出宣告 scope 與逐項狀態。
原始包裝檔 hash 不變；可讀的父檔報告與子檔詳細報告可分別下載。高風險後代沿用 `msrs-v1.2` 的逐層風險下限，
本檔直接分數及子檔來源仍分開保存。高風險是偵測／結構證據，不表示已執行內容。

## 資源與失敗邊界

PDF 與 Office 文件輸入仍受 50 MiB 上限。PDF 附件每份文件最多 30 個、單檔最多 20 MiB，
並受設定中的較小提取上限；PDF 尋訪最多 4,096 nodes，名稱樹深度最多 32。
Office 嵌入物件最多 30 個、單檔最多 20 MiB，CFB／OOXML metadata、stream/member 數與路徑另有上限。
這些是分析器上限，不會放寬整棵 root 的檔數、bytes、時間窗或深度。

demo 仍為上傳 20,000,000 bytes、整樹提取 20 檔／100,000,000 bytes／深度 3；
密碼續跑保留原有 high-water reservations，不因解鎖而重發提取額度。
format、document 與 archive 的不同來源 occurrence 各計入額度；同階段的同來源續跑才重用 reservation。
有限解碼／讀取與寫入前 reservation 共同限制輸出；parser 在可被強制停止的 Linux process group 中執行。
第三方 parser 解析 metadata 的內部記憶體仍需容器記憶體限制，bytes budget 不能代替 heap 限制。

部分內容失敗時保留已成功提取及掃描的兄弟檔案，並留下剩餘內容的未完成原因。
報告中的「沒有命中」只能描述已完成的範圍，不能推定未提取附件安全。

正式更新操作見[Job 部署手冊](deploy-document-embedded.md)。F-03 本機證據與 F-11 正式 smoke 分開記錄；
DO 清理、真實回退、自動病毒庫更新、長期成本及每批工作的保留期核對仍按各自 P0 ID 追蹤。
