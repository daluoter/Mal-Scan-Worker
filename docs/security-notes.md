# 安全通知核對紀錄

更新日期：2026-11-12（Asia/Taipei）。只記錄已核對的位置、用途與處理狀態，不保存通知信原文或真實憑證值。

## 2026-11-12：公開維運手冊的範圍核對

使用者詢問公開操作步驟與指令是否造成資安疑慮。本次檢查 P0-12 首批交付至 `9008910` 的 16 個提交、相關手冊與追蹤中的私人檔案名稱。
Gitleaks 8.24.3 對此提交範圍未發現秘密；完整待提交檔案快照也未命中。人工閱讀未發現本輪手冊包含真實 Token、私鑰、HMAC 值、報告 capability 或完整私人設定。
這些是指定範圍的程式／文件檢查，沒有另行登入 Google Cloud 重讀現行 IAM，也不是整個歷史或應用程式沒有漏洞的保證。

公開 Google 管理指令不會授予權限。REST client 在執行時透過操作者的 `gcloud` 身分取得短效憑證，僅送往允許的 HTTPS host，不將 Token 或原始 provider 錯誤內容印出；Google API 仍需對應 IAM 授權。
一般程式、通用操作方法與必要的驗收摘要可公開；私有 plan、完整 Job／環境設定、Cloudflare 下載設定、原始 checkpoint、物件 metadata 基準、原始財務資料及可授權的 URL／憑證應保留在私人操作目錄。

既有文件包含實際 project／bucket／服務帳號名稱、Build ID、digest 與時段。它們不是登入秘密，但會降低外部辨識環境的成本；後續新增紀錄優先使用必要的彙總與代號，精確物件名稱、generation、私人基準 fingerprint 與操作快照保持私有。
已公開且不具授權能力的 metadata 不因本次詢問自動要求憑證輪替或強制重寫 Git 歷史；若另發現真實憑證，仍依下方撤銷／輪替原則處理。

本次另補 `.gitignore`：排除私人自動更新 plan 目錄、基準／演練／通知／apply-state sidecar、操作路徑指標及私人 billing 匯出目錄。
目前這些私人 sidecar 未被 Git 追蹤，操作手冊也將它們存於 Cloud Shell HOME 的私人目錄；忽略規則補上的是手動複製進 checkout 時的防誤提交。
`.gitignore` 不會移除已追蹤檔案或舊提交，也可被 `git add -f` 略過，因此每次推送仍須審查實際差異與掃描待提交內容。

## GitGuardian Generic Password：公開合成 PDF 測試資料

使用者回報通知時間為 2026-10-18 21:28:31（Asia/Taipei），即 13:28:31 UTC。
提供的[公開 commit 連結](https://github.com/daluoter/MalScanWorker/commit/95396c19155e7445aa8a598b4440282e769e9b29#diff-8e134343842f6d7b98c4653252550665b3224dbe2ba46cdfd6b5b4f1043ac019R172)
指向 `worker/src/malscan_worker/quality/pdf_password_acceptance.py` 第 172 行；目前對應第 177 行。
已核對檔案路徑的 SHA-256 與 diff anchor 完全相符。

該行傳給 fixture builder 的字串是合成 PDF 的 **profile 識別名稱**。函式定義位於
[`pdf_password_fixtures.py`](../worker/src/malscan_worker/quality/pdf_password_fixtures.py)：
以 profile 查詢固定測試輸入，解碼 bytes 後核對大小與 SHA-256；它不接受登入憑證。
周邊密碼恢復流程使用模組明確宣告公開的 fixture 密碼，僅用於固定測試 PDF／ZIP。

**判定：依提供的精確連結，該位置是非憑證測試資料，屬 Generic Password 誤報。**
沒有理由因這一筆輪替 Cloudflare／Google Cloud 憑證或重寫公開 Git 歷史。
這個判定只涵蓋所提供的位置，不是其他告警或整個儲存庫的無秘密保證。
若 GitGuardian 詳細事件指向另一個值、檔案或範圍，應重新核對。

使用者可在 GitGuardian 的這一筆事件標記 **False positive**，理由可填：

> Synthetic PDF fixture profile identifier, not an authentication secret. Nearby public fixture passwords are test data only and are not used for production access.

平台上的標記／結案尚未由本專案操作，P0-19 繼續追蹤該步驟。
沒有新增整個檔案或 Generic Password 類型的忽略規則，也沒有停用偵測器。

## 其他密碼來源的處理原則

F-02 的 [`office_password_fixtures.py`](../worker/src/malscan_worker/quality/office_password_fixtures.py)
也包含明確標示為公開測試用途的 Office／ZIP 密碼。它們只解開同模組凍結的合成檔案，
不授予雲端或服務存取權。Office 驗收器另檢查這些值沒有寫入報告、日誌與 checkpoint；
沒有新增 Generic Password 或整個 fixture 檔案的忽略規則。未來若收到其他通知，仍須逐筆核對位置與用途。

- 公開 fixture 密碼不授予服務存取權；不得拿它當真實系統密碼。
- Compose 的固定開發預設密碼用於資料庫／物件儲存／佇列；若沿用在可連線的主機上，它們會成為真實可利用的憑證，部署者應另設強密碼及存取限制。沒有因此認定目前雲端 demo 使用這些值。
- 真實 API Token、資料庫密碼、HMAC 或私鑰若曾公開，應撤銷／輪替、更新私有設定並檢查使用紀錄；只刪除檔案或後續 commit 不會讓舊憑證失效。歷史重寫另行評估，不自動 force push。
- Gitleaks 與 GitGuardian 的規則不同。Gitleaks 零發現只代表該次掃描範圍與規則未命中，不能取代對另一個通知的逐筆核對。
