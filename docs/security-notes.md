# 安全通知核對紀錄

更新日期：2026-10-19（Asia/Taipei）。只記錄已核對的位置、用途與處理狀態，不保存通知信原文或真實憑證值。

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

- 公開 fixture 密碼不授予服務存取權；不得拿它當真實系統密碼。
- Compose 的固定開發預設密碼用於資料庫／物件儲存／佇列；若沿用在可連線的主機上，它們會成為真實可利用的憑證，部署者應另設強密碼及存取限制。沒有因此認定目前雲端 demo 使用這些值。
- 真實 API Token、資料庫密碼、HMAC 或私鑰若曾公開，應撤銷／輪替、更新私有設定並檢查使用紀錄；只刪除檔案或後續 commit 不會讓舊憑證失效。歷史重寫另行評估，不自動 force push。
- Gitleaks 與 GitGuardian 的規則不同。Gitleaks 零發現只代表該次掃描範圍與規則未命中，不能取代對另一個通知的逐筆核對。
