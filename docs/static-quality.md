# 靜態分析品質基準

2026-10-16：P1 第一批實作。目標是讓偵測結果、分析範圍與子檔案證據可以重現及核對。
這份基準使用合成資料與標準 EICAR 測試字串，不是實際惡意程式樣本庫，也不能據此估計真實世界的偵測率。

本批實測：真實引擎完整流程 18／18 通過；worker 618 passed／3 skipped、backend 160 passed／1 skipped、
frontend 28 passed。四個 skip 均為 PostgreSQL opt-in。Ruff、strict mypy 與前端 typecheck／lint／
cloud-demo build 通過。完整案例使用斷網、唯讀、非 root 容器及現行來源／規則掛載，
ClamAV 1.4.3／DB 28152、YARA 4.5.4；時間、雜湊與逐案例結果見[允許欄位紀錄](milestones/2026-10-16-static-quality.json)。
此批未部署到正式 GCP／Cloudflare，既有雲端驗收另見 [P0 紀錄](milestones/2026-10-15-p0-acceptance.md)。

## 版本化樣本與驗收

[`worker/quality/corpus-v1.json`](../worker/quality/corpus-v1.json) 保存版本、每個 fixture 的 SHA-256、
生成方法與案例預期。ZIP 的時間、來源權限、壓縮方法及 entry 順序固定；gzip 不寫入當前時間。
fixture 的 bytes 或預期需要改變時，必須審查 diff 及更新版本，執行器不會自動接受新的雜湊。

第一批有 18 個案例：

| 類型 | 範圍 | 主要驗收 |
| --- | --- | --- |
| 正常內容 | 純文字、JSON 設定、一般網址、Java API 文件 | 成功的掃描與零命中分開檢查；記錄已知寬鬆規則命中 |
| 測試／指標 | EICAR、PHP 字串指標、編碼 URL | 真實引擎命中、規則身份、來源與解碼證據；不執行樣本 |
| 子檔案 | 巢狀 ZIP、相同內容不同位置、ZIP／gzip 內的 EICAR | 每個 occurrence 保留身份；子檔案命中可回溯，繼承風險欄位一致 |
| 失敗／限制 | 損壞 ZIP／PDF、ClamAV 缺失、YARA 空目錄／無效規則、去混淆檔案大小／候選數、深度限制 | 明確 partial、階段原因與保留證據，不能因 `infected=false` 或空命中就判定掃描成功 |

正常樣本仍可能觸發啟發式規則。第一版特別保留兩筆可重現的寬鬆命中：
一般 HTTPS 網址觸發 `network_iocs`；Java `getInputStream()` 文件觸發 `jsp_webshell`。
品質摘要將它們列在 `benign_cases_with_rule_hits`，不把它們算成成功識別惡意程式。
基準通過代表目前宣告的行為與證據契約通過，不代表誤報問題已全部解決。

## 執行完整本機基準

需要 Python 3.11、worker 的固定依賴、libmagic、實際 ClamAV scanner 與可用的病毒資料庫。
以本機 CLI scanner 為例，從 repository 的 `worker` 目錄執行：

```bash
YARA_RULES_PATH="$PWD/rules" \
CLAMAV_MODE=cli \
CLAMAV_DATABASE_PATH=/absolute/path/to/verified-clamav-databases \
SANDBOX_ENABLED=false \
poetry run python -m malscan_worker.quality \
  --manifest quality/corpus-v1.json \
  --output-dir /absolute/path/to/new-quality-run
```

沿用現有環境設定時，也可使用設定好的 ClamAV daemon。任一必要引擎不可用，正常案例會失敗；
失敗控制案例則實際使用不存在的執行檔、空規則目錄或語法錯誤規則，不以 mock 代替偵測器。
每個案例使用獨立 Python process、原檔及 checkpoint，避免故障控制汙染其他案例。
`--case CASE_ID` 可重複使用以定位失敗；部分選取不等於完整基準通過。

輸出目錄必須是新路徑。每個案例保留完整 report 與 runner log，根目錄的
`quality-report.json` 保存 corpus 版本、manifest／fixture／report 雜湊、耗時、
各案例 coverage／命中／失敗、已知限制與總結果。程序退出碼 0 才表示所選案例皆通過。
這些案例只使用本機 stores，不呼叫 Cloud Run 或外部沙箱。

一般 worker CI 的 pytest 另外驗證固定樣本雜湊、原生 YARA 命中，以及能否拒絕
遺失階段、重複階段、錯誤來源身份、失敗掃描及互相矛盾的 report 欄位。
完整 ClamAV 容器基準與這些一般測試分開記錄。

## 子檔案與重複內容的證據

Portable runner 仍逐 occurrence 執行分析；自架版可能略過同一次提取中的相同內容派送。
每個來源位置都保留獨立節點，新的 `analysis_reference` 區分：

- `direct`：該節點的持久化報告與工作、SHA-256、大小及 root 身份相符；是否完成仍由 coverage 判斷。
- `inherited`：該 occurrence 沒有重新掃描；明確引用同 root、同 bytes、相同副檔名分析脈絡、已完成必要階段的直接來源。
- `unresolved`：缺少足夠的來源證據，維持 unknown／partial。

沿用節點的直接 `stage_coverage` 保持空白，來源階段在 `source_stage_coverage` 顯示。
`direct_finding_ids` 與 `inherited_finding_ids`、相應 evidence IDs 分開記錄。
來源未完成、缺少必要階段、identity 不符、跨 root 或循環引用都不能讓 duplicate 顯示完整分析。
這些引用在報告組裝時建立，不複製完整子報告，也不需要新增資料庫 migration。

父報告會彙整已驗證子檔案的 findings、IOC 與解碼證據。證據 ID 以 artifact 身份區隔，
避免不同檔案的 `ev-1` 相撞；來源 report 的直接評分證據不會因此被改寫或重複計分。
相同 bytes 的風險只計一次，選取最強、最近的有效 occurrence，不再受資料庫／提取排列順序影響。
報告保留所有 occurrence 的路徑，讓直接偵測與父檔繼承的風險可以分開查閱。

## 工具與規則內容

YARA 的引擎版本、規則集版本、規則內容 SHA-256 分開記錄。
[`worker/rules/manifest.json`](../worker/rules/manifest.json) 記錄目前 5 個檔案、15 條規則的
來源 commit、逐檔雜湊、規則分類及限制。`verified` 的範圍僅是本機檔案與原生解析出的
規則清單一致，不是作者身份簽章或準確率保證。

目前 repository 未提供可確認的規則授權，清單如實標為 `NOASSERTION`，不是授權許可。
外部規則來源、授權及更新／停用政策仍需在擴充規則前確認。
自訂規則目錄沒有 manifest 時仍會掃描，並明確顯示 unverified；規則語法錯誤或命名空間衝突則失敗。
EICAR 規則標為 test，其餘現有規則為 heuristic，不將「高嚴重度」直接等同已確認惡意。

ClamAV 報告另外提供 `engine_version`、`database_version` 與 `database_timestamp`，
保留舊 `tool_version` 以相容既有報告。病毒庫所載時間不是線上更新檢查，也不保證當下最新。

## 後續擴充

接續優先處理有量測證據的寬鬆規則誤報，再增加具有來源與預期的 PE、Office、PDF、LNK
結構樣本，以及更廣泛的密碼、附件及損壞變種。增加規則或 parser 前，都應同時增加正常對照與失敗案例。
真實惡意樣本偵測率、所有格式相容性與動態沙箱仍需要各自的驗收，不包含在這批 18 案例的結論內。
