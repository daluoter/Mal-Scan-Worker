# 部署 PDF 附件與 Office 嵌入檔案到既有 demo

更新日期：2026-10-20（Asia/Taipei）。F-03 程式與本機驗證完成；正式部署及新上傳驗收另列 F-11。
執行前先以發布訊息核對 commit、CI 與本機驗證已通過，不能僅因本手冊存在就認定候選版已可發布。
能力與限制見[文件附件說明](document-embedded.md)。

本批更新 **Cloud Run Job** 的共用靜態核心。既有 Pages、Cloudflare Worker、dispatcher、R2、IAM、secrets、
逐檔密碼契約與額度沿用；本手冊沒有發布 Worker 範本或重新建立資源的步驟。
在已登入 GCP 的 Cloud Shell 分段執行；非同步建置送出後可以斷線，重連查 status 接續。

API Token、OAuth 設定、R2 keys、HMAC、工作 capability、真實文件密碼與原始報告保持私有，
不要加入 Git、公開 issue 或命令列。下面生成的是公開惰性測試檔；公開 fixture 密碼不是服務憑證。

## 1. 取得已發布來源

建立獨立來源與 marker，保留既有 Office／PDF／P0 操作資料。先比對 `git rev-parse HEAD` 與發布訊息的 commit；
若 main 已前移，先在新來源切到該 commit，再執行後續步驟。

```bash
(
  set -e
  umask 077
  V2_EMBEDDED_SOURCE=$(mktemp -d "$HOME/malscan-v2-document-embedded.XXXXXX")
  git clone --quiet https://github.com/daluoter/MalScanWorker.git "$V2_EMBEDDED_SOURCE"
  cd "$V2_EMBEDDED_SOURCE"
  git rev-parse HEAD
  test -f worker/quality/document-embedded-v1.json
  test -f worker/src/malscan_worker/analyzers/pdf_attachments.py
  test -f worker/src/malscan_worker/analyzers/office_embedded.py
  pwd > "$HOME/malscan-v2-document-embedded-source-path.txt"
)
```

新開一批本機測試不會自動更新正式 Job。不要重複上傳同一批檔案來判斷舊版是否已變更。

## 2. 保存現有 Job 並送出一次建置

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-document-embedded-source-path.txt")"
  V2_EMBEDDED_PREPARE=$(mktemp "$HOME/malscan-v2-document-embedded-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_EMBEDDED_PREPARE"
  python3 - "$V2_EMBEDDED_PREPARE" <<'PY_STATE'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-document-embedded-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY_STATE
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-document-embedded-state-path.txt")"
)
```

工具保存舊映像 digest 與 Job 設定，建置候選映像並執行官方簽章病毒庫與正常／EICAR 離線控制。
這是人工觸發更新；P0-12 的自動排程尚未完成。Cloud Build、映像／來源儲存與 smoke 可能產生費用。
送出後可離開 Cloud Shell。狀態不明時先查下一節，不再次 submit 或新建第二份 state。

## 3. 重連查詢，確認後切換 Job

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-document-embedded-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-document-embedded-state-path.txt")"
)
```

等待 `phase=build_verified`、`build_status=SUCCESS`、`candidate_controls.success=true`，
核對候選 digest、病毒庫日期與規則指紋，再切換：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-document-embedded-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-document-embedded-state-path.txt")"
)
```

預期 `phase=promoted`。這只更新映像，尚未執行新掃描。遇到 drift、timeout 或回應遺失時保留 state，
重新查詢 status；不要重建資源、重送 promote 或放寬設定來跳過核對。
本批沒有前端或控制層變更，直接使用既有正式 <https://malscan-v2-demo.pages.dev>。

## 4. 在 Cloud Shell 產生固定 smoke 檔

以下只使用標準函式庫配方與已凍結的公開資料，不需在 Cloud Shell 安裝整套 worker、解密工具或掃描器。
每個輸入都先與 manifest 的大小及 SHA-256 比較，產物保存在新私人目錄。

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-document-embedded-source-path.txt")"
  V2_EMBEDDED_FIXTURES=$(mktemp -d "$HOME/malscan-v2-document-embedded-fixtures.XXXXXX")
  python3 - "$V2_EMBEDDED_FIXTURES" <<'PY_FIXTURES'
import hashlib
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path('worker/src').resolve()))
from malscan_worker.quality.document_embedded_fixtures import build_document_embedded_fixture
suite = json.loads(Path('worker/quality/document-embedded-v1.json').read_text())
cases = {case['profile']: case for case in suite['cases']}
output = Path(sys.argv[1])
for profile, extension in [
    ('pdf-name-tree-text', 'pdf'),
    ('pdf-flate-eicar', 'pdf'),
    ('office-embedded-pdf', 'docx'),
]:
    payload = build_document_embedded_fixture(profile)
    assert len(payload) == cases[profile]['bytes']
    assert hashlib.sha256(payload).hexdigest() == cases[profile]['sha256']
    target = output / f'{profile}.{extension}'
    target.write_bytes(payload)
    target.chmod(0o600)
    print(target)
PY_FIXTURES
  printf '%s\n' "$V2_EMBEDDED_FIXTURES" > "$HOME/malscan-v2-document-embedded-fixtures-path.txt"
)
```

`pdf-flate-eicar.pdf` 包含標準 EICAR 防毒測試字串，是用來確認防毒路徑的惰性控制，不是惡意程式。
電腦上的防毒軟體可能阻擋下載或隔離它；保留該結果即可，不要停用防護或改變 frozen bytes 來繞過。
若該檔無法進入雲端，上傳驗收先記其缺少證據，另外兩個案例仍可進行。

從 Cloud Shell 下載測試檔，再透過正式 Pages 上傳；這不是上傳到 GitHub，也不是在舊 upload-only PoC 網站測試。
保存原瀏覽器分頁，capability 在該分頁的 sessionStorage；刷新可保留，關閉分頁通常會失去存取權。

## 5. 在原有額度內驗收

三個基本 smoke 是三個新 root，預計 **3 次 executions**，沒有密碼補交。
先確認剩餘額度；目前每日 10 工作、每日 20／每月 40 次 executions，包含密碼續跑與不確定派送。
不足時等待重置，不提高額度或反覆建立相同工作。

| 檔案 | 要核對的內容 |
| --- | --- |
| `pdf-name-tree-text.pdf` | 本機基準 2 節點／0 分；PDF 出現真正的文字附件子檔，hash／大小與固定預期一致，`pdf-attachment/…` 來源、`attachment_extraction` 及子檔 AV／YARA coverage 可核對 |
| `pdf-flate-eicar.pdf` | 本機基準 2 節點／100 分；解壓後附件 bytes 是 EICAR 控制，附件的 ClamAV 有實際命中；父報告可回溯該子檔與有效風險，不能只看外層 PDF 是否命中 |
| `office-embedded-pdf.docx` | 本機基準 8 節點／0 分、提取 7 檔／2,226 bytes；非 `.bin` 的 PDF 套件 member 也會提取並成為子檔；來源保留 member 路徑，實際 PDF 頁數及掃描可核對。format／document／archive 的不同來源節點屬固定預期，不以節點數增加便判為不同惡意內容 |

提取的 `submitted` 不是掃描完成。最終核對根報告的所有節點、未完成原因與子檔 coverage，
下載最外層完整 JSON，而非只有內嵌檔案詳細頁的子樹。
原始輸入 hash 不變；需要同時有實際子檔 bytes 身份、來源、掃描結果，附件名稱清單不能代替。
規則／評分維持現有版本；分數與節點數依本批 native manifest／報告核對，不套用先前 PDF 84 分或 Office 0 分。

PDF 附件為加密 PDF 的密碼續跑另有本機固定案例；不是這三個基本 smoke 的雲端驗收範圍。
如要另外雲端演練，先計算初次、錯誤及正確補交所需 executions，分別保存等待、錯誤與完成證據；
每個加密檔案各三次的額度不等於整個 root 只有三次，仍受全站 execution 上限限制。

## 6. 保存證據、清理與回退

私人保存來源 commit、建置 ID、舊／新映像 digest、promotion 狀態、每個 root ID、完整報告與 status。
真實密碼、capability、secret payload 及原始文件保持私有；公開里程碑只摘錄審查過的 metadata 與 hash。
只有實際取得新部署與雲端報告後，才能按所列案例更新 F-11；本機測試或 Job 更新本身不代替正式 smoke。

每個 root 的 `retention_expires_at` 從 status 保存，不由完成時間或報告推算。
保留期到期加 20 分鐘後，依[保留期手冊](cloud-demo-operations.md#4-到期撤權與實體清理)核對該 root 的
七個 R2 前綴及工作／報告 API 撤權，記入 P0-18。空的 R2 清單不能證明 DO 資料列已刪除，P0-06 維持獨立待辦。

若候選版出問題，先保存診斷並停止新提交，再使用本批來源與 state 執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-document-embedded-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py rollback \
    --state-dir "$(cat "$HOME/malscan-v2-document-embedded-state-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-document-embedded-state-path.txt")"
)
```

回退後還要核對 digest、設定與實際可用性。提供命令不表示已演練，P0-11 真實雲端回退維持待辦；
P0-12 自動簽章病毒庫更新、P0-14 長期成本及 P0-15 Cloudflare 用量也不因本次功能交付結案。
