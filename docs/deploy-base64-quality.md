# 更新 PDF／Base64 品質修正到既有雲端 demo

本批只更新 Cloud Run 分析 Job 的映像；使用現有 Worker、dispatcher、Pages、bucket、IAM 與 secret。
本機驗證與雲端部署分開記錄，舊報告不會重新評分。使用原本已登入 Google Cloud 的 Cloud Shell。
2026-10-19 已核對使用者提供的 Job 切換與三案報告，見[雲端驗收](milestones/2026-10-19-base64-cloud-acceptance.json)；以下供其他部署或重現使用。
日／月額度與資料保留政策不變；Cloud Build、映像與測試仍可能產生用量。

## 1. 取得來源，保存重連路徑

先確認發布訊息的 commit 已通過 CI。在全新目錄取得來源，核對印出的 commit 與發布訊息一致再繼續；
若不同，於這個新目錄切換至發布訊息指定的 commit，不要覆蓋先前部署目錄。

```bash
(
  set -e
  umask 077
  V2_BASE64_SOURCE=$(mktemp -d "$HOME/malscan-v2-base64.XXXXXX")
  git clone --quiet https://github.com/daluoter/Mal-Scan-Worker.git "$V2_BASE64_SOURCE"
  cd "$V2_BASE64_SOURCE"
  git rev-parse HEAD
  python3 - <<'PY'
import json
from pathlib import Path
corpus = json.loads(Path('worker/quality/corpus-v5.json').read_text())
assert corpus['corpus_version'] == 'static-quality-v5.0.0'
assert corpus['policy_version'] == 'msrs-v1.2'
assert len(corpus['cases']) == 40
print('Base64 quality source verified; compare the commit above with the release message.')
PY
  pwd > "$HOME/malscan-v2-base64-source-path.txt"
)
```

## 2. 保存現行設定並只送出一次建置

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-base64-source-path.txt")"
  V2_BASE64_PREPARE=$(mktemp "$HOME/malscan-v2-base64-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_BASE64_PREPARE"
  python3 - "$V2_BASE64_PREPARE" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-base64-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-base64-state-path.txt")"
)
```

建置刷新並驗證官方 ClamAV 簽章資料庫、執行 clean／EICAR 控制，再發布映像。
這是人工操作流程，尚無自動排程。建置送出後可斷線；重新連線查詢，避免重送。

## 3. 查詢與切換

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-base64-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-base64-state-path.txt")"
)
```

取得 `phase=build_verified`、`build_status=SUCCESS` 與 `candidate_controls.success=true`，
核對資料庫日期、YARA 指紋與映像 digest 後執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-base64-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-base64-state-path.txt")"
)
```

預期 `phase=promoted`。若回應不明或出現設定差異，先保留 checkpoint 並重查 `status`，不要重建資源。

## 4. 產生三份固定 smoke 檔案

以下只使用 Python 標準函式庫，核對固定 SHA-256，不執行檔案內容：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-base64-source-path.txt")"
  python3 - <<'PY'
import hashlib
import json
import runpy
from pathlib import Path
corpus = json.loads(Path('worker/quality/corpus-v5.json').read_text())
build_document = runpy.run_path(
    'worker/src/malscan_worker/quality/document_fixtures.py'
)['build_document_fixture']
output = Path.home() / 'malscan-v2-base64-smoke'
output.mkdir(mode=0o700, exist_ok=False)
for name in ('pdf-name-dictionary', 'pdf-encoded-url-string', 'pdf-active-actions'):
    spec = corpus['fixtures'][name]
    payload = spec['text'].encode() if spec['kind'] == 'text' else build_document(spec['profile'])
    assert hashlib.sha256(payload).hexdigest() == spec['sha256']
    (output / (name + '.pdf')).write_bytes(payload)
print(output)
PY
)
```

若目錄已存在，先確認先前產物並沿用，不覆寫保留證據。下載三個 PDF，再到正式
<https://malscan-v2-demo.pages.dev> 上傳；不是舊 upload-only PoC 網頁。這是三個新工作，沿用每日 10 工作、
每日 20／每月 40 executions 的現有限制；額度不足便等待重置，不調高限制。

| 新工作 | 預期 |
| --- | --- |
| `pdf-name-dictionary.pdf` | 正常 PDF、自訂字典名稱；本檔 0 分。弱候選保留 `score_eligible=false`、offset／length，`techniques_found=[]` |
| `pdf-encoded-url-string.pdf` | 保留解碼網址 `https://quality.invalid/inert` 與 `score_eligible=true`，不得因 PDF 格式而忽略；綜合分數為 29（Base64 4＋既有 YARA 25） |
| `pdf-active-actions.pdf` | 惰性 Launch／JavaScript／OpenAction 結構仍為 84／高風險，非已確認惡意或執行行為 |

完整 JSON 應為 `msrs-v1.2`、YARA ruleset `1.1.0`，規則指紋與 corpus-v5 相同；新 Base64 候選
`provenance.meta.assessment_version=base64-evidence-v1`。保留 Job 映像／工作 ID／完整報告與 status 的
`retention_expires_at` 於私有目錄；到期加 20 分鐘後依[保留期手冊](cloud-demo-operations.md#4-到期撤權與實體清理)
逐 root 核對。雲端回報前，Q-06 此批只記為程式／本機驗證完成。

需要退回先前映像時，使用同一 checkpoint 的 `maintain-demo.py rollback --state-dir ...`，
再查 `status`。這是操作工具說明；未實際演練前不將 P0-11 標為完成。
