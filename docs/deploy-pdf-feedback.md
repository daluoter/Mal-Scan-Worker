# 部署 PDF 密碼與風險回饋修正

更新日期：2026-10-18（Asia/Taipei）。此批修正錯誤密碼提示、**每個加密檔案獨立三次補交**、
紅色高風險呈現，以及 `msrs-v1.2` 的子檔風險逐層回傳。
進度見 [F-08／F-09／Q-08／UX-06／UX-07](project-status.md)，行為與限制見 [PDF 密碼說明](pdf-password.md)。
四項修正已完成程式／本機驗證，結果見 [本批紀錄](milestones/2026-10-18-pdf-feedback.json)。
正式部署與 smoke 尚未完成，不能用先前已成功解密的 JSON 代替。

順序是 **Cloud Run Job → Cloudflare Worker → Pages → 新上傳驗收**。
Job 先支援新的逐檔次數契約，再更新控制層與前端。這次需更新 Worker，與首批只改 Job／Pages 不同。
不建立 IAM、bucket 或 secret，不更換 HMAC；dispatcher 不需更新。
舊 root 共用總數保留為歷史值，首次升級後逐檔計數從零開始一次；既有日／月 execution 用量保留。

以下在既有已登入 GCP／Cloudflare 的 Cloud Shell 分段操作。可以斷線後使用保存路徑接續；
每段失敗時先保留輸出並查詢，不盲目重送建置、上傳或密碼。
部署過程不需把 API Token、Secret 或 capability 貼到聊天。

## 1. 取得本批發布版

先核對發布訊息中的 commit 與 CI 結果。這次使用獨立路徑，不覆寫前一批 PDF／P0 的 source 或 maintenance state。

```bash
(
  set -e
  umask 077
  V2_PDF_FIX_SOURCE=$(mktemp -d "$HOME/malscan-v2-pdf-feedback.XXXXXX")
  git clone --quiet https://github.com/daluoter/MalScanWorker.git "$V2_PDF_FIX_SOURCE"
  cd "$V2_PDF_FIX_SOURCE"
  git rev-parse HEAD
  python3 - <<'PY_CHECK'
import json
from pathlib import Path
corpus = json.loads(Path('worker/quality/corpus-v4.json').read_text())
suite = json.loads(Path('worker/quality/pdf-password-v2.json').read_text())
assert corpus['corpus_version'] == 'static-quality-v4.0.0'
assert corpus['policy_version'] == 'msrs-v1.2'
assert len(corpus['cases']) == 32
assert suite['suite_version'] == 'pdf-password-v2.0.0'
assert suite['policy_version'] == 'msrs-v1.2'
assert len(suite['cases']) == 12
print('Feedback manifests found; compare HEAD with the release commit before continuing.')
PY_CHECK
  pwd > "$HOME/malscan-v2-pdf-feedback-source-path.txt"
)
```

如果 main 已往前移，在這個新目錄切到發布訊息指定的 commit，再繼續。檔案存在不能代替 commit／CI 核對。

## 2. 保存目前 Job，非同步建置一次

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")"
  V2_PDF_FIX_PREPARE=$(mktemp "$HOME/malscan-v2-pdf-feedback-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_PDF_FIX_PREPARE"
  python3 - "$V2_PDF_FIX_PREPARE" <<'PY_STATE'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-pdf-feedback-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY_STATE
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-feedback-state-path.txt")"
)
```

工具保存舊 digest 與設定，建置時刷新並驗證官方 ClamAV 簽章、正常／EICAR 控制後發布候選映像。
建置、儲存與測試仍產生用量。送出後可以關閉 Cloud Shell；回覆不明時先查下一步，不重跑 submit。

## 3. 查詢並切換 Job

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-feedback-state-path.txt")"
)
```

確認 `phase=build_verified`、`build_status=SUCCESS`、`candidate_controls.success=true`，
核對候選 digest、病毒庫日期與規則指紋後：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-feedback-state-path.txt")"
)
```

預期 `phase=promoted`；這只更新 Job，不會啟動掃描。遇到 drift 或不確定回覆先 status，不重複切換。

## 4. 登入並下載「目前正式 Worker」設定備份

**不可直接在 repository 範本執行 `wrangler deploy`。** 範本的 `PUBLIC_UPLOADS=false` 與 placeholder origin／dispatcher
會覆蓋已啟用的正式設定。這裡從目前部署下載設定，只改程式進入點，保留 vars、DO、R2、路由、相容性及額度。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")/deployment/cloudflare"
  npm ci
  npx --no-install wrangler whoami
)
```

若未登入，在同一目錄執行 `npx --no-install wrangler login --device --no-browser` 完成授權，再執行：

```bash
(
  set -e
  set -o pipefail
  umask 077
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  V2_PDF_FIX_WRANGLER="$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler"
  export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
  V2_PDF_FIX_BACKUP=$(mktemp -d "$HOME/malscan-v2-pdf-feedback-worker.XXXXXX")
  cd "$V2_PDF_FIX_BACKUP"
  "$V2_PDF_FIX_WRANGLER" init \
    --from-dash malscan-v2-demo-control --no-delegate-c3
  pwd > "$HOME/malscan-v2-pdf-feedback-worker-backup-path.txt"
  "$V2_PDF_FIX_WRANGLER" deployments list \
    --config "$V2_PDF_FIX_BACKUP/malscan-v2-demo-control/wrangler.jsonc" \
    | tee "$V2_PDF_FIX_BACKUP/deployments-before.txt"
)
```

此命令使用本批鎖定的 Wrangler 下載正式程式與設定，不發布遠端變更；保存舊 Worker Version ID。
下載不會取得 secret 值；既有 secret 不需重新輸入。備份保留在私人 home 目錄，不提交到 GitHub。
如果下載無法完成，先處理讀取失敗，不改用 repository 範本部署。

## 5. 產生保留正式設定的部署檔，先檢查再發布

```bash
(
  set -e
  set -o pipefail
  umask 077
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  V2_PDF_FIX_BACKUP=$(cat "$HOME/malscan-v2-pdf-feedback-worker-backup-path.txt")
  python3 - "$V2_PDF_FIX_SOURCE" "$V2_PDF_FIX_BACKUP" <<'PY_CONFIG'
import copy
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit
source, backup = map(Path, sys.argv[1:])
original = backup / 'malscan-v2-demo-control/wrangler.jsonc'
config = json.loads(original.read_text())
assert config['name'] == 'malscan-v2-demo-control'
values = config['vars']
expected = {
    'ALLOWED_ORIGIN': 'https://malscan-v2-demo.pages.dev',
    'PUBLIC_UPLOADS': 'true',
    'DAILY_JOB_LIMIT': '10',
    'DAILY_EXECUTION_LIMIT': '20',
    'MONTHLY_EXECUTION_LIMIT': '40',
    'RETENTION_SECONDS': '86400',
    'GCP_PROJECT': 'malscan-v2-poc',
    'GCP_REGION': 'us-central1',
    'GCP_JOB': 'malscan-v2-static-demo',
}
for key, expected_value in expected.items():
    assert str(values.get(key)).lower() == expected_value, f'Review current production setting: {key}'
url = urlsplit(values.get('GCP_DISPATCH_URL', ''))
assert url.scheme == 'https' and url.hostname and url.hostname.endswith('.run.app')
assert not url.username and not url.password and not url.query and not url.fragment
assert url.path in ('', '/') and 'REPLACE' not in url.netloc
assert 'CONTROL_HMAC_KEY' not in values, 'Secret must not be stored as a plain variable'
buckets = {item['binding']: item['bucket_name'] for item in config['r2_buckets']}
assert buckets == {'UPLOADS': 'malscan-v2-upload-poc', 'RESULTS': 'malscan-v2-analysis-results'}
bindings = config['durable_objects']['bindings']
assert len(bindings) == 1 and bindings[0]['name'] == 'CONTROL'
assert bindings[0]['class_name'] == 'DemoControl'
assert bindings[0].get('script_name', config['name']) == config['name']
assert [item['tag'] for item in config.get('migrations', [])] == ['v1']
assert config.get('workers_dev') is True
assert config.get('compatibility_date'), 'Missing production compatibility date'
updated = copy.deepcopy(config)
updated['main'] = str(source / 'deployment/cloudflare/src/worker.mjs')
assert Path(updated['main']).is_file()
assert {key for key in updated if updated[key] != config.get(key)} == {'main'}
target = backup / 'wrangler-feedback.json'
target.write_text(json.dumps(updated, indent=2) + '\n')
target.chmod(0o600)
print(json.dumps({'config': str(target), 'preserved_production_vars': expected,
                  'GCP_DISPATCH_URL': values['GCP_DISPATCH_URL'],
                  'r2_buckets': buckets, 'durable_object': 'CONTROL / DemoControl',
                  'only_changed_setting': 'main'}, indent=2))
PY_CONFIG
  export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" deploy \
    --config "$V2_PDF_FIX_BACKUP/wrangler-feedback.json" --keep-vars --dry-run \
    --outdir "$V2_PDF_FIX_BACKUP/dry-run"
)
```

檢查輸出的正式 origin、`PUBLIC_UPLOADS=true`、dispatcher、三種額度、兩個 bucket 與 DO 均符合現有部署。
若實際正式設定與表內不同，先核對原因，保留目前設定；不要為了讓檢查通過直接放寬限額或覆蓋正式 vars。
下載檔的既有 migration tag 保持 `v1`，不新增 migration、重建 DO 或刪除資料。
確認 dry-run 成功後才執行：

```bash
(
  set -e
  set -o pipefail
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  V2_PDF_FIX_BACKUP=$(cat "$HOME/malscan-v2-pdf-feedback-worker-backup-path.txt")
  export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" deploy \
    --config "$V2_PDF_FIX_BACKUP/wrangler-feedback.json" --keep-vars
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" deployments list \
    --config "$V2_PDF_FIX_BACKUP/wrangler-feedback.json" \
    | tee "$V2_PDF_FIX_BACKUP/deployments-after.txt"
)
```

保存新 Worker Version ID。新版啟動時加入逐檔計數欄位並保留舊 root 歷史總數，沒有清空工作或配額。

## 6. 更新 Pages 前端

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")/frontend"
  npm ci
  VITE_BASE_PATH=/ \
  VITE_API_DEPLOYMENT=cloud-demo \
  VITE_API_BASE_URL=https://malscan-v2-demo-control.daluoter.workers.dev \
  npm run build
  export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
  ../deployment/cloudflare/node_modules/.bin/wrangler pages deployment list \
    --project-name=malscan-v2-demo
  ../deployment/cloudflare/node_modules/.bin/wrangler pages deploy dist \
    --project-name=malscan-v2-demo --branch=main --commit-dirty=true
)
```

保存部署前後的 Pages deployment ID，開啟正式 <https://malscan-v2-demo.pages.dev>，重新載入以使用新版資產。
分支 preview URL 的 origin 不同，正式 API 不允許該來源。舊截圖的「需要解壓密碼」與「root 共用三次」
表示前端文字或控制契約仍舊，不能只以 Job 已切換認定三層都更新。

## 7. 使用兩個固定檔案驗收

可沿用已核對 SHA-256 的 `aes-128-active-actions.pdf` 與 `zip-aes-pdf-aes-128.zip`；
或用 Python 標準函式庫在新私人目錄生成相同 bytes，不需安裝 worker／crypto 依賴：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")"
  V2_PDF_FIX_FIXTURES=$(mktemp -d "$HOME/malscan-v2-pdf-feedback-fixtures.XXXXXX")
  python3 - "$V2_PDF_FIX_FIXTURES" <<'PY_FIXTURES'
import hashlib
import json
import runpy
import sys
from pathlib import Path
module = runpy.run_path('worker/src/malscan_worker/quality/pdf_password_fixtures.py')
suite = json.loads(Path('worker/quality/pdf-password-v2.json').read_text())
cases = {case['profile']: case for case in suite['cases']}
output = Path(sys.argv[1])
for profile, extension in [('aes-128-active-actions', 'pdf'), ('zip-aes-pdf-aes-128', 'zip')]:
    payload = module['build_pdf_password_fixture'](profile)
    assert len(payload) == cases[profile]['bytes']
    assert hashlib.sha256(payload).hexdigest() == cases[profile]['sha256']
    target = output / f'{profile}.{extension}'
    target.write_bytes(payload)
    target.chmod(0o600)
    print(target)
print('Fixture-only PDF password:', module['PDF_PASSWORD'])
print('Fixture-only ZIP password:', module['ARCHIVE_PASSWORD'])
PY_FIXTURES
  printf '%s\n' "$V2_PDF_FIX_FIXTURES" > "$HOME/malscan-v2-pdf-feedback-fixtures-path.txt"
)
```

從 Cloud Shell 下載兩個檔案到電腦，再經正式 Pages 網頁建立**新的上傳工作**。
保留同一瀏覽器分頁的工作權限。這些公開 fixture 密碼只用於合成測試檔。

| 工作 | 操作 | 必須看到的結果 |
| --- | --- | --- |
| AES-128 PDF | 等待後先錯誤一次，再輸入 `quality-pdf-only` | 顯示目前 PDF 路徑與剩餘 3；錯誤 execution 回報後明確顯示紅色「密碼不正確」、已用 1／剩餘 2；正確後完成子檔掃描 |
| AES ZIP → AES PDF | ZIP 先輸入 `quality-archive-only`；內層 PDF 先錯誤一次再輸入 `quality-pdf-only` | ZIP 已用 1 不扣 PDF；PDF 首次出現仍為已用 0／剩餘 3，錯誤後 1／2；目標路徑是 `nested/locked.pdf`，不是外層 ZIP |
| 完成報告 | 下載原檔與子檔 JSON，檢查摘要、樹及評分說明 | `msrs-v1.2`；解密子檔 84 分／高風險紅色；PDF 與 ZIP 祖先有效風險至少 84，直接分析的本檔分數另列，來源可回到 `decrypted.pdf` |

正常→提交→等待錯誤回報是非同步過程；POST 被接受不代表密碼正確。
計次採接受補交數，正確密碼也會計一次。不要額外建立工作來測每天只能上傳一次的舊說法：
目前限制仍是全站每日 10 個新工作與 20 次 execution、每月 40 次 execution；這兩個案例共需 7 次 execution。
若當月已接近上限，先查既有用量，不反覆重送。某檔三次耗盡與其他檔仍可續跑的邊界已有本機驗收範圍，
正式演練另留證據並計入全站額度，不自動再加測一批。

保存新 root／子檔 ID、映像 digest、Worker／Pages Version ID，以及等待、錯誤、完成 JSON／畫面。
真實文件密碼／capability 不放在截圖、檔名或公開證據；本頁公開 fixture 密碼只供合成測試檔使用。
四份舊完成 JSON 證明解密與掃描，不能單獨證明錯誤提示、逐檔次數或 Pages 已發布。
高風險 action 為惰性測試結構，不是 ClamAV／YARA 命中或真實執行的惡意行為。
新增工作到期後另核對 R2 指定前綴與撤權；不因此關閉 DO 清理或長期成本待辦。

## 8. 保留回退方式

先保存本次 state、Worker 舊版本與 Pages 舊 deployment ID。若需要恢復舊版，先停止新提交並保存診斷，
按介面相依性回復 Pages、Worker，再切回舊 Job；不要在新版 Worker 仍可送逐檔恢復時先降版 Job。

- Pages：在 Cloudflare Deployments 選擇部署前保存的正式版本並 rollback。
- Worker：使用保存的部署前 Version ID，在本批 backup config 下執行 `wrangler rollback VERSION_ID --config /absolute/path/to/wrangler-feedback.json`，並核對流量已切回。這是程式版本回退，不會回復 DO／R2 資料；新增欄位與歷史計數保留。
- Job：從本批 source 執行 `python3 deployment/cloud-run/maintain-demo.py rollback --state-dir "$(cat "$HOME/malscan-v2-pdf-feedback-state-path.txt")"`，再 status 核對。

密碼計次契約降版後改回舊 root 共用規則，舊版程式會讀取保留的總數；不要把回退當成補回嘗試或還原已刪除資料。
只有實際演練與驗證後才能完成 `P0-11`；部署手冊或一次正常升版不代表回退已驗收。
`P0-06` DO 清理、`P0-12` 自動病毒庫更新與 `P0-14` 長期成本仍維持待辦。
