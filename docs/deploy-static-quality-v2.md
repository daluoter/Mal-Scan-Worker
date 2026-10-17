# 將靜態品質第二批一次更新到雲端 demo

本次更新 Cloud Run 分析 Job 的映像與 Cloudflare Pages 前端。既有 Worker API、dispatcher、
bucket、secret、IAM 與保留政策不需重建。這是部署操作手冊；儲存庫的本機測試通過不代表線上已更新。

請使用原本已登入 Google Cloud 與 Cloudflare 的 Cloud Shell。以下步驟各自執行；Cloud Build
送出後可斷線，重新連線再從「查詢」繼續。不要在等待時重新送出 build。

## 1. 取得新版並保存獨立路徑

從本次發布訊息確認 GitHub commit 已通過 CI，再執行：

```bash
(
  set -e
  umask 077
  V2_QUALITY_SOURCE=$(mktemp -d "$HOME/malscan-v2-quality.XXXXXX")
  git clone --quiet https://github.com/daluoter/MalScanWorker.git "$V2_QUALITY_SOURCE"
  cd "$V2_QUALITY_SOURCE"
  git rev-parse HEAD
  python3 - <<'PY'
import json
from pathlib import Path
corpus = json.loads(Path('worker/quality/corpus-v2.json').read_text())
assert corpus['corpus_version'] == 'static-quality-v2.0.0'
assert len(corpus['cases']) == 32
print('Static quality v2 source verified; compare the commit above with the release message.')
PY
  pwd > "$HOME/malscan-v2-quality-source-path.txt"
)
```

確認印出的 commit 是本次發布版本。若不同，先在新目錄切換到發布訊息指定的 commit；
不要沿用仍有未套用修改的舊部署目錄。原本的 P0 路徑與 checkpoint 保持可供查閱。

## 2. 保存現行 Job 與回滾映像，送出一次建置

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")"
  V2_QUALITY_PREPARE=$(mktemp "$HOME/malscan-v2-quality-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_QUALITY_PREPARE"
  python3 - "$V2_QUALITY_PREPARE" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-quality-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-quality-state-path.txt")"
)
```

建置會刷新並驗證官方 ClamAV 簽章資料庫，執行 clean／EICAR 的 AV、YARA 控制後才發布映像。
這些控制與本機 32 案例分開記錄。建置與映像儲存可能產生用量，免費額度不保證零帳單。

`submit` 若回覆不明或連線中斷，先執行下一步 `status`；checkpoint 會協助核對既有 build。
不要重跑 `prepare`／`submit` 來處理等待狀態。

## 3. 重新連線後查詢，驗證成功才更新 Job

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-quality-state-path.txt")"
)
```

等待 `phase=build_verified`、`build_status=SUCCESS` 與 `candidate_controls.success=true`。
確認資料庫日期、YARA 規則 SHA-256、候選映像 digest 後，執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-quality-state-path.txt")"
)
```

預期 `phase=promoted`。此工具只更新映像，並驗證現行設定未發生其他變更；不會自動提交掃描工作。
若有 drift 或失敗，保留 checkpoint 與輸出先診斷。

## 4. 更新既有 Pages 前端

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")/deployment/cloudflare"
  npm ci
  npx --no-install wrangler whoami
)
```

若顯示未登入，在同一目錄執行 `npx --no-install wrangler login --device --no-browser`，完成網頁授權後繼續。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")/frontend"
  npm ci
  VITE_BASE_PATH=/ \
  VITE_API_DEPLOYMENT=cloud-demo \
  VITE_API_BASE_URL=https://malscan-v2-demo-control.daluoter.workers.dev \
  npm run build

  export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
  ../deployment/cloudflare/node_modules/.bin/wrangler pages deployment list \
    --project-name=malscan-v2-demo
  ../deployment/cloudflare/node_modules/.bin/wrangler pages deploy dist \
    --project-name=malscan-v2-demo \
    --branch=main \
    --commit-dirty=true
)
```

保存部署前後的 Pages deployment ID。正式網址仍是 <https://malscan-v2-demo.pages.dev>。
本步使用 `pages deploy`；不要以儲存庫範本重新部署控制 Worker。
兩個元件依序更新，期間舊報告仍保留原本的規則、分數與政策版本，不會被重新評分。

## 5. 雲端 smoke test 與回滾

先用三個新工作驗證正常 Office、含惰性 PDF action 的合成檔，以及加密 PDF；
完整 32 案例是本機品質驗收，不需全部重送雲端。沿用既有每日／每月執行限制。
需要生成這批固定樣本時，使用 Cloud Shell 的 Python 標準函式庫即可：

```bash
cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")"
python3 - <<'PY'
import runpy
from pathlib import Path
build_document_fixture = runpy.run_path(
    'worker/src/malscan_worker/quality/document_fixtures.py'
)['build_document_fixture']
output = Path.home() / 'malscan-v2-quality-smoke'
output.mkdir(mode=0o700, exist_ok=False)
for name, extension in [('office-normal', 'docx'), ('pdf-active-actions', 'pdf'), ('pdf-encrypted', 'pdf')]:
    (output / f'{name}.{extension}').write_bytes(build_document_fixture(name))
print(output)
PY
```

將產生的三個檔案從 Cloud Shell 下載到電腦，再於 demo 網頁上傳。
生成配方不呼叫掃描器、網路服務，也不執行樣本內容。

驗收新報告：正常 Office 為 clean、靜態 complete；PDF action 保留結構風險；
加密 PDF 為 partial，顯示需要密碼，不能以 clean 取代覆蓋限制。
新報告政策為 `msrs-v1.1`，規則集為 `1.1.0`；YARA 指紋應等於 `corpus-v2.json` 的 `rules_sha256`。
保存新工作 ID、映像 digest、工具／病毒庫時間與完整 JSON，後續再確認 24 小時保留期清除。

若需退回舊映像：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-quality-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py rollback \
    --state-dir "$(cat "$HOME/malscan-v2-quality-state-path.txt")"
)
```

前端需要回滾時，在 Cloudflare Pages 專案的 Deployments 選擇先前保存的正式 deployment 執行 rollback。
Job 與 Pages 的回滾各自處理；保留 checkpoint，不刪除先前映像。
