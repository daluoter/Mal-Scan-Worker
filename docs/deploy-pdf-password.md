# 將 PDF 密碼恢復更新到既有雲端 demo

此文件保留 **PDF 密碼恢復首批**的 Job／Pages 部署步驟。
2026-10-19 後續回饋版本已完成本輪 F-08 雲端人工驗收：使用者確認錯誤提示、逐檔三次與高風險呈現，
並提供新畫面及兩份完成報告，見 [雲端驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)。
此結論不改寫首批歷史結果，也不代表所有格式或維護待辦完成。

**目前請依 [PDF 回饋修正部署手冊](deploy-pdf-feedback.md)** 更新：本次還包含逐檔密碼計數的 Cloudflare Worker 改動，
順序為 Job → Worker → Pages，並從目前正式部署下載設定，保留 `PUBLIC_UPLOADS`、origin、dispatcher、DO／R2 與額度。
不要把本文件首批「Worker 不需更新」的範圍套到後續版本，也不要直接發布 repository 的 placeholder 範本。

首批程式／本機驗證結果見 [2026-10-18 紀錄](milestones/2026-10-18-pdf-password.json)；
功能見 [PDF 密碼說明](pdf-password.md)，狀態見 [進度清單](project-status.md)。以下首批步驟與 manifest 留作歷史及 fixture 生成參考。

## 1. 新目錄取得發布版，保存獨立路徑

先確認本批發布訊息提供的 GitHub commit 已通過 CI，再執行：

```bash
(
  set -e
  umask 077
  V2_PDF_SOURCE=$(mktemp -d "$HOME/malscan-v2-pdf.XXXXXX")
  git clone --quiet https://github.com/daluoter/MalScanWorker.git "$V2_PDF_SOURCE"
  cd "$V2_PDF_SOURCE"
  git rev-parse HEAD
  python3 - <<'PY'
import json
from pathlib import Path
corpus = json.loads(Path('worker/quality/corpus-v3.json').read_text())
suite = json.loads(Path('worker/quality/pdf-password-v1.json').read_text())
assert corpus['corpus_version'] == 'static-quality-v3.0.0'
assert len(corpus['cases']) == 32
assert suite['suite_version'] == 'pdf-password-v1.1.0'
assert len(suite['cases']) == 12
assert len({case['id'] for case in suite['cases']}) == len(suite['cases'])
print('PDF source manifests found; compare the commit above with the release message.')
PY
  pwd > "$HOME/malscan-v2-pdf-source-path.txt"
)
```

印出的 commit 應與本批發布版本一致；若 main 已往前移，先在這個新目錄切換到發布訊息指定的 commit，
再繼續。只確認檔案存在不能代替 commit／CI 核對。舊 P0／quality source 與 state 路徑不覆寫，保留作查閱及回退。

## 2. 保存目前映像／設定，只送出一次建置

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")"
  V2_PDF_PREPARE=$(mktemp "$HOME/malscan-v2-pdf-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_PDF_PREPARE"
  python3 - "$V2_PDF_PREPARE" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-pdf-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-state-path.txt")"
)
```

工具保存目前 Job／舊映像與一次非同步 build。這個 state 路徑保存本次回退的依據，不與舊批次共用。Cloud Build 會更新並驗證官方 ClamAV 簽章、
執行正常／EICAR 的 AV／YARA 控制，成功才發布映像；這些控制不代替本批 PDF 完整驗收。
建置送出後可以關閉 Cloud Shell。回覆不明或重新連線時，先查詢下一步，不重跑 prepare／submit。
建置、映像與測試仍會產生用量，沿用既有成本目標。

## 3. 重連查詢，成功才切換映像

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-state-path.txt")"
)
```

等待 `phase=build_verified`、`build_status=SUCCESS`、`candidate_controls.success=true`，
核對候選 digest、資料庫日期與 YARA 指紋後才執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-state-path.txt")"
)
```

預期 `phase=promoted`。工具只切換映像並核對其他 Job 設定，沒有建立掃描工作。
若顯示 drift 或回應不明，保留 checkpoint 並先執行 status 核對，不盲目重複切換。

## 4. 更新既有 Pages 前端

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")/deployment/cloudflare"
  npm ci
  npx --no-install wrangler whoami
)
```

若未登入，在同一目錄執行 `npx --no-install wrangler login --device --no-browser` 完成授權，然後繼續：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")/frontend"
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
本步只執行 `pages deploy`；不要把 repository 的 Worker 範本重新發布覆蓋現有控制設定。

## 5. 生成固定 smoke fixtures

Cloud Shell 的 Python 標準函式庫即可生成，不需安裝 worker／crypto 依賴：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")"
  python3 - <<'PY'
import hashlib
import json
import runpy
from pathlib import Path
module = runpy.run_path('worker/src/malscan_worker/quality/pdf_password_fixtures.py')
suite = json.loads(Path('worker/quality/pdf-password-v1.json').read_text())
cases = {case['profile']: case for case in suite['cases']}
output = Path.home() / 'malscan-v2-pdf-smoke'
output.mkdir(mode=0o700, exist_ok=False)
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
PY
)
```

這兩個公開測試密碼分別為 `quality-pdf-only` 與 `quality-archive-only`，只能用於本批合成檔。
action PDF 只有惰性的 `void 0;` 與不存在的文字檔名稱，樣本不執行；正常 PDF 對照沒有添加假的可疑標記。
輸出目錄已存在時不要覆寫原證據，換新路徑或沿用已核對的檔案。
從 Cloud Shell 將兩個 fixture 下載到電腦，經正式 Pages 網頁上傳。

## 6. 正式網頁驗收

| 工作 | 操作與預期 |
| --- | --- |
| AES-128 PDF | 上傳後等待密碼，部分報告可讀；先輸入一次錯誤測試字串，再輸入 `quality-pdf-only`。等待節點不變，成功後多一個 `pdf-decrypted` 子檔並完成其靜態掃描，保留 JavaScript／Launch 結構證據 |
| AES ZIP → AES-128 PDF | 先以 `quality-archive-only` 解開 ZIP，確認等待的是內層 PDF；對 PDF 先輸入一次外層密碼，應顯示錯誤，再輸入 `quality-pdf-only`。最後來源樹應為 ZIP → 加密 PDF → 解密 PDF，累計額度沒有重置 |

兩個工作若走完上述錯誤對照，預計共七次 execution（兩次初始上傳＋五次密碼續跑）。
首批 root 共用三次補交為歷史規則；本次新版改為每檔各三次，依回饋修正手冊操作。每日 20 次／每月 40 次 execution 及每日 10 個新工作不變；
先確認仍有額度，不為測試調高上限。

舊版已結束的 partial 報告不會自動補做解密；請在 Job 與 Pages 都更新後建立新的上傳工作。
保存兩個新工作 ID、映像 digest、Pages deployment ID、等待／錯誤／完成 JSON 與工具／資料庫版本。
核對 `job_status=done`、`report_complete=true`、static complete，原檔雜湊未變，
解密子檔有自己的 SHA-256、大小、必要階段與可回溯證據；解密成功本身不是 clean 判定。
這批等待密碼應為 `password_required`，不要沿用前一批「加密 PDF 完成但 partial」的舊預期。
之後另核對保留期與費用；兩個新工作的證據不能由先前四筆 R2 清理結果代替。

## 7. 必要時回退

回退是把執行程式切回本批建置前保存的映像，並非恢復已刪除資料：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-pdf-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py rollback \
    --state-dir "$(cat "$HOME/malscan-v2-pdf-state-path.txt")"
)
```

Pages 另在 Cloudflare 專案 Deployments 選擇先前保存的正式 deployment 執行 rollback。
保留 checkpoint 與映像，不刪除前一版。沒有實際執行與驗證這些步驟前，
進度清單的 P0-11「真實雲端回退演練」仍是待辦；本手冊不會自動完成該項驗收。
同樣地，本批功能上線不會完成 P0-06 DO 清理、P0-12 自動病毒庫更新或 P0-14 長期成本。
