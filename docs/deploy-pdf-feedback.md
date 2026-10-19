# 部署 PDF 密碼與風險回饋修正

更新日期：2026-10-19（Asia/Taipei）。此批修正錯誤密碼提示、**每個加密檔案獨立三次補交**、
紅色高風險呈現，以及 `msrs-v1.2` 的子檔風險逐層回傳。
進度見 [F-08／F-09／Q-08／UX-06／UX-07](project-status.md)，行為與限制見 [PDF 密碼說明](pdf-password.md)。
四項修正已完成程式／本機驗證，結果見 [本批紀錄](milestones/2026-10-18-pdf-feedback.json)。
2026-10-19 已完成本輪雲端人工驗收：使用者確認錯誤提示、逐檔三次及父子檔高風險呈現，
另核對新畫面與兩份 `msrs-v1.2` 完成報告，見 [雲端驗收紀錄](milestones/2026-10-19-pdf-feedback-acceptance.json)。
逐檔獨立及第三次限制依人工確認，沒有新增自動化雲端測試；最外層 ZIP 完整報告與 Pages deployment ID 未提供。
以下保留供新部署與日後更新使用；已完成本輪部署者不需為了補齊紀錄而重建 Job 或重送上傳。

順序是 **Cloud Run Job → Cloudflare Worker → Pages → 新上傳驗收**。
Job 先支援新的逐檔次數契約，再更新控制層與前端。這次需更新 Worker，與首批只改 Job／Pages 不同。
不建立 IAM、bucket 或 secret，不更換 HMAC；dispatcher 不需更新。
若 Job 已顯示 `phase=promoted`，不重跑第 2–3 節；第 5 節的設定產生失敗也不需要重建或再切換 Job。
舊 root 共用總數保留為歷史值，首次升級後逐檔計數從零開始一次；既有日／月 execution 用量保留。

以下在既有已登入 GCP／Cloudflare 的 Cloud Shell 分段操作。可以斷線後使用保存路徑接續；
每段失敗時先保留輸出並查詢，不盲目重送建置、上傳或密碼。
部署過程不需把 API Token、Secret 或 capability 貼到聊天。

本手冊保留公開 demo 網址與資源別名；實際帳戶 ID 由本機登入／設定選取。
Account ID、專案與 bucket 名稱不是登入憑證，但仍是部署識別資訊；既有文件與 Git 歷史可能包含這些識別值，
本次移除手冊中的值不代表已重寫歷史。下載設定、OAuth 設定檔、原始終端輸出、真實文件密碼、
R2 keys、HMAC、capability、原始報告與帳單都保留在本機私人目錄，不加入 Git。
`quality-pdf-only`／`quality-archive-only` 只用於公開合成 fixture，可公開，不是正式憑證。
提交前審閱 `git diff --cached` 並掃描待發布內容；忽略規則與掃描都不能代替人工確認。

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

上面的括號區塊結束後會回到原目錄；不要依賴先前的 `cd`，也不要在 `~` 用 `npx` 尋找專案內的 Wrangler。
若未登入，或正式發布時停在嘗試開啟 localhost OAuth 登入，先按 Ctrl+C，再獨立執行以下裝置登入：

```bash
(
  set -e
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" \
    login --device --no-browser
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" whoami
)
```

依終端機產生的新指示，在自己的瀏覽器完成授權，直到顯示登入成功；登入碼與 OAuth 網址不放入 Git 或 issue。
重新連線後若授權未生效，重做此登入即可，不重建 Job、重新下載備份或安裝另一個 Wrangler 版本。
單一帳戶由 Wrangler 使用既有 OAuth 登入選取；多帳戶時，在自己的 Cloud Shell 設定 `CLOUDFLARE_ACCOUNT_ID`，
不把實際值寫入手冊、程式或 commit。然後執行：

```bash
(
  set -e
  set -o pipefail
  umask 077
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  V2_PDF_FIX_WRANGLER="$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler"
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
  python3 "$V2_PDF_FIX_SOURCE/deployment/cloudflare/prepare-feedback-config.py" \
    --source "$V2_PDF_FIX_SOURCE/deployment/cloudflare/src/worker.mjs" \
    --worker-name malscan-v2-demo-control \
    --downloaded-config "$V2_PDF_FIX_BACKUP/malscan-v2-demo-control/wrangler.jsonc" \
    --output "$V2_PDF_FIX_BACKUP/wrangler-feedback.json"
  "$V2_PDF_FIX_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" deploy \
    --config "$V2_PDF_FIX_BACKUP/wrangler-feedback.json" --keep-vars --dry-run \
    --outdir "$V2_PDF_FIX_BACKUP/dry-run"
)
```

工具只輸出檢查結果與 `main` 變更，不輸出正式 vars、帳戶或 bucket 值；設定檔維持在私人備份目錄，權限為 `0600`。
檢查 `PUBLIC_UPLOADS=true`、HTTPS origin／dispatcher、三種額度、兩個 R2 binding 與本機 DO binding 符合要求。
來源是已下載的正式設定；除 `main` 外所有欄位完全相同，不為了通過檢查放寬限額或覆蓋正式 vars。

Wrangler 的 `init --from-dash` 可能省略 `migrations`，也可能重建其內容；因此不要求 tag 必須等於 `v1`。
工具原樣保留 `migrations` 與 `exports`，包含缺省／空陣列；不補 tag、不新增 `exports`、不重建 DO 或刪除資料。
下載後的「缺少 live exports」警告是提示，不能據此自行改變既有 DO 儲存宣告。
若其他檢查失敗，工具會以可辨識的錯誤訊息停止，不輸出可能含憑證的設定值。
確認 dry-run 成功後才執行：

```bash
(
  set -e
  set -o pipefail
  V2_PDF_FIX_SOURCE=$(cat "$HOME/malscan-v2-pdf-feedback-source-path.txt")
  V2_PDF_FIX_BACKUP=$(cat "$HOME/malscan-v2-pdf-feedback-worker-backup-path.txt")
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
本輪已另取得新畫面、兩份完成 JSON 與使用者人工確認，足以完成上述範圍驗收；
Pages deployment ID 未提供，因此不填造版本 ID，也不把人工確認記成自動化雲端測試。
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
