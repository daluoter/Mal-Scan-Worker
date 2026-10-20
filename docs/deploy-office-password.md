# 部署 Office 密碼恢復到既有雲端 demo

更新日期：2026-10-20（Asia/Taipei）。F-02 程式／本機驗證與 **F-10 正式 Office smoke** 分開追蹤。
本輪 Job／Pages 已有使用者提供的部署輸出，DOCX 正確解鎖的兩份根報告及一份巢狀 Office 子樹也已核對；
後續已取得 Office 錯誤紅字截圖、ZIP／Office 初始計次獨立的人工確認、成功續跑報告與完整 ZIP 根報告；F-10 已按三個固定 DOCX 流程完成限定驗收，見[本輪紀錄](milestones/2026-10-20-office-cloud-acceptance.json)。
第 1–7 節保留供其他部署使用；第 8 節保存本輪結案範圍與後續維護事項。
支援與限制見 [Office 密碼說明](office-password.md)。

這批順序為 **Cloud Run Job → Pages → 新上傳驗收**。沿用已支援逐檔密碼計次的正式 Cloudflare Worker、
dispatcher、R2、IAM、secrets 與現有額度，無須發布 Worker 範本或更換 HMAC。
如果部署尚未具備前一批逐檔密碼契約，先完成[前一批升級](deploy-pdf-feedback.md)，不能只以新 Job 取代控制層升級。
本批不處理自動病毒庫排程、真實回退、DO 清理或長期成本；這些維護項目仍獨立追蹤。

在已登入 GCP／Cloudflare 的 Cloud Shell 分段操作。每批使用獨立私人來源／state marker，
可以斷線後查詢接續；回應不明先查 `status`，不盲目重送建置、上傳或密碼。
實際 Account ID 由現有登入／本機設定選取，多帳戶時僅在自己的 shell 設定 `CLOUDFLARE_ACCOUNT_ID`；
不把實際識別值硬編碼到這份手冊。API Token、OAuth 設定、R2 keys、HMAC、capability、
真實文件密碼、完整原始報告、status 與帳單都保留在私人目錄，不加入 Git、不貼到聊天或 issue。
本手冊顯示的公開 fixture 密碼只適用本批合成測試檔。

## 1. 取得來源並核對發布 commit

先核對發布訊息的 commit 與 CI；以下建立新目錄，不覆寫既有 PDF／Base64／P0 部署資料。

```bash
(
  set -e
  umask 077
  V2_OFFICE_SOURCE=$(mktemp -d "$HOME/malscan-v2-office-password.XXXXXX")
  git clone --quiet https://github.com/daluoter/Mal-Scan-Worker.git "$V2_OFFICE_SOURCE"
  cd "$V2_OFFICE_SOURCE"
  git rev-parse HEAD
  python3 - <<'PY_CHECK'
import json
from pathlib import Path
suite = json.loads(Path('worker/quality/office-password-v1.json').read_text())
assert suite['suite_version'] == 'office-password-v1.0.0'
assert suite['policy_version'] == 'msrs-v1.2'
assert len(suite['cases']) == 14
assert Path('worker/src/malscan_worker/analyzers/office_decryption.py').is_file()
print('Office source found; compare HEAD with the release commit before continuing.')
PY_CHECK
  pwd > "$HOME/malscan-v2-office-password-source-path.txt"
)
```

若 main 已往前移，在這個新目錄切到發布訊息的 commit 再繼續；存在 manifest 不能代替 commit／CI 核對。

## 2. 保存目前 Job，只送出一次建置

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-office-password-source-path.txt")"
  V2_OFFICE_PREPARE=$(mktemp "$HOME/malscan-v2-office-password-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_OFFICE_PREPARE"
  python3 - "$V2_OFFICE_PREPARE" <<'PY_STATE'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-office-password-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY_STATE
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-office-password-state-path.txt")"
)
```

工具保存舊映像 digest／Job 設定；建置刷新並驗證官方 ClamAV 簽章與 clean／EICAR 控制後發布候選映像。
這是人工啟動的更新，尚無自動排程。Cloud Build、映像、儲存及 smoke 仍可能產生費用。
送出後可離開 Cloud Shell；重新連線使用下一節查詢，不再次 submit。

## 3. 查詢並切換 Job

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-office-password-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-office-password-state-path.txt")"
)
```

取得 `phase=build_verified`、`build_status=SUCCESS`、`candidate_controls.success=true`，
核對 digest、病毒庫日期與規則指紋後執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-office-password-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-office-password-state-path.txt")"
)
```

預期 `phase=promoted`。這只更新 Job，不會啟動掃描。遇到 drift 或回應遺失先重查 status，保留 state，
不重建資源、不放寬正式設定。

## 4. 使用固定 Wrangler 更新 Pages

需 Node.js 22+。先在本批來源安裝鎖定的部署工具與前端依賴，使用固定路徑，避免在 home 目錄執行 npx
而下載另一版 Wrangler。這裡只用 Wrangler 發布 Pages，**不執行 `wrangler deploy` 更新 Worker**。

```bash
(
  set -e
  V2_OFFICE_SOURCE=$(cat "$HOME/malscan-v2-office-password-source-path.txt")
  cd "$V2_OFFICE_SOURCE/deployment/cloudflare"
  npm ci
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" whoami
)
```

若尚未登入，或命令停在嘗試開啟 localhost OAuth，先 Ctrl+C，再獨立使用裝置登入：

```bash
(
  set -e
  V2_OFFICE_SOURCE=$(cat "$HOME/malscan-v2-office-password-source-path.txt")
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" login --device --no-browser
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" whoami
)
```

在自己的瀏覽器完成該次授權；不要保存登入碼／OAuth 網址到 Git。重連後只處理登入，不重建已切換的 Job。
登入可用後：

```bash
(
  set -e
  set -o pipefail
  umask 077
  V2_OFFICE_SOURCE=$(cat "$HOME/malscan-v2-office-password-source-path.txt")
  V2_OFFICE_PAGES_STATE=$(mktemp -d "$HOME/malscan-v2-office-password-pages.XXXXXX")
  printf '%s\n' "$V2_OFFICE_PAGES_STATE" > "$HOME/malscan-v2-office-password-pages-state-path.txt"
  cd "$V2_OFFICE_SOURCE/frontend"
  npm ci
  VITE_BASE_PATH=/ \
  VITE_API_DEPLOYMENT=cloud-demo \
  VITE_API_BASE_URL=https://malscan-v2-demo-control.daluoter.workers.dev \
  npm run build
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" pages deployment list \
    --project-name=malscan-v2-demo | tee "$V2_OFFICE_PAGES_STATE/deployments-before.txt"
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" pages deploy dist \
    --project-name=malscan-v2-demo --branch=main --commit-dirty=true \
    | tee "$V2_OFFICE_PAGES_STATE/deploy.txt"
  "$V2_OFFICE_SOURCE/deployment/cloudflare/node_modules/.bin/wrangler" pages deployment list \
    --project-name=malscan-v2-demo | tee "$V2_OFFICE_PAGES_STATE/deployments-after.txt"
)
```

保存舊／新 Pages deployment ID；開啟正式 <https://malscan-v2-demo.pages.dev> 並重新載入。
preview URL 的 origin 不同，不能代替正式 Pages 的 API 驗收。這批只調整密碼文案與格式提示，
前端不解析或解密 Office 文件。

## 5. 以標準函式庫產生三份固定 smoke 檔

不需在 Cloud Shell 安裝 worker／crypto 依賴。以下以 runpy 讀取已凍結的合成 fixture，核對 manifest 的
大小與 SHA-256，不執行 fixture 內容。產物放到新私人目錄；既有目錄不覆寫。

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-office-password-source-path.txt")"
  V2_OFFICE_FIXTURES=$(mktemp -d "$HOME/malscan-v2-office-password-fixtures.XXXXXX")
  python3 - "$V2_OFFICE_FIXTURES" <<'PY_FIXTURES'
import hashlib
import json
import runpy
import sys
from pathlib import Path
module = runpy.run_path('worker/src/malscan_worker/quality/office_password_fixtures.py')
suite = json.loads(Path('worker/quality/office-password-v1.json').read_text())
cases = {case['profile']: case for case in suite['cases']}
output = Path(sys.argv[1])
profiles = [
    ('agile-aes256-docx', 'docx'),
    ('agile-aes256-external-template-docx', 'docx'),
    ('zip-aes-office-agile-aes256-docx', 'zip'),
]
for profile, extension in profiles:
    payload = module['build_office_password_fixture'](profile)
    assert len(payload) == cases[profile]['bytes']
    assert hashlib.sha256(payload).hexdigest() == cases[profile]['sha256']
    target = output / f'{profile}.{extension}'
    target.write_bytes(payload)
    target.chmod(0o600)
    print(target)
print('Public fixture-only Office password:', module['OFFICE_PASSWORD'])
print('Public fixture-only ZIP password:', module['ARCHIVE_PASSWORD'])
PY_FIXTURES
  printf '%s\n' "$V2_OFFICE_FIXTURES" > "$HOME/malscan-v2-office-password-fixtures-path.txt"
)
```

`quality-office-only` 與 `quality-office-archive-only` 只適用上述公開合成測試檔；不是正式憑證，
不將未來使用者的文件或密碼加入此生成流程。從 Cloud Shell 下載三個檔案到電腦，再經正式 Pages 新上傳。
fixture 的外部範本在 `.invalid`，是靜態關聯證據，不會連線下載；巨集與文件內容也不執行。

## 6. 在既有額度內進行 Office smoke

先確認剩餘配額。本輪成功解鎖的三個新 root 預計 **7 次 executions**：兩份直接 Office 各需初次＋密碼續跑，
ZIP→Office 需初次＋ZIP 續跑＋Office 續跑。沿用每日 10 工作、每日 20／每月 40 次 executions；
若不足，等待重置，不提高限制或建立重複 root。每次補交與結果不確定的派送都可能計入 execution。

| 檔案 | 基本操作 | 要核對的結果 |
| --- | --- | --- |
| `agile-aes256-docx.docx` | 等待密碼，再提交 `quality-office-only` | Office 路徑與剩餘次數明確；原檔仍可讀部分報告；正確後出現 `decrypted.docx`，SHA-256／大小與 manifest 明文一致，正常內容無新增風險 findings |
| `agile-aes256-external-template-docx.docx` | 等待密碼，再提交 `quality-office-only` | 解密子檔保留外部範本 relationship 證據與來源。本機基準子檔 53／medium、加密父檔繼承 15／low，本檔另為 0；這個對照未達高風險下限，不能套用 PDF 的 84 分。只憑關聯不能稱已執行或已確認惡意 |
| `zip-aes-office-agile-aes256-docx.zip` | ZIP 提交 `quality-office-archive-only`，再對 `nested/locked.docx` 提交 `quality-office-only` | ZIP 已用 1 不扣 Office；新 Office 起始為已用 0／剩餘 3。使用正確 artifact，子檔保留相同明文 hash；完成 stage 與累計額度不重設 |

若要在雲端再演練「錯誤一次→紅字→正確」，需額外 **1 次 execution，合計至少 8 次**。
在第一份 Office 正確補交前先送錯誤密碼，等待執行確認 `wrong_password`，核對紅字及已用 1／剩餘 2，
再送正確密碼。只在剩餘額度足夠時操作；若本輪只完成七次基本 smoke，錯誤紅字的 Office 雲端驗收仍記待補，
不以完成 JSON 反推已看過錯誤畫面。第三次耗盡與多 sibling 邊界已有獨立本機驗證範圍，若要另做正式演練，
先計算額外用量並保存證據，不自動加測另一批。

每個 root／解密子檔完整 JSON 應能核對：原檔身份不變、`office-decrypted` 來源、依內容型別命名、
Agile `hmac_verified`、實際 ClamAV／YARA 與適用 format／document coverage、`msrs-v1.2`、規則集 `1.1.0`。
成功解密不保證所有階段 complete；若工具失敗或預算截斷，按實際 partial 與原因記錄，不改成已通過。
正常內容是否有風險觀察、外部範本分數與父子有效風險，以本批 manifest／原生驗證與正式報告比對，
不沿用舊 PDF 的 4／84 分數。

## 7. 私有保存證據與後續清理

保留 Job 新舊 digest、Pages 新舊 deployment ID、root／child ID、等待／錯誤／完成畫面、完整報告與 status。
工作 capability 留在原瀏覽器分頁的 sessionStorage；重新整理可保留，關閉分頁可能失去存取權。
不要把真實密碼或 capability 放在截圖、公開檔名、Git 或驗收摘要。

**每個新 root 的 `retention_expires_at` 從 status 保存，不從完成報告推定。** demo 保留期仍為 24 小時；
到期加 20 分鐘後，依[保留期手冊](cloud-demo-operations.md#4-到期撤權與實體清理)逐 root 核對七個 R2
指定前綴與工作／報告存取撤回，證據記入 P0-18。R2 空清單不證明 DO row 已刪除，P0-06 仍待辦。
F-10 只有取得本批部署與新報告／畫面證據後，才能按實際完成範圍更新；日誌、已切換 Job 或本機通過均不能取代正式 smoke。

若要回復舊版，先保存診斷與停止新提交，再從 Pages 選擇保存的舊正式 deployment，
Job 使用本批來源與 state 執行 `maintain-demo.py rollback --state-dir ...`，再查 status 核對。
Worker／dispatcher 本批未變更。這只是回退方法，沒有實際演練與再次驗證前，P0-11 維持待辦。
P0-12 自動病毒庫排程、P0-14／P0-15 長期及 Cloudflare 成本亦不因本次升版而完成。

## 8. 本輪限定驗收完成與後續維護

2026-10-20 已補齊外層 ZIP 根工作 `94d643f0-0f74-45a6-9d3c-2f8dc16d8653` 的完整報告。
ZIP 固定輸入的 hash／大小、9 個節點的來源與宣告掃描範圍均符合預期，工作與靜態分析完成，
沒有等待中的後代或待核對派送。ZIP 最終已用 1／剩餘 2；內層 Office
`50b1efed-24a7-5385-b9c7-8d0316a5098f` 已用 2／剩餘 1，各自上限為 3。
整個 root 的展開額度為 8 files／19,196 bytes，與非 root 節點相加一致。
ZIP 根報告 6 分／clean，來自密碼保護封存的 6 分觀察，符合本機基準。

結合先前正常 DOCX、外部範本 DOCX 的根報告、Office 錯誤紅字截圖及人工流程確認，
**F-10 完成（限定案例）**：三個固定 DOCX 流程的正確解鎖、一次錯誤後續跑、ZIP／Office 次數獨立與
完整結果已取得證據。ZIP 解鎖後 Office 初始 0／3 依人工確認，錯誤後紅字與 1／2 有截圖，
最終成功與 ZIP 1／2、Office 2／1 計次可由根 JSON 核對；兩份 Office 詳細報告另外保留作子樹佐證。

本輪文件由使用者提供並離線核對，沒有取回雲端實體明文 bytes 或獨立查詢每次 execution 映像。
這不擴張為全部 Office 格式的雲端相容性；Office 第三次耗盡也沒有在本輪雲端演練。
後續功能接續 F-03 PDF 附件與 Office 嵌入物件深化。

各 root 的 `retention_expires_at`、到期撤權與實體清理繼續依第 7 節追蹤 P0-18；
DO 資料列清理、長期成本、真實回退、自動病毒庫更新等維護項目維持原待辦。
這些工作使用既有資料核對；本輪限定驗收已結束，不需要新增上傳或 Cloud Run execution。

其他部署者保存報告時，先確認根工作檔名與 `job_id`。內層 Office 詳細頁可使用
「返回上一層分析 → 閱讀目前分析報告 → 下載目前完整 JSON 報告」取得最外層完整報告；
子樹 JSON 與根 JSON 的證據範圍分開記錄。
