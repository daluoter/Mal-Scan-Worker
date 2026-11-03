# 續接附件驗收：更新病毒庫與修正報告介面

更新日期：2026-11-03（Asia/Taipei）。本輪來源已修正報告長網址／路徑換行及部分分析的判定呈現；
程式推送不會自動更新正式 Pages 或 Cloud Run Job。依發布訊息核對 commit 與驗證結果後再執行。

使用者 11/2 的兩份報告已證明 PDF／Office 附件提取身份正確，但所有 ClamAV 階段均因
`ClamAV daily database is stale; rebuild the signed database image` 失敗。
PDF 根檔 6 分來自 YARA-only 子檔 25 分的折算，不是完整掃描後的安全判定。
F-11 維持 1／3 通過，見[本輪紀錄](milestones/2026-11-03-document-embedded-cloud-followup.json)。

本輪只需一次受控病毒庫刷新建置、既有 Job 的 image 切換，以及 Pages 前端更新。
沿用原有 Worker、dispatcher、IAM、R2、secrets 與額度；不重建這些資源。
建置、保留映像及 smoke 仍可能產生費用；先前已刪除的七版不需重跑清理。

## 1. 保存新來源

在既有 Google Cloud Shell 執行。先核對輸出的 commit 與本輪發布訊息；若 main 已前移，
在這份新 checkout 切到發布訊息的完整 commit 後才繼續。不要修改既有操作 checkout 或舊 state。

```bash
(
  set -e
  umask 077
  if [ -e "$HOME/malscan-v2-f11-followup-source-path.txt" ]; then
    echo '本輪來源已保存；請接續既有來源與 state，不重新建立一批。'
    exit 1
  fi
  V2_FOLLOWUP_SOURCE=$(mktemp -d "$HOME/malscan-v2-f11-followup.XXXXXX")
  git clone --quiet https://github.com/daluoter/Mal-Scan-Worker.git "$V2_FOLLOWUP_SOURCE"
  cd "$V2_FOLLOWUP_SOURCE"
  git rev-parse HEAD
  test -f docs/deploy-report-followup.md
  pwd > "$HOME/malscan-v2-f11-followup-source-path.txt"
)
```

## 2. 準備一次病毒庫更新並送出非同步建置

此步保存目前 Job 設定／digest 作為回退基準，用 FreshClam 取得官方簽章資料庫，
再以候選映像執行正常檔／EICAR 的 ClamAV 與 YARA 離線控制。七天新鮮度 gate 保持啟用。
測試使用的過期資料庫 header 只存在本機回歸測試，不會進入正式映像。

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")"
  if [ -e "$HOME/malscan-v2-f11-followup-state-path.txt" ]; then
    echo '本輪 state 已存在；請查詢下一節 status，不重送建置。'
    exit 1
  fi
  V2_FOLLOWUP_PREPARE=$(mktemp "$HOME/malscan-v2-f11-followup-prepare.XXXXXX.json")
  python3 deployment/cloud-run/maintain-demo.py prepare > "$V2_FOLLOWUP_PREPARE"
  python3 - "$V2_FOLLOWUP_PREPARE" <<'PY_STATE'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert state['phase'] == 'prepared'
(Path.home() / 'malscan-v2-f11-followup-state-path.txt').write_text(state['state_dir'] + '\n')
print(json.dumps(state, indent=2))
PY_STATE
  python3 deployment/cloud-run/maintain-demo.py submit \
    --state-dir "$(cat "$HOME/malscan-v2-f11-followup-state-path.txt")"
)
```

送出後可以斷線。若指令回應不確定，保留 state 並查詢下一節，不另外 submit 或執行 `gcloud builds submit`。
若停在 `prepared`，代表尚未有已確認的建置；先核對輸出及 Cloud Build 清單再決定接續，避免重複建置。

## 3. 重連、驗證候選版並更新既有 Job

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-f11-followup-state-path.txt")"
)
```

等待 `phase=build_verified`、`build_status=SUCCESS`、`candidate_controls.success=true`。
核對三份資料庫 `signature_verified=true`、daily 所載時間與年齡、四項正常／EICAR 控制及候選 digest。
不要因為 build SUCCESS 就跳過離線控制；`status` 也會重新檢查候選 daily 是否仍在七天內。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py promote \
    --state-dir "$(cat "$HOME/malscan-v2-f11-followup-state-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-f11-followup-state-path.txt")"
)
```

確認 `phase=promoted` 才開始新上傳。本步不執行分析 Job，也不會重算既有兩份歷史報告。
新鮮度從 daily 資料庫所載時間起算，不是從 promotion 起算。
若切換後隔數天才測試，需重新核對 daily 年齡；舊 state 的 `promoted` 是發布紀錄，不是當前掃描健康證明。

### 3.1 已套用候選映像，卻停在 promotion_pending

11/3 使用者已取得 `build_verified`、`SUCCESS` 與完整離線控制；daily 28172 在控制時約 22 小時，三份資料庫簽章皆通過。
隨後 `promote` 出現 `Post-update configuration differs`。唯讀診斷確認 Job 已 Ready、image 等於候選，
唯一差異為 `/spec/template/metadata/annotations/run.googleapis.com~1client-version`。
這是 gcloud 客戶端版本註記，維護工具現已只在該精確路徑排除它；其他設定仍嚴格比對。

此情況仍在**第 3 節末尾的狀態核對**。依修正發布訊息，在同一份來源 checkout fetch 並切到修正 commit，
保留既有 `malscan-v2-f11-followup-source-path.txt`、`malscan-v2-f11-followup-state-path.txt` 與私人 state。
然後只執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")"
  python3 deployment/cloud-run/maintain-demo.py status \
    --state-dir "$(cat "$HOME/malscan-v2-f11-followup-state-path.txt")"
)
```

這會讀取現行 Job；設定完全符合候選且 Ready 時，只把本機 state 記錄為 `promoted`，不再次送出 image 更新、
不建置、不執行掃描。看到 `phase=promoted` 後接**第 4 節 Pages 更新**，再接第 5 節兩案驗收。
若仍為 pending，保留 state 並重新核對差異，不清除檢查點或直接改 phase；相同錯誤文字不代表每次都是同一原因。
原始 `job-before.json` 與 v1 指紋驗證保留，回退基準不因這項比對修正而重寫。

## 4. 更新既有 Cloudflare Pages 前端

Cloud Shell 原有 Wrangler 登入通常可以沿用。先檢查身分；如已登出，使用既有 Cloudflare 帳戶的
`npx --no-install wrangler login --device --no-browser` 完成登入，再繼續。不要建立 temporary 帳戶或新 Pages project。
多帳戶時使用原帳戶的 `CLOUDFLARE_ACCOUNT_ID` 選擇；不要分享 Token 或 OAuth 設定檔。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")/deployment/cloudflare"
  npm ci
  npx --no-install wrangler whoami
)
```

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-f11-followup-source-path.txt")/frontend"
  npm ci
  VITE_BASE_PATH=/ \
  VITE_API_DEPLOYMENT=cloud-demo \
  VITE_API_BASE_URL=https://malscan-v2-demo-control.daluoter.workers.dev \
  npm run build
  ../deployment/cloudflare/node_modules/.bin/wrangler pages deploy dist \
    --project-name=malscan-v2-demo \
    --branch=main \
    --commit-dirty=true
)
```

驗收使用正式網址 <https://malscan-v2-demo.pages.dev>。重新整理既有報告可檢查介面，但原報告的分數、
AV 失敗及 partial 不會因此改變。確認長網址在卡片內完整換行；手機寬度也不應讓整頁向右溢出。
低分且分析不完整時應有明顯警示，不能以綠色成功樣式當成有效 clean；已知高風險仍須醒目保留。

## 5. 僅重測兩個未通過案例

使用已保存、未修改的 `pdf-flate-eicar.pdf` 與 `office-embedded-pdf.docx`。
若需要重新產生，沿用[附件部署手冊第 4 節](deploy-document-embedded.md#4-在-cloud-shell-產生固定-smoke-檔)
的 frozen recipe；兩者 SHA-256 與大小需符合 `worker/quality/document-embedded-v1.json`。
端點防毒攔截 EICAR 時保持防護，在允許此測試的環境操作，不停用或規避防毒。

這次預計兩個新 root／兩次 executions，先確認額度。不提高、清空或重置每日／每月 counter，
不重傳已通過的文字附件案例，也不重跑舊失敗工作。

| 案例 | 這次需取得的結果 |
| --- | --- |
| Flate EICAR PDF | 2 節點；提取 68-byte EICAR 子檔、SHA-256 與來源正確；父子 ClamAV 實際成功執行，子檔有 EICAR 命中，YARA 命中；子檔強證據傳到父報告，本機基準為 100 分；static／batch 完整 |
| Office 嵌入 PDF | 8 節點、7 次提取／2,226 bytes；352-byte PDF 的來源與身份符合固定預期，所有節點 ClamAV／YARA 實際完成，static／batch 完整；根檔基準仍為 0 分 |

分數必須由真實偵測證據形成，不以檔名、固定答案或手動加分代替。`job_status=done`、
`report_complete=true` 只代表工作結束，不能取代 `analysis.static`、`batch_analysis` 與每個子檔的 coverage。

保存兩份最外層完整 JSON，另將 status 的 `retention_expires_at` 私下保存以便 P0-18 到期核對。
候選 digest、建置／promoted 摘要、Pages 發布結果可交給維護者核對；原始 capability、密碼與 secrets 不貼出。
F-11 在新報告核對通過前維持 1／3；P0-06 DO 清理、P0-11 真實回退、P0-12 自動更新、
P0-14 長期成本及建置來源保留等維護項目仍另行追蹤。

## 6. 發布失敗與後續更新

image 更新不確定時先查 `status`，不要再次建置或刪除 state。需要回退時使用這批保存的 state 與
[維護手冊](cloud-demo-operations.md#2-更新病毒庫及保留回退版本)；舊映像的病毒庫也可能已過期，
回退不能保證恢復有效防毒掃描，不可關閉 gate 來湊成成功。

本次刷新仍是人工更新，P0-12 的自動排程沒有因此完成。更新頻率須從 daily 年齡預留失敗修復時間；
在下一輪功能擴充前，應安排可驗證的更新／失敗告警與映像保留策略，避免再累積失效掃描或無限保留建置映像。
