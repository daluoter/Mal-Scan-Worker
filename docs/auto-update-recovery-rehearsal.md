# 自動更新中斷與重連演練（P0-12）

更新日期：2026-11-12（Asia/Taipei）。本頁使用 `rehearse-auto-update-recovery.py`，沿用已安裝的私人自動更新計畫。

**本輪復原、自動清理交易及最新 404／200／200 版本查詢均已通過限定案例驗收。下一步為[GCS 建置來源保留期觀察](automatic-update-storage-observation.md)。**
第 1–5 節保留演練程序供查考，本輪無須重跑 `prepare`、取消或 `resume`。

使用者於台北 **11/12 00:23:06** 讀回第 6 節清理 checkpoint：`completed`、選中與刪除各 1 個、`pending: null`。
控制器已刪除舊自動版 `493fd6bd…bfc21c` 並完成當時完整盤點讀回確認，目前 `f4e433ab…f8cd68` 與回退 `4b81ba05…edc975` 保留。
後續台北 **11/12 00:29:55–00:30:01** 的三個精確 Version GET 依序為 **404／200／200**，`fresh_registry_absence_verified: true`。
見[清理紀錄](milestones/2026-11-12-automatic-image-cleanup-acceptance.json)。第 6–7 節均已完成，本輪無須重複執行；GCS 來源到期、容量與費用仍待觀察。

使用者提供的原 controller 為 `d26087e7-fd27-480c-b419-52eb3c80e1a3`，候選 Build 為 `196af19d-17ac-49f3-a62f-0023d869356c`，
接續 controller 為 `1f3aef61-b0df-4228-b97c-fe2b10d303f8`。結果 `recovery_verified`、`candidate_build_reused` 皆為 true，沒有自動重送寫入或執行分析 Job。
發布 `db-20261111T152527Z-2fd604dfa556` 使用 `f4e433ab…f8cd68`；工具核對原目前版 `4b81ba05…edc975` 成為回退版。
重連聲明於台北 **23:30:36** 保存，復原通過核對於 **23:37:35** 保存；這不是獨立登入歷史或精確映像切換時間。
見[11/11 驗收紀錄](milestones/2026-11-11-automatic-update-recovery-acceptance.json)；尚不據此結案自動清理、儲存空間回收、帳單或 P0-11 真實回退。

歷史準備時段為 **11/11 23:20 開始監看、23:23 自然更新**，允許時段 23:18–23:43；
當時目前／回退基準為 `4b81ba05…edc975`／`493fd6bd…bfc21c`。更早的 11/8 推算與 11/9 準備紀錄繼續保留，不用於重新取消工作。

| 時機 | 你要執行的命令 | 會做什麼 |
| --- | --- | --- |
| 準備階段（本輪已完成） | `prepare` | 只讀核對，保存私人演練紀錄與目標時間 |
| 目標更新前約三分鐘 | `watch-and-interrupt` | 等待本次自然更新，核對後取消一個維護 controller |
| 確認中斷、關閉並重連後 | `status`，再 `resume --confirm-reconnected` | 查回原紀錄，最多建立一個接續 controller |
| 接續提交後 | `status` | 讀回同一候選、Job 與復原結果 |

## 這次要驗證什麼

11/6 台北 15:19 的只讀基準已通過：目前映像為 `493fd6bd…bfc21c`、回退版為 `4a018a2a…10b263`，
daily `28174` 建立於台北 11/5 14:26:24。三天門檻為台北 11/8 14:26:24，下一個符合門檻的排程是當晚 23:23。
這是 11/6 當時的推算，並非 11/9 的最新雲端狀態。真正演練前會重新核對並重新計算下一個符合門檻的排程。

Cloud Shell 視窗關閉時，雲端更新程序仍可能繼續執行。因此這次包含兩份證據：

1. 工具受控取消一個已核對的維護 controller，保存其 campaign 與候選 Build，驗證真正中斷後可接續。
2. 操作者關閉／重連 Cloud Shell，沿用同一份私人紀錄查詢及接續，保存明確的人工確認。

工具只會選取本輪已核對的維護 controller；候選映像 Build 與分析 Job 保留各自原有流程。
它不強迫病毒庫提前到期，也不修改原 plan、核准來源、全域 enabled state 或 lease。
接續的標準 controller 仍會依原政策執行更新與有界清理。
本演練與 P0-11 的實際映像回退分開驗收，清理／保留期與費用也繼續各自追蹤。

## 1. 現在：準備私人演練紀錄

本輪已完成，本節與後續第 2–5 節命令保留供對照；不需要重新建立準備紀錄或重做演練。

先依本批交付訊息更新本機來源至包含演練工具的 commit，再執行：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py prepare \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

這個 `prepare` 讀取已核准來源、健康狀態、目前 Job 與排程，並在原 plan 目錄建立私人 `recovery-rehearsal.json`。
它不取消工作、不提交新 Build，也不重新安裝自動更新資源。
原本的 plan、來源 bundle、操作 journal 與全域 state 繼續使用。

預期為 `phase: prepared`。保存摘要顯示的目標排程與監看時段；今天先完成這一步即可。
重複執行會沿用同一份紀錄，不能用另建計畫來清除未知的操作結果。
若已有舊的演練紀錄且 `window_has_passed: true`，先保留並提供摘要，不能將它當作新計畫使用。
若回報 `recovery_prepare_too_close_to_due_tick`，代表距離下一個到期排程不足五分鐘；本機不會建立這份演練紀錄，待該次正常更新結束後再重新準備。

## 2. 演練當天：在更新前開始監看

在 `recommended_watch_at_taipei` 顯示的時間開啟 Cloud Shell（通常是目標排程前三分鐘），執行：
本輪已準備的時間為 **2026/11/11 23:20（Asia/Taipei）**。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py watch-and-interrupt \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

輪詢等待上限為 15 分鐘，網路讀回另需時間；取消前會再次確認仍在目標排程前五分鐘至後二十分鐘內。
開始後會先顯示 `phase: armed`、`waiting_for_natural_candidate: true`；這是等待摘要，需繼續等待命令返回最後結果。
若十五分鐘輪詢結束後最後仍為 `armed`，表示尚未核對並送出取消；與固定錯誤一樣，先保留完整輸出供核對，不算中斷成功。
工具等待自然更新，重新核對原基準、維護鎖 owner、controller 身分／固定來源、campaign 與候選 Build。
候選 Build 尚為 `QUEUED`／`PENDING` 時繼續等待；整體為 `WORKING`、建立時間不超過 90 秒且各項檢查通過時，才會先保存取消意圖，再對綁定的 controller 發出一次取消請求。
Build 的細部步驟狀態未必即時更新，本演練不宣稱精確停在某個 Docker 子步驟。

取消有競爭時序：若更新已正常完成或候選／campaign 已離開預期狀態，工具會保留紀錄並停止。
`missed_window` 表示未成功捕捉中斷時機，不算復原驗收通過，也不會因而再建立一筆接續 Build。

## 3. 查詢中斷結果，再關閉／重連

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py status \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")"
)
```

`cancel_pending` 表示取消意圖已保存、結果仍待讀回；使用同一個 `status` 查詢，不重送取消。
`interrupted` 才表示已確認原 controller 為 `CANCELLED`，且原 campaign 與候選 Build 仍可識別。
工具不會手動刪除 lease；接續程序會先確認舊 owner 已終止，再使用原有的條件式接管機制。

取得 `interrupted` 後，關閉 Cloud Shell 視窗，再重新開啟並登入同一帳號。
回來先執行本節相同的 `status`，確認仍是同一份紀錄、campaign 與候選 Build。
若監看期間先發生斷線，回來也先查 `status`；保留原紀錄，依目前階段接續。

## 4. 重連後：接續同一個候選

實際完成上一節的關閉／重連後，再執行：

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 deployment/cloud-run/rehearse-auto-update-recovery.py resume \
    --plan-dir "$(cat "$HOME/malscan-v2-auto-update-plan-path.txt")" \
    --confirm-reconnected
)
```

`--confirm-reconnected` 保存的是操作者已重連的明確聲明，不代表工具讀取了瀏覽器或登入歷史。
工具核對舊 controller 已取消、同一個 campaign／候選仍在、核准來源與允許的 Job 狀態相符，且沒有其他工作持有維護鎖。
它先保存唯一接續意圖，再最多建立一個使用原核准來源的 controller Build。
接續請求的排隊 TTL 為五分鐘，並要求距下一次 Scheduler 派送超過三十分鐘；不以修改排程或停用告警取得演練時段。
來源、候選或 Job 狀態不符時停止，不手動改寫原 campaign 或全域 phase。

若建立回應遺失，原意圖與唯一 tag 用於查回結果，不會因再次輸入命令而直接重送建立。
接著使用第 3 節的 `status` 讀回同一筆演練；候選 Build 尚未完成時可稍後再查。

## 5. 完成條件與異常處理

只有工具核對到 `phase: recovered`，並完成同一候選、controls、Job 與接續 controller 的證據核對後，才記錄本次復原通過。
驗收包含：

- 原維護 controller 的取消結果已確認，未知結果沒有自動重送。
- 原 campaign 與候選 Build 身分保留，同一發布沒有多出第二個候選建置。
- 接續使用已核准來源與原檢查點；新映像、目前／回退指標及 Job 完整設定符合預期。
- 候選的官方簽章與離線控制通過，接續 controller 的健康輸出與本次演練相符。
- 依精確候選 Build 再讀實際 controls，並確認完整 Job 設定只改變預期映像；平台產生的既有已知 metadata 使用相同比較規則。
- 操作者重連的人工確認與雲端接續證據分開保存。

`prepared`、`armed`、`cancel_pending`、`resume_pending`、`resume_submitted` 都不是已通過。
`missed_window` 或固定錯誤碼也不能當作復原成功；保留安全摘要供核對。
原 plan、bundle、journal 與演練 sidecar 保持在 Cloud Shell HOME；全域 coordinator state／lease 繼續保存在原私人 GCS bucket。
公開紀錄只使用審查後的 metadata 與 hash。

演練預期最多多用一個接續 controller Build，候選映像沿用自然更新的一次建置。
這些維護工作不呼叫分析 Job 的 execute API，不消耗 demo 掃描 execution 額度；Cloud Build 及相關儲存／日誌仍有各自計費方式，不承諾零費用。

## 6. 本輪通過後：讀回自動清理摘要

本輪已取得上述讀回與限定驗收；以下命令保留供對照。它只讀私人 GCS checkpoint，輸出已驗證的清理 metadata；不輸出完整 state、plan、環境變數或憑證。
接續 controller 會執行原有清理政策，但 `recovered` 本身不表示刪了幾個映像。
下一個 Scheduler tick 可能替換上一輪 completed 清理紀錄，宜先保存這次摘要；若已被替換，也不為補證據再送建置或強制刪除。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 - <<'PY_CLEANUP'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path("deployment/cloud-run").resolve()))
import auto_update as auto
import auto_retention as retention

store = auto.Store("malscan-v2-poc-db-operations")
raw, generation = store.load_json("state.json")
state = auto.validate_state(raw)
if state["active"] is not None:
    raise RuntimeError("controller_update_in_flight")

result = {
    "scope": "read_only_saved_automatic_cleanup_evidence",
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "read_only": True,
    "current_image": state["current"]["image"],
    "rollback_image": state["current"]["rollback_image"],
    "cleanup_checkpoint_observed": state.get("cleanup") is not None,
    "fresh_registry_absence_verified": False,
    "billed_savings_verified": False,
    "remote_mutations": False,
    "cloud_run_executed": False,
}
if state.get("cleanup") is not None:
    cleanup = retention._validate_state(
        state["cleanup"],
        retention._ownership(state["owned"]),
        {
            "current": state["current"]["image"],
            "rollback": state["current"]["rollback_image"],
            "pending": None,
        },
    )
    result["saved_cleanup"] = {
        key: cleanup[key]
        for key in (
            "scope", "phase", "created_at", "observed_at",
            "selected", "removed", "pending",
        )
    }
    result["saved_cleanup"]["candidate_count"] = len(cleanup["selected"])
    result["saved_cleanup"]["removed_count"] = len(cleanup["removed"])

_, final_generation = store.load_json("state.json")
if final_generation != generation:
    raise RuntimeError("coordinator_changed_during_read")
print(json.dumps(result, indent=2))
PY_CLEANUP
)
```

判讀方式：

- `saved_cleanup.phase: completed`、`removed_count > 0`：控制器保存了刪除及當時完整盤點讀回的證據，下一步可對這些精確 digest 補最新缺席查詢。
- `completed` 但 `removed_count: 0`：這份紀錄沒有刪除候選；依其時間確認是哪一輪，不能據此推定其他輪次從未清理。
- checkpoint 未觀察到、非 completed 或出現錯誤：先提供摘要／固定錯誤碼；不重送 `resume`，不改寫 state。

政策只處理自動流程 ledger 擁有、比目前與回退版都舊、且完整盤點未發現引用的合格映像；目前版與回退版保留。
程式中的 24 小時是盤點／刪除計畫有效期，並非映像固定保留一天。GCS 建置來源的保留期需另外讀回設定與實際到期物件。
版本刪除、最新 registry 缺席、底層容量回收與帳單節省是不同證據；本節不驗證費用。之後再核對 TWD 專案／SKU 的使用費、抵用與淨額，以及 Cloudflare 獨立用量。

## 7. 確認本輪三個映像版本的最新存在狀態

本輪已取得上述三個精確版本讀回，以下命令保留供對照，不需要重跑以補做相同驗收。

以下沿用現有 checkout 的 REST client，只對 Artifact Registry 的三個精確 Version 發出 GET；不建立 Build、不執行分析、不刪除映像。
三個角色取自台北 11/12 00:23 的清理摘要；本指令查詢版本存在狀態，不重新查 live Job 設定，也不改變目前／回退指標。
預期舊版為 HTTP 404，目前版與回退版為 HTTP 200；只有三者符合預期，整體核對才通過。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 - <<'PY_REGISTRY'
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

spec = importlib.util.spec_from_file_location(
    "registry_presence_setup", Path("deployment/cloud-run/setup-auto-update.py")
)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
rest = setup.REST()
prefix = (
    "projects/malscan-v2-poc/locations/us-central1/"
    "repositories/malscan-v2-poc/packages/full-worker/versions/"
)
digests = {
    "removed": "493fd6bd011d136fb6cd85a3e5cb13c363bb9ded0b2617d07fc5a710b9bfc21c",
    "reported_current": "f4e433ab8dba941fa820ece4940dcec725fcb06155acf390622300e20cf8cd68",
    "reported_rollback": "4b81ba056abef2372f7cab901582c7b8960a3e4d38c30562e5c039c760edc975",
}
rows = []
query_started_at = datetime.now(timezone.utc).isoformat()
for role, digest in digests.items():
    version = "sha256:" + digest
    try:
        value = rest.request(
            "GET",
            "https://artifactregistry.googleapis.com/v1/"
            + prefix + quote(version, safe="") + "?fields=name",
            missing_ok=True,
        )
        if value is not None and (
            not isinstance(value, dict) or value.get("name") != prefix + version
        ):
            raise RuntimeError("registry_version_identity_invalid")
    except Exception:
        print(json.dumps({
            "success": False,
            "scope": "read_only_exact_registry_version_presence",
            "error": "registry_version_read_failed",
            "role": role,
            "fresh_registry_absence_verified": False,
            "remote_mutations": False,
            "cloud_run_executed": False,
        }))
        raise SystemExit(1)
    rows.append({
        "role_in_saved_report": role,
        "digest": version,
        "http_status": 404 if value is None else 200,
        "present": value is not None,
    })

retained_present = all(row["present"] for row in rows[1:])
verified = not rows[0]["present"] and retained_present
print(json.dumps({
    "scope": "read_only_exact_registry_version_presence",
    "query_started_at": query_started_at,
    "observed_at": datetime.now(timezone.utc).isoformat(),
    "read_only": True,
    "versions": rows,
    "reported_retained_versions_present": retained_present,
    "fresh_registry_absence_verified": verified,
    "live_job_configuration_queried": False,
    "billed_savings_verified": False,
    "remote_mutations": False,
    "cloud_run_executed": False,
}, indent=2))
raise SystemExit(0 if verified else 1)
PY_REGISTRY
)
```

將輸出提供給維護者核對。403、逾時、網路或身份不符均會中止，不能當成 404；不因查詢失敗而重新刪除。
若後續自然更新已改變版本保留情況，先依查詢時間與原清理紀錄核對，不將舊角色當成最新 Job 指標。
這是三次個別版本查詢的結果，不是整個倉庫的原子盤點；即使核對成功，也不證明 layer 空間或帳單已下降。

接續的保留期觀察應涵蓋 operations bucket 的 `build-sources/` 七天 lifecycle 設定與到期物件；`bundles/` 與 state 繼續保存。
保留期到點不等於已實體刪除，不從這份映像摘要推定 GCS 結果。費用則以專案 `malscan-v2-poc`、TWD、相同日期與 SKU 的使用費／抵用／淨額比較，Cloudflare 另行核對。
