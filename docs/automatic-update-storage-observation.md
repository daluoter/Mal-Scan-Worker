# 自動更新建置來源的保留期觀察

更新日期：2026-11-12（Asia/Taipei）。映像版本刪除與 GCS 建置來源物件是兩項證據；本頁只觀察私人 operations bucket 的 `build-sources/`。
不建立 Build、不執行分析、不修改 lifecycle，也不下載物件內容。舊的 multi-region `malscan-v2-poc_cloudbuild` bucket 不在本次範圍。

先保存目前實際存在物件的 metadata，之後才能對同一個名稱與 generation 確認到期後缺席。
以下命令只讀 provider，並在原私人 plan 目錄新增 `build-source-retention-baseline.json`（0600）；不改寫原 plan、journal、state 或來源 bundle。
重跑會沿用既有基準並顯示其原始觀察時間，不重新盤點或覆寫它。保留這個檔案，不上傳完整私人基準到公開儲存庫。

## 1. 現在：核對設定並保存私有基準

本輪已由使用者完成：設定與清單讀回通過，保存 3 個來源物件，當時皆未達 age 條件。
公開[紀錄](milestones/2026-11-12-build-source-retention-baseline.json)僅保留彙總；精確 metadata、私人 fingerprint 與時間留在原基準。
下列命令保留供對照，重跑仍只沿用舊基準，不能當成到期後的最新缺席查詢。

沿用現有來源 checkout 執行，不需重新 clone 或部署：

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 - <<'PY_STORAGE'
import importlib.util
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

spec = importlib.util.spec_from_file_location(
    "storage_observation_setup", "deployment/cloud-run/setup-auto-update.py"
)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
bucket = "malscan-v2-poc-db-operations"
base = "https://storage.googleapis.com/storage/v1/b/" + bucket
directory = Path((Path.home() / "malscan-v2-auto-update-plan-path.txt").read_text().strip())
target = directory / "build-source-retention-baseline.json"

def stamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp_invalid")
    return parsed.astimezone(timezone.utc)

def objects(value, observed):
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("object_list_invalid")
    seen = set()
    for row in value:
        if (not isinstance(row, dict) or set(row) != {"name", "generation", "timeCreated", "size"}
            or not isinstance(row["name"], str) or not row["name"].startswith("build-sources/")
            or row["name"] in seen or not re.fullmatch(r"[1-9][0-9]{0,18}", row["generation"])
            or not re.fullmatch(r"0|[1-9][0-9]{0,18}", row["size"])
            or stamp(row["timeCreated"]) > observed + timedelta(minutes=5)):
            raise ValueError("object_metadata_invalid")
        seen.add(row["name"])
    return sorted(value, key=lambda row: (row["name"], row["generation"]))

try:
    if (directory.is_symlink() or not directory.is_dir()
        or directory.stat().st_mode & 0o077 or target.is_symlink()):
        raise ValueError("private_directory_required")
    reused = target.exists()
    if reused:
        if not target.is_file():
            raise ValueError("baseline_file_invalid")
        wrapped = setup.read_private(target)
        saved = wrapped["baseline"]
        if wrapped["sha256"] != setup.digest(saved):
            raise ValueError("baseline_fingerprint_invalid")
    else:
        rest = setup.REST()
        fields = "name,projectNumber,metageneration,location,lifecycle,versioning,softDeletePolicy,retentionPolicy,iamConfiguration"
        before = rest.request("GET", base + "?" + urlencode({"fields": fields}))
        expected = {"rule": [{"action": {"type": "Delete"}, "condition": {
            "age": 7, "matchesPrefix": ["build-sources/"]}}]}
        if (before.get("name") != bucket or str(before.get("projectNumber")) != "371636043543"
            or not re.fullmatch(r"[1-9][0-9]{0,18}", str(before.get("metageneration", "")))
            or str(before.get("location", "")).lower() != "us-central1"
            or before.get("lifecycle") != expected
            or before.get("versioning", {}).get("enabled", False) is not False
            or str(before.get("softDeletePolicy", {}).get("retentionDurationSeconds", "0")) != "0"
            or before.get("retentionPolicy")
            or before.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled") is not True
            or before.get("iamConfiguration", {}).get("publicAccessPrevention") != "enforced"):
            raise ValueError("bucket_configuration_differs")
        rows, token, seen_tokens = [], None, set()
        for page_number in range(10):
            query = {"prefix": "build-sources/", "maxResults": 100,
                     "fields": "items(name,generation,timeCreated,size),nextPageToken"}
            if token:
                query["pageToken"] = token
            page = rest.request("GET", base + "/o?" + urlencode(query))
            items = page.get("items", [])
            if not isinstance(items, list) or len(items) > 100 or len(rows) + len(items) > 1000:
                raise ValueError("object_page_invalid")
            rows.extend(items)
            token = page.get("nextPageToken")
            if token is None or token == "":
                break
            if not isinstance(token, str) or len(token) > 8192 or token in seen_tokens:
                raise ValueError("pagination_invalid")
            seen_tokens.add(token)
        else:
            raise ValueError("object_listing_incomplete")
        after = rest.request("GET", base + "?" + urlencode({"fields": fields}))
        if before != after:
            raise ValueError("bucket_changed_during_read")
        saved = {"schema_version": 1, "bucket": bucket, "prefix": "build-sources/",
                 "observed_at": datetime.now(timezone.utc).isoformat(),
                 "bucket_configuration_sha256": setup.digest(before),
                 "objects": objects(rows, datetime.now(timezone.utc))}
        maintenance = setup.module("storage_observation_private", "maintain-demo.py")
        maintenance.write_private(target, {"baseline": saved, "sha256": setup.digest(saved)}, exclusive=True)
    if (saved.get("schema_version") != 1 or saved.get("bucket") != bucket
        or saved.get("prefix") != "build-sources/"
        or not re.fullmatch(r"[a-f0-9]{64}", saved["bucket_configuration_sha256"])):
        raise ValueError("baseline_identity_invalid")
    observed = stamp(saved["observed_at"])
    rows = objects(saved["objects"], observed)
    now = datetime.now(timezone.utc)
    due = [stamp(row["timeCreated"]) + timedelta(days=7) for row in rows]
    upcoming = min((value for value in due if value > now), default=None)
    print(json.dumps({
        "scope": "read_only_build_source_retention_baseline", "read_only": True,
        "baseline_reused": reused, "fresh_provider_reads_performed": not reused,
        "baseline_observed_at": saved["observed_at"], "baseline_sha256": setup.digest(saved),
        "baseline_configuration_verified": True, "prefix_listing_read_complete_at_baseline": True,
        "saved_object_count": len(rows), "saved_object_bytes": sum(int(row["size"]) for row in rows),
        "saved_objects_now_age_eligible": sum(value <= now for value in due),
        "next_age_eligible_at_taipei": upcoming.astimezone(ZoneInfo("Asia/Taipei")).isoformat() if upcoming else None,
        "actual_object_expiry_verified": False, "billed_savings_verified": False,
        "remote_mutations": False, "cloud_run_executed": False,
    }, indent=2))
except Exception:
    print(json.dumps({"success": False, "error": "storage_baseline_not_verified",
                      "remote_mutations": False, "cloud_run_executed": False}))
    raise SystemExit(1)
PY_STORAGE
)
```

將公開摘要貼回供核對；完整基準留在 Cloud Shell。403、逾時、設定差異、分頁未讀完或 metadata 身分不符都會停止，不把錯誤當成空清單。
本次最多讀十頁、共一千筆。list 分頁不是跨物件的原子快照；保存的名稱與 generation 用於之後逐筆精確確認，不用空清單推定未曾觀察過的物件已刪除。

## 2. 依實際觀察時間安排到期讀回

`next_age_eligible_at_taipei` 由本次實際物件 `timeCreated + 7 天` 計算，表示下一個符合 age 條件的時刻，**不是保證刪除時間**。
`saved_objects_now_age_eligible` 只計算保存基準中的物件年齡，不表示它們目前仍存在或已刪除；重跑基準命令不會更新物件清單。
若清單為空、所有物件已達 age，或回傳 null，先提供摘要，不新增測試物件、不改 lifecycle。

設定核對與物件到期後的實體缺席分開驗收。後續將用保存的精確名稱／generation 發出 metadata GET，並再次核對 soft delete／versioning；不使用 `alt=media` 下載內容。
這一步尚未提供後續缺席結果，`actual_object_expiry_verified` 保持 false；不能僅憑 lifecycle 設定或日期已到宣稱清理成功。

官方 [Object Lifecycle Management](https://cloud.google.com/storage/docs/lifecycle) 說明正數 age 從物件建立時間計算，動作非同步執行，沒有保證的最長延遲。
到點後可再次觀察，未消失就保存仍存在的結果，不能自行補一個固定二十分鐘或二十四小時的刪除承諾。
規則僅涵蓋 `build-sources/`；`bundles/`、協調 state、lease 與其他前綴繼續保留。物件缺席也不代表 registry layer 容量或帳單已下降，費用仍以專案／TWD／SKU／日期範圍另行核對。

## 3. 等待來源到期時：並行觀察容量與費用

費用觀察不需要等本節來源到期驗證完成。先在 Billing Reports 匯出 **2026/11/1 至報表目前已入帳日期**的 CSV：

- 幣別使用已確認的 **TWD**，篩選專案 **`malscan-v2-poc`**；保留篩選範圍的證據。
- 依 SKU 分組，保留服務／SKU、使用費、抵用／折扣與淨額。若介面無法設定專案篩選，另匯出依專案分組的報表供核對，不直接假設整個帳單帳戶只有此專案。
- 報表日期與資料更新時間一起保存；資料尚未入帳、前後期間長度不同或抵用不同，都不能直接歸因為清理節省。
- 原始 CSV 與帳單身份資訊保持私人，可提供維護者核對，不提交 GitHub；Cloudflare 帳單與用量另外處理。

容量可先讀取倉庫 metadata，作為後續同條件比較的基準：

```bash
gcloud artifacts repositories describe malscan-v2-poc \
  --project=malscan-v2-poc --location=us-central1 \
  --format='json(name,sizeBytes)'
```

若缺少 `sizeBytes`，記為未觀察到，不能當成零。倉庫大小與單一映像顯示大小、共享 layer、當期儲存計費仍有不同範圍；版本已刪除不表示費用歸零。
此基準沒有精確的清理前容量，後續趨勢需要多個觀察時點與對應 SKU 報表一起判讀。上述命令不更動資源。
