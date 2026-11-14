# 建置來源到期後的只讀確認

更新日期：2026-11-14（Asia/Taipei）。本輪最早符合七天條件的時刻已過，可以現在執行。
此指令讀取原私人基準，查詢**已達七天的既有物件 generation**；不重新保存基準、不建立或刪除物件，也不下載內容。
沿用現有 Cloud Shell 來源目錄與原 plan，不需要重新 clone、建置或部署。

```bash
(
  set -e
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 - <<'PY_EXPIRY'
import importlib.util
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

def require(condition):
    if not condition:
        raise ValueError("retention_readback_not_verified")

def stamp(value):
    require(isinstance(value, str))
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None)
    return result.astimezone(timezone.utc)

try:
    spec = importlib.util.spec_from_file_location(
        "expiry_readback_setup", "deployment/cloud-run/setup-auto-update.py"
    )
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    directory = Path((Path.home() / "malscan-v2-auto-update-plan-path.txt").read_text().strip())
    target = directory / "build-source-retention-baseline.json"
    require(not directory.is_symlink() and directory.is_dir()
            and not directory.stat().st_mode & 0o077 and target.is_file())
    wrapped = setup.read_private(target)
    require(isinstance(wrapped, dict) and set(wrapped) == {"baseline", "sha256"})
    saved = wrapped["baseline"]
    require(isinstance(saved, dict) and wrapped["sha256"] == setup.digest(saved))
    require(set(saved) == {"schema_version", "bucket", "prefix", "observed_at",
                           "bucket_configuration_sha256", "objects"})
    require(type(saved["schema_version"]) is int and saved["schema_version"] == 1
            and saved["bucket"] == "malscan-v2-poc-db-operations"
            and saved["prefix"] == "build-sources/"
            and isinstance(saved["bucket_configuration_sha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", saved["bucket_configuration_sha256"]))
    started = datetime.now(timezone.utc)
    baseline_at = stamp(saved["observed_at"])
    require(baseline_at <= started + timedelta(minutes=5))
    objects = saved["objects"]
    require(isinstance(objects, list) and len(objects) <= 1000)
    seen, due = set(), []
    for row in objects:
        require(isinstance(row, dict) and set(row) == {"name", "generation", "timeCreated", "size"})
        name, generation, size = row["name"], row["generation"], row["size"]
        require(isinstance(name, str) and name.startswith("build-sources/")
                and len(name.encode("utf-8")) <= 1024 and name not in seen
                and isinstance(generation, str) and re.fullmatch(r"[1-9][0-9]{0,18}", generation)
                and isinstance(size, str) and re.fullmatch(r"0|[1-9][0-9]{0,18}", size))
        seen.add(name)
        created = stamp(row["timeCreated"])
        require(created <= baseline_at + timedelta(minutes=5))
        due.append(created + timedelta(days=7))
    rest = setup.REST()
    base = "https://storage.googleapis.com/storage/v1/b/" + saved["bucket"]
    fields = "name,projectNumber,metageneration,location,lifecycle,versioning,softDeletePolicy,retentionPolicy,iamConfiguration"
    before = rest.request("GET", base + "?" + urlencode({"fields": fields}))
    require(isinstance(before, dict)
            and setup.digest(before) == saved["bucket_configuration_sha256"])
    expected = {"rule": [{"action": {"type": "Delete"}, "condition": {
        "age": 7, "matchesPrefix": ["build-sources/"]}}]}
    require(before.get("name") == saved["bucket"]
            and str(before.get("projectNumber")) == "371636043543"
            and str(before.get("location", "")).lower() == "us-central1"
            and re.fullmatch(r"[1-9][0-9]{0,18}", str(before.get("metageneration", "")))
            and before.get("lifecycle") == expected
            and before.get("versioning", {}).get("enabled", False) is False
            and str(before.get("softDeletePolicy", {}).get("retentionDurationSeconds", "0")) == "0"
            and not before.get("retentionPolicy")
            and before.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled") is True
            and before.get("iamConfiguration", {}).get("publicAccessPrevention") == "enforced")
    results, eligible, absent, present = [], 0, 0, 0
    for index, (row, eligible_at) in enumerate(zip(objects, due), 1):
        if eligible_at > started:
            continue
        eligible += 1
        query = {"generation": row["generation"], "fields":
                 "bucket,name,generation,timeCreated,size,timeDeleted,softDeleteTime,hardDeleteTime"}
        value = rest.request("GET", base + "/o/" + quote(row["name"], safe="")
                             + "?" + urlencode(query), missing_ok=True)
        if value is None:
            absent += 1
            status = 404
        else:
            require(isinstance(value, dict) and value.get("bucket") == saved["bucket"]
                    and all(value.get(key) == row[key] for key in ("name", "generation", "size"))
                    and stamp(value.get("timeCreated")) == stamp(row["timeCreated"])
                    and not any(value.get(key) for key in ("timeDeleted", "softDeleteTime", "hardDeleteTime")))
            present += 1
            status = 200
        results.append({"saved_object_index": index, "http_status": status})
    after = rest.request("GET", base + "?" + urlencode({"fields": fields}))
    require(after == before and setup.read_private(target) == wrapped)
    verified = eligible > 0 and absent == eligible
    upcoming = min((value for value in due if value > started), default=None)
    print(json.dumps({
        "scope": "read_only_saved_build_source_expiry", "read_only": True,
        "query_started_at": started.isoformat(), "observed_at": datetime.now(timezone.utc).isoformat(),
        "baseline_configuration_unchanged": True, "private_baseline_unchanged": True,
        "saved_object_count": len(objects), "age_eligible_saved_count": eligible,
        "not_yet_age_eligible_saved_count": len(objects) - eligible,
        "age_eligible_absent_count": absent, "age_eligible_present_count": present,
        "age_eligible_results": results,
        "next_age_eligible_at_taipei": upcoming.astimezone(ZoneInfo("Asia/Taipei")).isoformat() if upcoming else None,
        "actual_object_expiry_verified": verified,
        "all_saved_objects_absent_verified": verified and eligible == len(objects),
        "lifecycle_deletion_cause_verified": False, "billed_savings_verified": False,
        "remote_mutations": False, "cloud_run_executed": False,
    }, indent=2))
except Exception:
    print(json.dumps({"success": False, "error": "retention_readback_not_verified",
                      "actual_object_expiry_verified": False,
                      "remote_mutations": False, "cloud_run_executed": False}))
    raise SystemExit(1)
PY_EXPIRY
)
```

將摘要 JSON 貼回即可。名稱、generation、基準 fingerprint 與物件內容不會輸出；完整私人基準繼續留在 Cloud Shell。

- `actual_object_expiry_verified: true`：至少一個保存物件已滿七天，且本次所有符合條件的精確 generation 都回傳 404，接受這些物件到期後缺席的限定案例。
- `all_saved_objects_absent_verified: true`：另表示保存的整批物件皆符合年齡條件且缺席。只有最早一個物件到期，不代表三個物件應同時刪除。
- 仍為 200 或尚無符合年齡的物件：會照實列出計數，不能當成已刪除，不手動補刪或重建基準。
- 403、逾時、身份不符、基準變更或 bucket 設定漂移：輸出固定錯誤，不會被當成 404。

這是個別 metadata 查詢，沒有原子快照或刪除動作。即使時間與設定相符，若無對應 provider 刪除事件，仍不能斷言由 lifecycle 執行刪除；也不能據此宣稱底層容量已回收或帳單已下降。
這份確認只涵蓋保存的 `build-sources/` 物件；`bundles/` 與 state 的實際存在需另行核對，lease 在 idle 時可以正常不存在。
