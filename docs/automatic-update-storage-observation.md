# 自動更新建置來源的保留期觀察

更新日期：2026-11-21（Asia/Taipei）。本頁追蹤私人 operations bucket 的 `build-sources/` 保留期與 Artifact Registry 儲存費。
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

本批以原私人基準逐筆查詢精確 generation，已完成到期驗證。 [到期後只讀查詢](build-source-expiry-readback.md)
三個物件各自從建立時間起算七天，最早一個達 age 不代表三個同時到期；未到期物件保持保存是正常結果。
各次只讀查詢均沿用第 1 節保存的初始基準。

11/14 已取得[第一筆到期後缺席紀錄](milestones/2026-11-14-build-source-expiry-acceptance.json)：1 個符合年齡的保存 generation 回傳 404，另 2 個尚未符合條件而未查詢。
該次 `actual_object_expiry_verified: true` 僅涵蓋當時符合條件者；`all_saved_objects_absent_verified: false` 保留整批未完成的差別。11/16 的[後續讀回](milestones/2026-11-16-build-source-expiry-followup.json)則是 2 個已到期者中 1 個 404、1 個 200，另 1 個未到期，因此當次 `actual_object_expiry_verified: false`；原先單筆缺席驗收保留。11/17 的[驗收讀回](milestones/2026-11-17-build-source-expiry-acceptance.json)確認當時已到期的兩筆皆為 404。第三個當時尚未符合年齡，整批缺席仍待驗證。

11/19 三筆已符合年齡，兩筆為 `404`，一筆仍為 `200`。11/20 精確 generation 查詢確認三筆皆為 `404`，bucket 設定與私人基準核對一致，本批到期缺席驗證完成。 [11/19 讀回](milestones/2026-11-19-build-source-expiry-followup.json) · [11/20 驗收](milestones/2026-11-20-build-source-expiry-acceptance.json)
11/21 執行基準命令時沿用舊快照，`fresh_provider_reads_performed: false`。到期後缺席以 11/20 的精確 generation 驗收為準。
`saved_objects_now_age_eligible` 只計算保存基準中的物件年齡，不表示它們目前仍存在或已刪除；重跑基準命令不會更新物件清單。
若清單為空、所有物件已達 age，或回傳 null，先提供摘要，不新增測試物件、不改 lifecycle。

設定核對與物件到期後的缺席分開驗收。新的讀回使用保存的精確名稱／generation 發出 metadata GET，並再次核對 soft delete／versioning；不使用 `alt=media` 下載內容。
初始基準的 `actual_object_expiry_verified: false` 保持歷史紀錄，不改寫；後續缺席驗收另記新紀錄。不能僅憑 lifecycle 設定或日期已到宣稱清理成功。

官方 [Object Lifecycle Management](https://cloud.google.com/storage/docs/lifecycle) 說明正數 age 從物件建立時間計算，動作非同步執行，沒有保證的最長延遲。
到點後可再次觀察，未消失就保存仍存在的結果，不能自行補一個固定二十分鐘或二十四小時的刪除承諾。官方的二十四小時說明是設定變更生效延遲，不是刪除時限。若再次觀察仍為 200，再核對物件 hold／retention metadata，保持原基準與規則。
規則僅涵蓋 `build-sources/`；`bundles/`、協調 state、lease 與其他前綴繼續保留。物件缺席也不代表 registry layer 容量或帳單已下降，費用仍以專案／TWD／SKU／日期範圍另行核對。

## 3. 容量與費用觀察

11/21 收到 11/11–11/18 的 SKU 彙總，主要費用仍來自 Artifact Registry Storage，另有少量其他儲存與傳輸費。匯出缺少日期、專案及幣別欄位，待取得帶日期的報表與篩選範圍後再做前後比較。同一倉庫的新容量讀值接近 11/16，仍低於 11/14 盤點基準。 [11/21 摘要](milestones/2026-11-21-storage-cost-readback.json)

比較 11/14 清理前後的費用時，選用報表日期 11/11–11/13 與 11/16–11/18，各三天，略過清理及過渡日 11/14–11/15。

1. 在 Cloud Billing 的 Reports 使用 **SKUs — daily costs this month** 預設。將 **Charge period** 設為 11/11–11/18，**Group by** 設為 **Date > SKU**，篩選專案 `malscan-v2-poc` 及 **Artifact Registry Storage** SKU。匯出一份 CSV 並確認有日期欄。報表按美國太平洋時間切分每日用量。 [Google Cloud 報表說明](https://docs.cloud.google.com/billing/docs/how-to/reports)
2. 若無法匯出日期欄，依 **SKU** 分組並針對兩個期間各匯出一份 CSV，比較等長期間總額。兩段使用相同專案、SKU、幣別與抵用設定，並保存日期範圍及匯出時間。
3. 費用可能需要超過 24 小時才入帳。若報表數字有變動，以後續讀回重新比較。原始 CSV 與帳單資訊留在私人紀錄。

11/14 與 11/16 已取得同一倉庫的容量讀值。日後若需加做同口徑比較，可沿用以下查詢。

```bash
gcloud artifacts repositories list \
  --project=malscan-v2-poc --location=us-central1 \
  --filter='name="projects/malscan-v2-poc/locations/us-central1/repositories/malscan-v2-poc"' \
  --limit=2 \
  --format='json(name,sizeBytes)'
```

`describe` 會先印出人類可讀的 `Repository Size`，再移除格式化 JSON 的 `sizeBytes`；本頁改用既有盤點工具相同的 list 介面取得精確容量欄位。
請確認只列出一個名稱完全相符的 repository；若仍缺少 `sizeBytes`，記為未觀察到，不能當成零。倉庫大小與單一映像顯示大小、共享 layer、當期儲存計費仍有不同範圍；版本已刪除不表示費用歸零。
11/16 的倉庫讀值低於 11/14 的盤點基準。節省金額仍待上方相同口徑的費用報表核對。 [容量觀察](milestones/2026-11-16-registry-capacity-observation.json)

預算百分比通知與實際請款分開判讀：通知表示依該預算的專案範圍與抵用設定，計算金額觸及門檻；它不列出造成費用的服務／SKU，也不能單獨證明信用卡已扣款。
使用者提供的本輪通知日期早於已驗收的映像清理，不能用這封通知推定清理後費用仍新增；後續仍需相同日期範圍、專案與 SKU 的實際報表。
原始郵件、帳單識別資訊、精確財務數字及 CSV 不提交公開 GitHub。

11/14 已收到並解析當期服務彙總 CSV，專案篩選由使用者明確確認；原檔不需要重傳。
服務彙總足以觀察哪個服務佔主要淨費用，不能代替 SKU 或逐日資料。後續 **SKU CSV 已收到**：主要淨費用確認為 **Artifact Registry Storage**，見[精簡觀察紀錄](milestones/2026-11-14-sku-cost-observation.json)，這份檔案不需要重傳。
GCS 來源到期驗證已完成。Registry 的映像儲存費待逐日 SKU 報表核對，搭配同口徑的 `sizeBytes` 觀察判讀。
若要判斷清理前後變化，另需對應日期與入帳更新時間；同一份月內累計增加，不能單獨證明每日成本增加或清理失效。

11/14 已核對私人逐版 metadata，並完成 3 個舊映像的限定清理。前後盤點範圍與保護引用收錄於當批紀錄。 [盤點彙總](milestones/2026-11-14-current-registry-inventory-acceptance.json) · [清理驗收](milestones/2026-11-14-legacy-registry-review.json)
