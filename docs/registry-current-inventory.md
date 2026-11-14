# 自動更新啟用後的映像只讀盤點

更新日期：2026-11-14（Asia/Taipei）。用來核對目前倉庫版本與 Cloud Run 引用，供費用評估使用；不是刪除計畫。
沿用現有 Cloud Shell 來源目錄，不需要重新建置或更新服務。盤點會讀多區域 Job、未完成 execution、服務與 revision，可能需要一些時間。

自動更新已切換過映像，Cloud Shell HOME 的舊人工 checkpoint 不一定對應目前 Job。
本指令從私人 coordinator 讀回並驗證目前 checkpoint，只在私人暫存 HOME 還原它，讓既有 Inspector 依最新版本核對回退引用；離開後刪除暫存副本。這個暫存路徑只交給 Inspector，不會改寫 `$HOME` 或切換 `gcloud` 憑證設定。
不呼叫 controller 的 `run`／`cleanup`，不提交 Build、不執行分析、不更新或刪除任何雲端資源。

```bash
(
  set -e
  umask 077
  cd "$(cat "$HOME/malscan-v2-auto-update-source-path.txt")"
  python3 - <<'PY_INVENTORY'
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path("deployment/cloud-run").resolve()))
import auto_update as auto

def require(condition):
    if not condition:
        raise ValueError("current_registry_inventory_not_verified")

try:
    store = auto.Store("malscan-v2-poc-db-operations")
    raw, generation = store.load_json("state.json")
    state = auto.validate_state(raw)
    lease, lease_generation = store.load_json("lease.json")
    require(state["active"] is None and lease is None and lease_generation == 0)
    current = state["current"]
    saved = current["files"]["state.json"]
    with tempfile.TemporaryDirectory(prefix="malscan-registry-home-", dir=Path.home()) as value:
        temporary_home = Path(value)
        directory = temporary_home / ".malscan-v2-operations" / "maintenance" / saved["release"]
        directory.mkdir(parents=True, mode=0o700)
        for name, content in current["files"].items():
            require(name in auto.FILES)
            auto.maintenance.write_private(directory / name, content, exclusive=True)
        report = auto.inventory.Inspector(home=temporary_home).inspect()
    _, final_generation = store.load_json("state.json")
    final_lease, final_lease_generation = store.load_json("lease.json")
    require(final_generation == generation and final_lease is None and final_lease_generation == 0)
    require(report["schema_version"] == 1
            and report["scope"] == "read_only_registry_cleanup_inventory"
            and report["project"] == auto.PROJECT and report["repository_region"] == auto.REGION
            and report["remote_mutations"] is False and report["cloud_run_executed"] is False)
    images, issues = report["images"], report["readiness_issues"]
    present = {row["image"] for row in images}
    primary = {row["image"] for row in report["references"]
               if row["kind"] == "job" and row["resource"] == auto.JOB and row["region"] == auto.REGION}
    checkpoint_matches = (report["rollback_checkpoint"]["status"] == "matched"
                          and report["rollback_checkpoint"]["matching_releases"] == [saved["release"]]
                          and primary == {current["image"]})
    retained_present = {current["image"], current["rollback_image"]} <= present
    complete = (not issues and not report["protected_versions_not_listed"]
                and checkpoint_matches and retained_present and report["repository"] is not None)
    counts, packages, media = Counter(), {}, Counter()
    for row in images:
        counts[row["classification"]] += 1
        package = row["image"].split("@", 1)[0][len(auto.inventory.PREFIX):]
        label = package if package in {"full-worker", "demo-dispatcher", "engine-poc"} else "other"
        packages.setdefault(label, Counter())[row["classification"]] += 1
        media[row["reported_media_type"] or "unknown"] += 1
    metadata = report["repository"] or {}
    size = metadata.get("sizeBytes")
    require(size is None or type(size) is int and size >= 0)
    output_directory = Path(tempfile.mkdtemp(prefix="registry-readback-", dir=Path.home()))
    output = output_directory / "registry-inventory.json"
    auto.inventory.write_report(output, report, Path.home())
    print(json.dumps({
        "scope": "read_only_current_registry_inventory", "read_only": True,
        "observed_at": report["observed_at"], "inventory_read_complete": complete,
        "coordinator_generation_unchanged": True, "maintenance_lease_absent_at_reads": True,
        "current_checkpoint_matches_job_image": checkpoint_matches,
        "current_and_rollback_versions_present": retained_present,
        "repository_size_bytes_observed": size is not None, "repository_size_bytes": size,
        "version_count": len(images), "classification_counts": dict(counts),
        "package_counts": {key: dict(value) for key, value in sorted(packages.items())},
        "media_type_counts": dict(sorted(media.items())), "readiness_issue_count": len(issues),
        "private_report_file": str(output), "deletion_plan_ready": False,
        "oci_manifest_graph_verified": False, "billed_savings_verified": False,
        "remote_mutations": False, "cloud_run_executed": False,
    }, indent=2))
    raise SystemExit(0 if complete else 1)
except Exception:
    print(json.dumps({"success": False, "scope": "read_only_current_registry_inventory",
                      "error": "current_registry_inventory_not_verified",
                      "deletion_plan_ready": False, "remote_mutations": False,
                      "cloud_run_executed": False}))
    raise SystemExit(1)
PY_INVENTORY
)
```

先貼回摘要即可。完整盤點是已投影過的 metadata，保存於新建私人 HOME 目錄的 `registry-inventory.json`（0600）；暫存的完整 checkpoint／Job 設定不會輸出或放進報告。
若後續需要審查候選，另提供此私人報告給維護者，不提交公開 GitHub。

- `inventory_read_complete: true` 表示這次既有 Inspector 範圍的讀取無缺口，目前／回退版本存在且目前 checkpoint 對應 primary Job 映像。
- `false`、非零 `readiness_issue_count` 或固定錯誤表示讀取／狀態核對未完成。保留摘要；不刪除、不改 state、不手動解除 lease。
- `repository_size_bytes: null` 代表未觀察到精確容量，不能當成零；各映像顯示大小加總也不是可回收空間或帳單。

`unclassified` 只表示未被本次已檢查的 Cloud Run 引用直接保護，不等於不用或可刪除。
OCI index 子 manifest、attestation、共享 layer 與非 Cloud Run 消費者仍需額外核對；盤點本身不會核准或執行任何刪除。
本次觀察不是跨資源的原子快照；雲端更新期間或出現 state／lease 變動會安全停止，未來任何刪除仍需新的完整引用核對與具體計畫。

## 本輪完整報告已審查並取得限定清理驗收

11/14 的[摘要讀回](milestones/2026-11-14-current-registry-inventory-acceptance.json)已通過：10 個版本、5 個受引用保護、5 個未分類，精確容量與目前／回退版存在皆已確認。
後續已收到同一私人 metadata 報告，完整 digest／tags／時間／media／引用經既有正規化與候選選擇核對；3 個舊 full-worker 均為允許的 schema 2 manifest，且早於全部受保護 worker 版本。見[逐版審查摘要](milestones/2026-11-14-legacy-registry-review.json)。
engine-poc 的 2 個未分類版本為 OCI manifest，但與受保護 index 的關係尚未證明；整組 3 個版本均保留。

後續輪次如需提供盤點，將摘要 `private_report_file` 指向的 **`registry-inventory.json`** 下載，透過私人對話交給維護者審查；可用 Cloud Shell 的「下載檔案」功能選取該完整路徑。
該檔是 Inspector 已投影的 metadata，不是原始 Job 設定或 coordinator state；不要改傳其他 checkpoint、環境設定、憑證或 bundle。
原始 metadata 報告保持私有，不提交公開 GitHub；公開紀錄只保留必要彙總。

本輪依[自動更新啟用後的限定清理](guarded-registry-cleanup.md)完成，使用者提供的 guarded readback 為 `completed`、3 個候選全部刪除、無 pending、版本數 10 → 7；沒有啟動掃描。接受本批工具前後引用核對內的刪除結果，沒有新增 agent provider 查詢或另行精確 Version GET。原排程已恢復啟用，下一步為[只讀心跳確認](guarded-registry-cleanup.md#目前接續只讀確認啟用後心跳)，再核對容量／儲存 SKU；不重跑本批或 10/22 批次。
