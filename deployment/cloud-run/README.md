# Serverless v2 靜態 demo 部署

本機完整映像驗收可在 Linux localhost Docker／MinIO 執行：先建置 `worker/Dockerfile` 的
`cloud-job` target 為 `malscan-v2-full-cloud:verified`，設定 worker 的本機 MinIO 環境，再以
worker Python 執行 `deployment/cloud-run/verify-local-image.py --output-dir .local-cloud-smoke`。
它使用三個全新容器驗證巢狀不同密碼、S3 checkpoint、signed status／report、秘密控制刪除，
只建立並清除自身隨機測試 buckets。結果可傳給 Cloudflare opt-in fixture test，見該目錄 README。

新版完整映像共用 self-host 的 Python pipeline、子檔提取、評分及 v3 報告。Cloudflare Worker
負責上傳、授權、限額、派送與驗證報告；SQLite Durable Objects 儲存控制狀態，兩個私有 R2
buckets 存來源與結果。先前的 `engine-poc` 映像只驗證引擎，不能用在這個 Job。

**截至 2026-10-15（Asia/Taipei），完整映像、Runner Job、免私鑰 Cloud Run dispatcher、
Cloudflare 控制 Worker 與 Pages 正式入口已部署；良性 `hello.txt` 已從正式網頁完成分析及報告下載。
React Router 修補、精確正式 origin 與受限上傳入口已發布。這是首份良性檔驗收，不代表下面所有
進階案例均完成；實際帳單、Cloudflare CPU 與 live CAPE 仍待確認。**

目前正式網站為 `https://malscan-v2-demo.pages.dev`，API 為
`https://malscan-v2-demo-control.daluoter.workers.dev`。首次已驗收 execution
`malscan-v2-static-demo-hrcmh` 從建立到完成約 238.075 秒，report 記錄分析 29.331 秒；
平台啟動等待是目前待優化項目。完整證據與限制見[里程碑](../../docs/milestones/2026-10-15-cloud-demo.md)。

以下是**初次建立資源的操作指南**。已成功部署的專案先查既有狀態，再只更新有變更的元件，
不要重建 Secret、服務帳戶或 Job。repository 的 `wrangler.jsonc` 仍預設關閉上傳並使用 placeholder
origin，作為安全的部署範本；重新 deploy 前必須檢閱，不能將範本直接覆蓋到正式環境。
GitHub push 本身不代表 GCP／Cloudflare 已自動更新。
以下在已登入該專案的 Cloud Shell、這份新版工作樹的 repository root 執行。先同步原始碼至 Shell。
已提交的 Cloud Build／Cloud Run execution 不依賴 Shell 持續連線；重連先查既有 ID，不要重送。

## 1. 準備新版資源

保留原 PoC：Project `malscan-v2-poc`、region `us-central1`、Artifact Registry repository
`malscan-v2-poc`、來源 bucket `malscan-v2-upload-poc`、來源唯讀 Secret `malscan-v2-r2-read:1`。
建立另一個**私有** R2 bucket `malscan-v2-analysis-results`，及只限它的 Object Read & Write 憑證。
writer 不應有來源 bucket 寫入權。兩個專用 demo buckets 設一天 lifecycle，作為清理失效的後備；
不要混入永久資料。控制面也依 root-specific prefix 清理並保留 20 分鐘 tombstone 處理晚到寫入。

```bash
gcloud config set project malscan-v2-poc
gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com cloudbuild.googleapis.com
```

## 2. 發布完整映像

Cloud Build 避開之前 Shell Docker daemon 推送的網路問題；它是另一項可能計費的服務。
build account 需要既有 registry 寫入與 logging 權限。若受 IAM 限制，依實際錯誤給該帳戶
需要的權限，不要授予專案 Owner。

若提交後在讀取來源時出現 `storage.objects.get` 403，依錯誤中列出的建置服務帳戶，
只對來源 bucket 補讀取權。此專案曾使用 Compute default service account：

```bash
gcloud storage buckets add-iam-policy-binding gs://malscan-v2-poc_cloudbuild \
  --project=malscan-v2-poc \
  --member=serviceAccount:371636043543-compute@developer.gserviceaccount.com \
  --role=roles/storage.objectViewer --condition=None
```

補完後從已解壓的專案目錄重新提交。這項 binding 不包含 registry 寫入或 logging 權限；
若後續另有 IAM 錯誤，依實際缺少的動作與資源處理。

若 Docker step 已 `SUCCESS`、整體卻 `FAILURE`，且 warnings 指出無法寫入 Cloud Logging，
先為錯誤列出的建置帳戶補 `roles/logging.logWriter`（專案級）。這是已確認的日誌問題，
不代表它就是整體失敗的原因。`CLOUD_LOGGING_ONLY` 沒有 GCS log 備份，事後補權限不會
補回漏寫的歷史日誌。依該次 build 的實際 tag 查 Artifact Registry，確認是否已有映像，
再決定下一次建置／推送的修正；不能僅依 Docker step 成功就繼續部署。

此專案的實際 build account 為 Compute default SA，與專案 IAM 中既有的 legacy
Cloud Build service account 是不同身分。若需補齊此 build account 的映像推送權，
將 Writer 限定在目標 repository：

```bash
gcloud artifacts repositories add-iam-policy-binding malscan-v2-poc \
  --project=malscan-v2-poc --location=us-central1 \
  --member=serviceAccount:371636043543-compute@developer.gserviceaccount.com \
  --role=roles/artifactregistry.writer --condition=None
```

來源讀取、日誌寫入與 repository 推送是三項獨立權限。補齊後以新 RELEASE 重試；
以新 build 的最終狀態與 registry digest 判斷成果。

```bash
RELEASE="v2-$(date -u +%Y%m%dT%H%M%SZ)"
gcloud builds submit . --region=us-central1 \
  --config=deployment/cloud-run/cloudbuild.yaml \
  --substitutions="_RELEASE=$RELEASE" --async
```

記下 build ID；斷線重連查該 ID。等狀態為 SUCCESS 後，從 build 結果重新讀映像名稱，
不依賴已中斷 Shell 裡的 RELEASE 變數：

```bash
gcloud builds describe BUILD_ID --region=us-central1 --format='value(status)'
gcloud builds log BUILD_ID --region=us-central1
IMAGE_TAG=$(gcloud builds describe BUILD_ID --region=us-central1 \
  --format='value(results.images[0].name)')
gcloud artifacts docker images describe \
  "$IMAGE_TAG" \
  --format='value(image_summary.fully_qualified_digest)'
```

後續使用 `full-worker@sha256:…`，不要用可變 tag。在 daily 資料庫年齡達五天前安排以新 RELEASE
重建，預留下載／驗證失敗的修復時間，並強制 signatures layer 更新。七天是從 CVD 產生時間起算，
不是映像建置時間；固定每七天重建可能留下過期空窗。freshclam 與 sigtool 驗證 CVD，建置與執行時拒絕超過七天的 daily CVD；過期會
呈現 ClamAV coverage failed。更新排程須由部署者設定，這裡沒有聲稱已建立自動更新。

## 3. Runner 身分、固定 Secret versions

```bash
gcloud iam service-accounts create malscan-v2-static-demo \
  --display-name='MalScan static demo runner'
gcloud iam service-accounts add-iam-policy-binding \
  malscan-v2-static-demo@malscan-v2-poc.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role=roles/iam.serviceAccountUser --condition=None
```

在 `deployment/cloudflare/wrangler.jsonc` 填兩個 buckets、project、frontend 精確 HTTPS origin；
先保持 `PUBLIC_UPLOADS=false`，使用不同於舊 PoC 的 Worker 名稱。安裝鎖定 CLI，先查既有登入：

```bash
(cd deployment/cloudflare && npm ci && npx --no-install wrangler whoami)
```

Cloud Shell 若尚未登入，使用鎖定 Wrangler 版本提供的裝置授權，依終端列出的網址及
一次性代碼在自己的瀏覽器完成授權，不需要遠端 localhost callback 或另建 API token：

```bash
(cd deployment/cloudflare && npx --no-install wrangler login --device --no-browser)
```

確認為兩個 buckets 所在帳號，再部署入口關閉的新版 Worker：

```bash
export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
(cd deployment/cloudflare && npx --no-install wrangler deploy)
python3 deployment/cloud-run/store-demo-secrets.py
```

先部署 intake 關閉的控制面，再設定 secrets。helper 隱藏輸入結果 bucket 的兩個值，產生 HMAC key，將它與 writer 存到 Secret Manager，
再把同一 HMAC key 設至 Worker，不輸出值。原來源唯讀 secret 不會修改。GCP 兩個 secrets 已
建立但 Worker 設定中斷時，加 `--resume` 讀回原 v1 key 繼續；若只有 HMAC 成功建立，resume
會再次隱藏輸入缺少的結果 bucket 憑證。不要任意旋轉一邊而另一邊留舊值。憑證與 key 不要貼進聊天。

```bash
for SECRET in malscan-v2-r2-read malscan-v2-r2-results malscan-v2-control-hmac; do
  gcloud secrets add-iam-policy-binding "$SECRET" \
    --member=serviceAccount:malscan-v2-static-demo@malscan-v2-poc.iam.gserviceaccount.com \
    --role=roles/secretmanager.secretAccessor --condition=None
done
python3 deployment/cloud-run/prepare-job.py --image-digest='完整的full-worker@sha256:…'
gcloud run jobs create malscan-v2-static-demo --flags-file=cloud-static-job.flags.json
```

flags helper 只寫可檢閱設定，不呼叫雲端。Job：1 task／parallelism 1／2 vCPU／4 GiB／900 秒／
0 retries。內部上限：20 個提取成員、100,000,000 expanded bytes、深度 3、分析 840 秒；上傳
最多 20,000,000 bytes。密碼續跑保留累積 files／bytes 與 root retention deadline。
三個 Secret 各自掛在 `/secrets/source/credentials.json`、`/secrets/results/credentials.json`、
`/secrets/control/key`，並同步指定 `MALSCAN_*_SECRET_FILE`。Cloud Run 不接受不同 Secrets
共用同一個掛載目錄；舊 bundle 的 flags 需要先修正這六個路徑，不必重建映像或重建 Secrets。
per-execution refs 由 Worker 提供，**不要直接無參數 execute**。已存在時先 describe，更新用
`gcloud run jobs update` 同一 flags；secret 輪替後明確改 version，避免 `latest`。

## 4. 無 Google 私鑰的派送服務

此專案已實際遇到 `constraints/iam.disableServiceAccountKeyCreation`。
保留這項政策，不重試建立金鑰，也不要再執行 `store-invoker-secret.py` 或設定
`GCP_INVOKER_JSON`。本版使用小型 Cloud Run HTTPS dispatcher；它從 metadata server
取得自身服務身分的短期 OAuth token，再呼叫固定 Job 的 `:run`。Worker 的使用者登入
或版本 metadata 不能當作 Google Workload Identity Federation 的平台憑證。

另建 invoker，只有該 Job 的 run／runWithOverrides 權限：

```bash
gcloud iam service-accounts create malscan-v2-demo-invoker \
  --display-name='MalScan demo control dispatcher'
gcloud iam roles create malscanDemoDispatch --project=malscan-v2-poc \
  --title='MalScan demo dispatch' --stage=GA \
  --permissions=run.jobs.run,run.jobs.runWithOverrides
gcloud run jobs add-iam-policy-binding malscan-v2-static-demo --region=us-central1 \
  --project=malscan-v2-poc \
  --member=serviceAccount:malscan-v2-demo-invoker@malscan-v2-poc.iam.gserviceaccount.com \
  --role=projects/malscan-v2-poc/roles/malscanDemoDispatch
```

`gcloud run jobs add-iam-policy-binding` 不接受 `--condition=None`；不要從 Secret 或
service-account 的 IAM 指令套用這個參數。若帳戶、角色已建立而此步失敗，只重跑 Job binding。

以上 invoker 帳戶、custom role 與 Job binding 若已成功，不要重新建立。invoker 不需要
對 Runner SA 的 `actAs`；它不能改 Job 的 service account、映像或 CPU。部署這個新
Service 的操作者需要對 invoker 的 SA-level `actAs`，dispatcher 只需讀取既有 HMAC
Secret version 1，不授予它兩組 R2 credentials：

```bash
gcloud iam service-accounts add-iam-policy-binding \
  malscan-v2-demo-invoker@malscan-v2-poc.iam.gserviceaccount.com \
  --project=malscan-v2-poc \
  --member="user:$(gcloud config get-value account)" \
  --role=roles/iam.serviceAccountUser --condition=None
gcloud secrets add-iam-policy-binding malscan-v2-control-hmac \
  --project=malscan-v2-poc \
  --member=serviceAccount:malscan-v2-demo-invoker@malscan-v2-poc.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor --condition=None
```

使用目前 repository 的 keyless dispatcher 原始碼；先前下載的 source archive 不會自行更新。
既有完整掃描映像與 Runner Job 可沿用，僅 dispatcher 修改時不需重建完整掃描映像。
以下只提交小型 dispatcher 映像；從 repository root 執行一次，保存回傳 Build ID：
建置來源限定 `deployment/dispatcher`，使用該目錄自己的 `.gcloudignore`；不要提交整個
repository，root ignore 規則會排除 deployment，且此服務只需要自身建置檔案。

```bash
test -f deployment/dispatcher/cloudbuild.yaml
V2_DISPATCH_RELEASE="dispatch-$(date -u +%Y%m%dT%H%M%SZ)"
gcloud builds submit deployment/dispatcher \
  --project=malscan-v2-poc --region=us-central1 \
  --config=deployment/dispatcher/cloudbuild.yaml \
  --substitutions="_RELEASE=$V2_DISPATCH_RELEASE" --async
```

等待該次 Build 狀態為 `SUCCESS`，從 `results.images[0]` 取得
`us-central1-docker.pkg.dev/malscan-v2-poc/malscan-v2-poc/demo-dispatcher@sha256:…`。
不要使用完整掃描映像或可變 tag 部署這個 Service。建置仍為 `QUEUED`／`WORKING` 時只查
既有 ID，不要重新 submit。四個既有 APIs（Run、Artifact Registry、Secret Manager、
Cloud Build）即可，這個方案不需 IAM Credentials API、GCS ledger 或 Firestore。

查既有建置並取得已發布 digest（將 `BUILD_ID` 換成剛才回傳的 ID）：

```bash
V2_DISPATCH_BUILD_ID='BUILD_ID'
gcloud builds describe "$V2_DISPATCH_BUILD_ID" \
  --project=malscan-v2-poc --region=us-central1 \
  --format='yaml(id,status,statusDetail,failureInfo,results.images)'
```

僅在 `SUCCESS` 後繼續：

```bash
V2_DISPATCH_IMAGE_TAG=$(gcloud builds describe "$V2_DISPATCH_BUILD_ID" \
  --project=malscan-v2-poc --region=us-central1 \
  --format='value(results.images[0].name)')
V2_DISPATCH_IMAGE=$(gcloud artifacts docker images describe "$V2_DISPATCH_IMAGE_TAG" \
  --project=malscan-v2-poc --format='value(image_summary.fully_qualified_digest)')
python3 deployment/cloud-run/prepare-dispatcher-service.py \
  --image-digest "$V2_DISPATCH_IMAGE"
cat keyless-dispatcher-service.flags.json
```

helper 只產生可檢閱的新設定檔、不呼叫雲端，已存在時拒絕覆寫。從 Cloud Shell 重連後
先回 `cd "$(cat "$HOME/malscan-v2-source-path.txt")"`，並重新填同一個 Build ID。

Service 名稱固定 `malscan-v2-dispatcher`，1 vCPU／256 MiB／min instances 0／max instances 1／
concurrency 1／request timeout 60 秒／request-based CPU throttling。服務身分使用上述 invoker；
掛載 `malscan-v2-control-hmac:1` 至 `/secrets/control/key`，以
`CONTROL_HMAC_SECRET_FILE` 指定該檔案；固定 `GCP_PROJECT=malscan-v2-poc`、
`GCP_REGION=us-central1`、`GCP_JOB=malscan-v2-static-demo`、
`CONTROL_ORIGIN=https://malscan-v2-demo-control.daluoter.workers.dev`。

檢閱 flags 後才部署及讀回設定：

```bash
gcloud run deploy malscan-v2-dispatcher \
  --flags-file=keyless-dispatcher-service.flags.json
gcloud run services describe malscan-v2-dispatcher \
  --project=malscan-v2-poc --region=us-central1 \
  --format='yaml(metadata.name,status.url,status.conditions,spec.template)'
```

部署完成後，讀 Service 的 `status.url`，寫入 Worker 的 `GCP_DISPATCH_URL`。
此變數只放 HTTPS origin，**不要加 `/dispatch`**；Worker 會自行加路徑。
保留 `PUBLIC_UPLOADS=false`，重新 deploy Worker，且不要直接執行 Runner Job。

```bash
V2_DISPATCH_URL=$(gcloud run services describe malscan-v2-dispatcher \
  --project=malscan-v2-poc --region=us-central1 --format='value(status.url)')
python3 deployment/cloud-run/configure-dispatcher-url.py \
  --dispatcher-url "$V2_DISPATCH_URL"
export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
(cd deployment/cloudflare && npx --no-install wrangler deploy)
```

URL helper 保留既有 bindings、bucket 名稱、CORS origin 與其他 vars，驗證固定 Job 後僅設定
`GCP_DISPATCH_URL` 並強制 `PUBLIC_UPLOADS=false`。上述步驟不建立分析 execution；下一階段
才配置前端與受限的真實上傳驗收。

已部署的 Service 僅需更新程式時，成功建置並讀回上述 immutable digest 後使用：

```bash
gcloud run services update malscan-v2-dispatcher \
  --project=malscan-v2-poc --region=us-central1 \
  --image="$V2_DISPATCH_IMAGE"
```

這會沿用既有環境、Secret 掛載與身分；不用重新執行 exclusive flags helper 或 URL helper。
後者會重新關閉 intake，不應在單純更新映像時重跑。更新後檢查 Ready revision 與 `/health`。
`GET /health` 正常只證明 dispatcher 存活，正式網頁取得報告才證明分析流程可用。

Python callback 必須保留 `User-Agent: MalScanWorker-dispatcher/1.0`。此環境的 Cloudflare
Browser Integrity 曾對預設 `Python-urllib` 回傳純文字 403／1010，尚未進入 Worker auth 或 CORS。
明確識別的應用程式 UA 已修正 callback；不要因此停用 Cloudflare 保護或放寬 CORS。

公開 HTTPS Service 以應用層 HMAC 驗證。部署使用 `--allow-unauthenticated`；若組織政策
拒絕公開服務，停止並保留錯誤，不更改組織政策。HMAC 在派送與 callback 使用不同 signing
domain，包含短效時間窗口與固定 Job／refs；dispatcher 在呼叫 Google 前向原 Durable Object
原子領取一次性 dispatch claim。重播、不同 body、過期或跨 root 請求不能再次啟動 Job。
若 claim 成功後中斷或 Google 回覆不確定，仍呈現 uncertain，不能盲目重跑。

此改動不代表免費保證：無效 HTTP 流量也可能啟動公開 dispatcher 並計費。
最大 instance 數只限制服務規模，不取代既有月額度、HMAC 驗證或一次性 claim。

## 5. 前端、最後啟用與驗收

```bash
cd frontend
npm ci
VITE_BASE_PATH=/ \
VITE_API_DEPLOYMENT=cloud-demo \
VITE_API_BASE_URL=https://malscan-v2-demo-control.daluoter.workers.dev \
npm run build
export CLOUDFLARE_ACCOUNT_ID=4caa88de736dafcb865ded345a359776
../deployment/cloudflare/node_modules/.bin/wrangler pages project create \
  malscan-v2-demo --production-branch=main
../deployment/cloudflare/node_modules/.bin/wrangler pages deploy dist \
  --project-name=malscan-v2-demo --branch=main --commit-dirty=true
```

Pages 指令從 `frontend` 執行，使用先前安裝及登入的固定版 Wrangler，避開控制 Worker 的
專用設定檔。上述 project create 只執行一次；已建立時先核對既有專案再決定是否部署。
目前產物沒有頂層 `404.html`，Pages 自動提供 SPA fallback。取得正式 production Pages
origin 後，將它精確填入 Worker `ALLOWED_ORIGIN`，不要使用單次 deployment 的預覽 origin。
全部設定妥當才將 `PUBLIC_UPLOADS` 改為 `true` 並重發 Worker。預設每月 40 次執行硬上限，
每日票證 10 次／執行 20 次；每 root 密碼重試 3 次；保留 24 小時。包括密碼重試與不確定派送
都耗用執行額度。quota 耗盡應明確拒絕。

第一份良性檔已驗收；其餘雲端案例仍待執行。後續至少保留這些真實 execution ID／signed status／reports：

1. 20 MB → Cloud Run 完整 pipeline，SHA256／版本／stage coverage 一致。
2. 巢狀加密 ZIP，內外不同密碼；等待時 partial report、錯誤後恢復、額度不重扣。
3. 良性檔、EICAR 無害測試字串、損壞檔與超限；未完成不應顯示全面成功。
4. ticket 重播／跨 root／錯誤或過期 capability 拒絕；logs、overrides、report、checkpoint 無密碼。
5. Shell／browser 中斷後追蹤原工作，不確定派送不盲目重啟；到期清理與晚到寫入。
6. 實際 Cloudflare CPU、Cloud Run startup／run、共用免費用量與 Billing。

月額度不保證零費用：Jobs 有最低計費時間；冷啟動、registry、build、secrets、logs、storage
各有條件，同帳單帳戶的其他工作也共用免費用量。低用量 cloud demo 固定 dynamic disabled；
完整可調限額及動態選項以 self-host 為主。見[支援矩陣](../../docs/analysis-support.md)。
