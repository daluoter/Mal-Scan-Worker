# 提交與公開內容的防護

更新日期：2026-11-12（Asia/Taipei）。本頁適用於開發 checkout；已核准的雲端更新來源與私人 bundle 不需因此重建或替換。
公開資訊範圍與先前通知的判讀見[安全核對紀錄](security-notes.md)。

## 已交付的檢查

| 層次 | 檢查範圍 | 作用與限制 |
| --- | --- | --- |
| Git 忽略規則 | 私人 plan、基準、演練、通知、帳單匯出等產物 | 減少誤加入；既有追蹤檔案與 `git add -f` 可以略過忽略規則 |
| 私人檔案守門 | 提交前檢查暫存變更；CI 檢查完整 Git index | 阻擋已知私人產物、憑證型檔名、環境設定與間接連結，強制加入也會檢查；不是任意檔名的內容掃描 |
| Gitleaks | 本機 hook 檢查暫存變更；CI 檢查完整追蹤快照與本次提交範圍 | 固定掃描器與內建規則，不使用 repo 的額外忽略檔或 inline allow；未命中仍不保證所有秘密格式都可辨識 |
| GitHub Actions | 每次 push／PR，包含文件改動；另可手動執行 | 只有 repository 讀取權限，不使用雲端憑證，不上傳原始 finding／報告 artifact；CI 在推送後執行，不能撤回已經公開的秘密 |

守門程式只輸出規則代號與計數；秘密掃描只輸出成功／失敗與必要計數，不列印原始內容、私人檔名或 provider 回應。
掃描器下載固定版本並核對 archive SHA-256；新 workflow 的 checkout／Python actions 使用固定 commit。
本機官方 Gitleaks hook 固定來源 commit，使用隔離的 Go toolchain 建置；第一次執行需網路下載工具。
公開範例檔名可通過檔名檢查，但其內容仍要經 Gitleaks，不能用 `.example` 放入真實憑證。

## 開發者安裝本機 hook

本工作區已安裝 hook；新 clone 或 Cloud Shell 的其他 checkout 不會自動安裝。
以下在**已更新至本批版本的開發目錄**執行；不要為安裝 hook 改寫已凍結的維護 plan／來源。

```bash
python3 -m venv "$HOME/.venvs/mal-scan-publication"
"$HOME/.venvs/mal-scan-publication/bin/python" -m pip install pre-commit==4.2.0
"$HOME/.venvs/mal-scan-publication/bin/pre-commit" install
python3 scripts/check_publication.py --tracked
```

提交前可手動執行兩項新檢查：

```bash
"$HOME/.venvs/mal-scan-publication/bin/pre-commit" run publication-private-artifacts
"$HOME/.venvs/mal-scan-publication/bin/pre-commit" run gitleaks
```

這兩個 hook 都檢查暫存區；傳入 `--all-files` 不會把 staged-only Gitleaks 改成全倉庫掃描。
完整追蹤內容與本次提交歷史由 CI 額外檢查；秘密先加進某個 commit、後來才刪掉，仍會在本次歷史範圍被檢查。
遇到檢查失敗時，在私人終端核對暫存差異與檔名；不要把完整秘密、原始 finding 或私人設定貼到公開 issue／CI 日誌。

hook 是本機設定，能被略過，因此團隊每個開發 checkout 都需安裝，並由 GitHub 端設定補上限制。
偵測工具、設定錯誤或 index 狀態讀取失敗時，本批檢查會失敗，不把未完成檢查當作通過。

## CI 的歷史範圍

- 一般 push：事件的 before 至 after，加上完整追蹤快照。
- PR：base 至 head，另掃描 checkout 的合併快照。
- 新分支：以目前遠端 default branch 為比較基準；第一次 default-branch push 沒有 before 時，掃描其完整祖先歷史。
- 手動執行：目前 commit 與完整追蹤快照，不宣稱重新審查整個歷史。

必要的提交邊界不存在時會中止。沒有新增掃描忽略清單；舊歷史的替換用範例若被完整歷史掃描命中，仍需逐筆確認，不能為讓工作變綠而停用偵測。

## 仍需 repository owner 確認的設定

本次曾嘗試啟用 GitHub 的 Secret scanning／Push Protection，API 回覆 `Resource not accessible by integration`。
目前整合權限無法修改，也沒有取得其有效狀態的讀回；這不代表功能一定停用，不能記為已啟用。

owner 可到 repository **Settings → Code security／Code security and analysis** 檢查 Secret scanning 與 Push protection。
另建議以 main 的 branch rule／ruleset 要求 PR 審查及 `publication-security` 檢查通過，並審查安全 workflow、hook 與規則變更。
本批沒有修改 branch rules，也未確認現行是否已強制執行；一般 Actions 失敗不等於拒絕第一次推送。
Push Protection 的支援格式、略過機制與權限也各有範圍，不取代本機檢查與差異審閱。

若真實憑證已公開，先撤銷／輪替並檢查使用紀錄；刪除檔案、讓 CI 失敗或改寫歷史，都不能讓舊憑證自動失效。
