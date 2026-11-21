# ASUSTOR NAS CLI

[![CI](https://github.com/popuchoco/asustor-nas-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/popuchoco/asustor-nas-cli/actions/workflows/ci.yml)

以 Python 撰寫的 ASUSTOR ADM NAS 安全優先命令列工具，提供唯讀診斷、磁碟拓樸、DeadBolt 勒索病毒防護檢查，以及有相容性閘門的核心模組管理。指令名稱為 `adm`，取自 ASUSTOR 作業系統名稱。

[English](README.md) · [安裝指南](install.md) · [指令規格](docs/CLI_SPEC.md) · [相容性說明](docs/COMPATIBILITY.md) · [疑難排解](docs/TROUBLESHOOTING.md) · [巡檢手冊](docs/COOKBOOK.md) · [報告範例](examples/reports/README.md) · [安全政策](SECURITY.md) · [研究來源與授權](docs/RESEARCH_AND_LICENSES.md)

## 功能

- 透過固定、唯讀的 SSH 指令查詢 ADM 系統、容量、RAID、網路和磁碟資訊。
- 計算固定 allowlist 服務程序數、讀取可用的本機 NUT UPS 狀態，並彙整 IPv4／IPv6 TCP 狀態計數；不輸出位址或連接埠，也不把觀察值當成健康判決。
- 讀取 SMART 健康狀態，不會啟動磁碟自我測試；待機磁碟會略過查詢。
- 讀取 Linux thermal-zone 溫度觀察值；不套用機型專屬健康門檻。
- 從 `/sys` 與 `/proc` 建立實體磁碟、分割區、Linux 軟體 RAID 和 `/volumeN` 掛載點的對應。
- 稽核 DeadBolt 防護基線、在有限時間與命中數內搜尋檔名及 ADM 管理頁線索、跨次比對 JSON 報告，並離線匯出結構化摘要為 Markdown。
- 檢查 NAS 是否符合 `asustor-platform-driver` 的核心版本及硬體需求；符合條件時，可在建立本機狀態備份並完成明確確認後載入或卸載驅動模組。
- 透過 stdio 提供無額外依賴、唯讀的 MCP 伺服器，包含結構化健康摘要與精簡風險訊號工具。

這是系統維運輔助工具，不會讀取檔案內容做惡意程式掃描、不會驗證備份可還原性、不會判定路由器對外暴露，也不能證明 NAS 沒有感染。

## 安裝

需要 Python 3.11 以上，以及作業系統提供的 OpenSSH 用戶端。執行期只使用 Python 標準函式庫。

```console
python -m pip install .
adm --help
```

請依照[Windows、macOS 與 Ubuntu 安裝指南](install.md)，透過 `pipx` 安裝已檢視的 `v1.9.0` 原始碼標籤。專案尚未發布至 PyPI；明確發布前無法使用 PyPI 安裝。從本機原始碼安裝與離線 wheel 說明見[發布與套件建置](docs/PUBLISHING.md)。

開發期間可從原始碼目錄執行：

```powershell
$env:PYTHONPATH = '.\src'
python -m asustor_nas_cli --help
```

## 快速開始

```powershell
$env:ASUSTOR_HOST = 'nas.example'
$env:ASUSTOR_USER = 'nas-user'
adm probe --insecure --json
adm health --json
adm disk-topology --json
```

SSH 預設使用連接埠 22，ADM HTTPS 預設使用 8001。可設定 `ASUSTOR_SSH_PORT`、`ASUSTOR_HTTPS_PORT`，或傳入 `--port`／`--https-port`。SSH 金鑰可透過 `ASUSTOR_SSH_IDENTITY_FILE` 或 `--identity-file` 指定。CLI 不保存 SSH 密碼；密碼登入需在互動終端執行。MCP 使用 OpenSSH 批次模式，需先設定可用的金鑰或 ssh-agent。

測試 NAS 使用自簽 HTTPS 憑證。`--insecure` 會略過該次連線的憑證驗證，報告會記錄未驗證狀態。日常使用請優先安裝受信任憑證，或使用 `--ca FILE.pem`。`--ca` 和 `--insecure` 不可同時使用。

## 隱私預設

CLI JSON 和 MCP 回應會以 `NAS` 作為主機標籤，並提供穩定的 `host_id` 指紋供報告比對，不輸出設定的主機位址。SSH 輸出中的 IP／MAC 位址和錯誤訊息中的 NAS 帳號會遮蔽。用戶端不接收、顯示或保存 NAS 密碼與私鑰內容。分享報告前仍應將事件檔案路徑與 DMI 機型資訊視為維運資料檢查。

## 指令

| 指令 | 用途 |
| --- | --- |
| `adm probe` | 檢查 ADM HTTPS 管理頁與憑證 |
| `adm doctor` | 檢查 HTTPS 並收集 SSH 診斷資料 |
| `adm status --summary`、`health --summary`、`storage --summary`、`raid --summary` | 加入結構化摘要並保留原始 sections |
| `adm status`、`health`、`storage`、`raid`、`network`、`disks` | 讀取 ADM 與 Linux 狀態 |
| `adm disk-topology` | 對應磁碟、分割區、md 陣列與資料卷 |
| `adm smart` | 讀取 SMART 健康狀態，不啟動磁碟自我測試 |
| `adm temperature` | 讀取可用的 thermal-zone 溫度；不套用健康門檻 |
| `adm services` | 計算固定服務程序數；不判斷服務是否應該執行 |
| `adm ups` | 讀取本機第一台 NUT UPS 的狀態與電量；多台裝置時標記為 partial，並省略名稱 |
| `adm connections` | 彙整 IPv4／IPv6 TCP 連線狀態，不顯示位址或連接埠 |
| `adm security audit` | 檢視 DeadBolt 事前防護基線 |
| `adm incident scan` | 有界限地搜尋資料卷檔名和管理頁 DeadBolt 線索 |
| `adm security compare` | 比對相容的稽核或掃描 JSON 報告 |
| `adm report compare` | 離線比對兩次健康摘要與風險訊號 |
| `adm report render` | 離線將支援的診斷、安全、事件、平台與觀察報告轉成 Markdown |
| `adm platform status` | 讀取核心、DMI 和驅動模組狀態 |
| `adm platform module --load/--unload/--reset` | 在通過驗證的 Linux 主機上管理驅動模組 |
| `adm mcp` | 以 stdio 提供唯讀 MCP 工具 |

NAS 資料查詢與比對指令支援 `--json`；可用 `--compact-json` 輸出單行 JSON（會自動啟用 `--json`）。JSON 報告使用 `schema_version: 1`，規格位於 [`schemas/`](schemas/)。退出碼見[指令規格](docs/CLI_SPEC.md)。

使用 `adm report render --input health.json` 轉換結構化報告；`--input -` 會從標準輸入讀取 JSON。指令接受 1 MB 以內、schema v1 的診斷、安全、事件、平台、拓樸、SMART、溫度、觀察及比對報告，最多輸出 2 MB Markdown，不會連線 NAS，並省略原始 SSH `sections`。檔案路徑、主機標籤、IP／MAC 位址，以及名稱含帳號或密鑰用途的欄位會遮蔽；分享前仍請檢查其他維運資訊。

使用 `adm report compare --before yesterday.json --after today.json` 離線比對健康摘要或風險訊號。前後報告必須來自相同主機且類型一致；指令會標示風險訊號和結構化欄位的變化。後次覆蓋不完整時，消失的觀察會標為「未重見」，不會當成已排除。

`--summary` 會輸出版本化的 `diagnostic-summary` JSON，並保留原始指令內容在 `sections`。`adm health --summary` 也會唯讀收集 SMART、溫度、服務程序、UPS 與 TCP 狀態觀察。服務數、UPS 值和連線計數不會新增風險訊號，也不會改變健康摘要的退出碼政策。溫度警示預設採通用、可調整的 80°C 提醒值。thermal-zone 編號不會指出感測器所屬元件，因此不代表機型專屬的溫度健康判定。加上 `--exit-on-warning` 後，偵測到 RAID／SMART／溫度問題回傳 `2`，資料不完整回傳 `1`，完整且沒有警示回傳 `0`。

排程巡檢可用 `adm health --summary --exit-on-warning --compact-json`，以單行 JSON 輸出結果並依觀察狀態回傳退出碼：有警示為 `2`、涵蓋不完整為 `1`、觀察完整且沒有警示為 `0`。排程時可分別保存標準輸出與退出碼。

`adm smart` 只對支援的區塊裝置名稱執行 `smartctl -H -n standby`，不會啟動 SMART 自我測試，也不輸出磁碟序號或屬性；待機磁碟可能回報未知。AS-202TE 唯讀實測看到兩個支援裝置，但健康狀態都未知、涵蓋範圍不完整，因此不能據此判定磁碟健康。

`adm temperature` 讀取 `/sys/class/thermal/thermal_zone*/temp` 唯讀介面，並將毫攝氏度換算為攝氏度；輸出只含通用區域編號和讀值。感測器可用性依機型和核心而異；AS-202TE 實測沒有可用的 thermal-zone 感測器。此指令本身不套用溫度門檻。

端到端範例見[日常巡檢與事件應對手冊](docs/COOKBOOK.md)。

## DeadBolt 勒索病毒防範與檢測

`adm security audit` 依 ASUSTOR 的 AS-2022-008 DeadBolt 公告檢查 ADM 版本、檢視本機 TCP 監聽連接埠，以及搜尋 ADM 管理頁的有限字串線索。該公告列出 ADM 3.5 與 4.0 為受影響分支；ADM 4.1 以上或 5.x 顯示通過，只代表該公告沒有列為受影響，不代表 NAS 已完整修補或使用最新韌體。請另查[最新 ASUSTOR 安全公告](https://www.asustor.com/zh-tw/security/security_advisory)與[ADM 發行資訊](https://www.asustor.com/zh-tw/service/release_notes)。備份狀態、密碼強度、EZ-Connect 和路由器外部暴露情況無法自動驗證，會保持未知；人工確認旗標只代表操作者聲明。

`adm incident scan` 只搜尋 `/volumeN` 下檔名以 `.deadbolt` 結尾的檔案及管理頁文字，不會讀取檔案內容、不會隔離或刪除檔案，也不會停止服務。可用 `--max-seconds` 和 `--max-hits` 設定掃描上限。程式會從 `PATH` 尋找 `find`、`timeout` 和 `awk`，並先確認 `find -xdev` 可用；缺少安全限時掃描所需功能時，報告會將檔案掃描標示為不可用。掃描不完整時會明確標示；未發現線索不代表 NAS 沒有感染。

```powershell
adm security audit --host nas.example --user nas-user --insecure --json > audit-before.json
adm incident scan --host nas.example --user nas-user --insecure --json > scan-before.json
# 之後另存報告，再比對相同類型的報告：
adm security compare --before scan-before.json --after scan-after.json
```

依據包括 ASUSTOR [DeadBolt 公告](https://www.asustor.com/en/security/security_advisory_detail?id=9)、[ADM 發行資訊](https://www.asustor.com/zh-tw/service/release_notes)與[防護指引](https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6)。目前規則集為 `asustor-deadbolt-v1`。

## 核心模組管理

[asustor-platform-driver](https://github.com/mafredri/asustor-platform-driver) 可透過 GPIO 控制部分機種的 LED 與按鈕；選用的 IT87 模組也會提供風扇 PWM。錯誤的 GPIO 對應可能使系統不穩或損壞硬體。CLI 會在允許任何模組變更前檢查核心版本及 DMI 廠牌／產品名稱。該驅動專案將 Linux 6.1 以上列為支援下限，相容性清單不包含 AS-202TE。本專案的 AS-202TE 測試機使用 Linux 3.4，因此只可查看狀態，CLI 會拒絕變更模組。

模組變更須同時符合以下條件：

1. NAS 執行 Linux 6.1 以上。
2. DMI 廠牌／產品名稱符合[相容性文件](docs/COMPATIBILITY.md)中的白名單。
3. 載入 `asustor_it87` 時，衝突的 `it87` 模組尚未載入。
4. 操作者提供 `--confirm-risk` 和本機備份路徑。
5. 先以 `modprobe -n` 無變更地解析固定模組計畫。
6. 一般操作流程還須在提示中輸入完整動作名稱及遮蔽後的 NAS 指紋。

載入與復原範例：

```console
adm platform status --host NAS-IP --user nas-user
adm platform module --load --host NAS-IP --user nas-user \
  --backup ./platform-before.json --confirm-risk
adm platform module --reset --host NAS-IP --user nas-user \
  --backup ./platform-before.json --confirm-risk
```

載入或卸載前，CLI 會先將三個管理模組的載入狀態寫成本機 JSON 檔；若檔案已存在，不會覆寫。`--reset` 會在 NAS 主機、核心版本與 DMI 身分都相同時，恢復該檔記錄的載入狀態。重設前也會把當下狀態另存為 `<backup>.before-reset.json`（可用 `--rollback-backup` 指定位置），讓之後仍可回復；若該檔已存在，重設會停止而不覆寫。備份不包含模組二進位檔、NAS 資料、韌體設定、LED 亮度或風扇 PWM；reset 是盡力恢復模組狀態，不是完整系統回復。CLI 不會安裝／編譯核心模組，也不會寫入 LED／風扇 sysfs。

進階自動化可加 `--force` 略過互動式第二次確認，但仍須提供 `--confirm-risk`、有效備份（`--reset` 則需既有且符合身分的備份），並通過全部相容性檢查。`--force` 不會使用核心的強制卸載選項。

## 唯讀 MCP 伺服器

在 MCP 用戶端設定 `adm mcp`，並提供環境變數：

```json
{
  "mcpServers": {
    "asustor": {
      "command": "adm",
      "args": ["mcp"],
      "env": {
        "ASUSTOR_HOST": "nas.example",
        "ASUSTOR_USER": "nas-user",
        "ASUSTOR_SSH_IDENTITY_FILE": "/path/to/id_ed25519",
        "ASUSTOR_HTTPS_PORT": "8001"
      }
    }
  }
}
```

伺服器需要 SSH 金鑰／agent 驗證，只執行固定 SSH 指令並提供唯讀工具。`adm_health_summary` 回傳結構化健康欄位和原始 sections；`adm_risk_signals` 只回傳涵蓋狀態，以及 RAID、SMART、溫度的重點訊號，不含原始 sections。溫度門檻是可調整的通用提醒值。`adm_security_compare` 可在不連線 NAS 的情況下比對兩份報告。`adm_platform_status` 只讀取支援狀態；MCP 不提供載入、卸載或重設模組功能。更多細節見[指令規格](docs/CLI_SPEC.md#mcp-interface)及[報告範例](examples/reports/README.md)。

## 專案結構與貢獻

`adm` 指令將診斷、安全、報告及受相容性閘門保護的核心模組管理分成不同模組。詳見[架構](docs/ARCHITECTURE.md)、[貢獻指南](CONTRIBUTING.md)及[發布檢查清單](docs/RELEASE_CHECKLIST.md)。

另見[架構](docs/ARCHITECTURE.md)、[疑難排解](docs/TROUBLESHOOTING.md)、[巡檢手冊](docs/COOKBOOK.md)、[發布檢查清單](docs/RELEASE_CHECKLIST.md)、[安全檢視](docs/SECURITY_REVIEW.md)、[貢獻指南](CONTRIBUTING.md)、[發布與安裝](docs/PUBLISHING.md)、[更新紀錄](CHANGELOG.md)和[安全政策](SECURITY.md)。

## 授權、研究來源與商標

本專案原始程式碼與文件採 MIT 授權，詳見 [LICENSE](LICENSE)。實際使用的軟體與授權檢視記錄於[研究來源與授權](docs/RESEARCH_AND_LICENSES.md)。

本專案為獨立社群專案，與 ASUSTOR Inc. 無隸屬、背書或贊助關係。ASUSTOR、ADM 及 ASUSTOR 產品與機型名稱均為各自權利人的商標。
