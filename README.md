# ASUSTOR NAS CLI

以 Python 建立、命令名稱為 `adm` 的唯讀診斷與勒索病毒檢查工具。使用 OpenSSH 讀取 ADM 主機資訊，並以 HTTPS 檢查 ADM 管理頁。CLI 結構參照 [Synology CLI](https://github.com/akari-sora/synology-nas-cli) 與 [QNAP CLI](https://github.com/popuchoco/qnap-nas-cli)。

在管理電腦安裝 `adm` 指令，再透過 SSH 執行 NAS 上已確認可用的 Linux／ADM 查詢指令。

## 安裝

需要 Python 3.10 或更新版本，以及作業系統提供的 OpenSSH 用戶端。程式執行時只用 Python 標準函式庫。

在專案目錄安裝後即可使用 `adm` 指令。

```powershell
python -m pip install .
adm --help
```

開發時也可從原始碼目錄執行。

```powershell
$env:PYTHONPATH = '.\src'
python -m asustor_nas_cli --help
```

## 指令

```text
adm probe    檢查 ADM HTTPS 管理頁和 TLS 憑證
adm doctor   檢查 HTTPS，再透過 SSH 讀取 NAS 狀態
adm status   查詢主機名稱、核心、CPU、記憶體和運作時間
adm health   彙整系統、容量、RAID、網路和磁碟觀察資料
adm storage  查詢已掛載檔案系統容量
adm raid     查詢 Linux 軟體 RAID 狀態
adm network  查詢網路介面和 IP 位址
adm disks    列出 smartctl 偵測到的磁碟
adm security audit    稽核 DeadBolt 事前防護基線
adm incident scan     掃描 DeadBolt 檔名與 ADM 登入頁線索
adm security compare  比對兩份已儲存的 JSON 報告
```

資料指令都支援 `--json`。SSH 使用固定的唯讀命令清單，密碼由 OpenSSH 在互動終端提示，程式不保存密碼。

## 連線到 AS-202TE

可用命令列參數或環境變數指定 NAS 和 SSH 帳號。

```powershell
$env:ASUSTOR_HOST = 'nas.example'
$env:ASUSTOR_USER = 'nas-user'
adm probe --insecure --json
adm doctor --insecure --json
adm storage --json
adm raid
```

AS-202TE 測試機的 HTTPS 憑證無法通過一般驗證。`--insecure` 只略過該次 HTTPS 憑證驗證，輸出會標示 `tls_verified: false`。安裝有效憑證後可省略此參數，也可用 `--ca FILE.pem` 指定 CA 憑證。

SSH 預設使用 TCP 22。需要其他連接埠時使用 `--port`。HTTPS 預設使用 TCP 8001，可使用 `--https-port` 修改。SSH 密碼登入需要在互動終端執行，或改用本機 OpenSSH 金鑰。

## 勒索病毒事前稽核與 IOC 掃描

`security audit` 將 NAS 可直接觀察的項目與需要操作者確認的項目分開。它會比對 ASUSTOR DeadBolt 公告中的 ADM 修補基線、檢查 ADM 登入頁有限的 DeadBolt 字串線索、讀取本機 TCP 監聽連接埠，並記錄目前使用的 SSH 連線。備份、密碼強度、EZ-Connect 與路由器對外設定無法由這些唯讀 SSH 查詢證實，預設會標示為 `unknown`。

```powershell
adm security audit --host nas.example --user nas-user --insecure --json
```

操作者可用旗標註記人工確認結果。這些旗標只記錄操作者聲明，不代表 CLI 已從 NAS 驗證設定：

```powershell
adm security audit --host nas.example --user nas-user --insecure `
  --backup-verified --strong-password-confirmed `
  --ezconnect-disabled --remote-access-reviewed
```

`incident scan` 只搜尋所有 `/volumeN` 掛載點中，檔名以 `.deadbolt` 結尾的檔案，並檢查 ADM HTTPS 登入頁的有限線索。預設遠端搜尋上限為 60 秒與 100 筆命中，可用 `--max-seconds` 和 `--max-hits` 調整。它不讀取檔案內容、不修改或刪除檔案，也不會自動關機或隔離 NAS。

```powershell
adm incident scan --host nas.example --user nas-user --insecure --json > scan-before.json
# 稍後再次掃描並另存為 scan-after.json
adm security compare --before scan-before.json --after scan-after.json
```

也可用相同的 `security compare` 比對兩份 `security audit --json` 報告。比對要求報告來自相同 NAS、規則版本與報告類型；「不再觀察到」不代表威脅已清除。掃描若超時、達到命中上限、遇到存取錯誤或無法檢查登入頁，會標示部分或未知覆蓋範圍。沒有觀察到 IOC 不代表沒有感染；此工具不是一般防毒或完整鑑識工具。

版本比對使用 ASUSTOR AS-2022-008 的 ADM 3.5.9.RUE3／4.0.5.RUE3 修補基線，並另外採用官方發行資訊確認 ADM 3.5.9.RWM1 已修正 DeadBolt 相關安全問題。其他未核實的 ADM build 會保守標示 `unknown`，不按 build 字母順序推測新舊。

來源： [AS-2022-008 DeadBolt 公告](https://www.asustor.com/en/security/security_advisory_detail?id=9)、[ADM 發行資訊](https://www.asustor.com/zh-tw/service/release_notes)、[DeadBolt 防護指引](https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6)。

## AS-202TE 實機驗證

以提供的 SSH 帳號登入成功。設備回報 ADM 3.5.9.RWM1、Linux 3.4.26、Intel Atom CE5310。已確認下列唯讀查詢可用。

- `df -hP` 顯示掛載容量
- `cat /proc/mdstat` 顯示 md0、md1 和 md126 軟體 RAID 陣列狀態
- `ip -o link show` 和 `ip -o addr show` 顯示介面和位址
- `smartctl --scan` 列出 ADM 偵測到的磁碟
- `hostname`、`uname`、`uptime`、`free -m` 和 `/proc/cpuinfo` 提供系統資訊

ADM 使用 BusyBox shell，未提供 `systemctl` 或 `journalctl`。一般 admin SSH 工作階段可讀取 `/proc/mdstat`，但 `mdadm --detail` 和 SMART 健康檢查需要更高權限，因此首版只列出磁碟裝置，不讀取 SMART 健康資料。`health` 的 `ok` 表示各項觀察命令已成功執行，不代表磁碟或 RAID 狀態一定健康。

勒索病毒功能也已在此設備實際執行：`security audit` 將 RWM1 判定為 ASUSTOR 公告已修補的版本，並觀察到管理埠 8000/8001 與 SSH 22 正在監聽；備份、密碼、EZ-Connect 與路由器設定維持人工確認。`incident scan` 完成 `/volume0` 和 `/volume1` 的檔名搜尋，未觀察到 `.deadbolt` 命中。由於測試設備的 HTTPS 憑證未通過驗證，管理頁覆蓋標為部分，整體掃描不會回報成安全。
