# ASUSTOR NAS CLI

以 Python 建立、命令名稱為 `adm` 的唯讀診斷工具。使用 OpenSSH 連線讀取 ADM 主機資訊，並以 HTTPS 檢查 ADM 管理頁。CLI 結構參照 [Synology CLI](https://github.com/akari-sora/synology-nas-cli)，唯讀診斷方式參照 [QNAP CLI](https://github.com/popuchoco/qnap-nas-cli)。

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

## AS-202TE 實機驗證

以提供的 SSH 帳號登入成功。設備回報 ADM 3.5.9.RWM1、Linux 3.4.26、Intel Atom CE5310。已確認下列唯讀查詢可用。

- `df -hP` 顯示掛載容量
- `cat /proc/mdstat` 顯示 md0、md1 和 md126 軟體 RAID 陣列狀態
- `ip -o link show` 和 `ip -o addr show` 顯示介面和位址
- `smartctl --scan` 列出 ADM 偵測到的磁碟
- `hostname`、`uname`、`uptime`、`free -m` 和 `/proc/cpuinfo` 提供系統資訊

ADM 使用 BusyBox shell，未提供 `systemctl` 或 `journalctl`。一般 admin SSH 工作階段可讀取 `/proc/mdstat`，但 `mdadm --detail` 和 SMART 健康檢查需要更高權限，因此首版只列出磁碟裝置，不讀取 SMART 健康資料。`health` 的 `ok` 表示各項觀察命令已成功執行，不代表磁碟或 RAID 狀態一定健康。
