#requires -Version 5.1
<#
Keenetic WG & Routes v1.3.4
Standalone safe updater for WireGuard / AmneziaWG / AmneziaWG 2.0 plus static route management on KeeneticOS.
Uses its own credentials, logs, rollback data and safety backups.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Security
[System.Windows.Forms.Application]::EnableVisualStyles()

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class KeeneticWGUpdaterIdentity
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern int SetCurrentProcessExplicitAppUserModelID(string appID);
}
"@

$DefaultRouterBaseUrl = 'http://192.168.1.1:8080/'
$HttpTimeoutSeconds = 10

function Normalize-KeeneticBaseUrl {
    param([Parameter(Mandatory)][string]$Value)

    $text = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'Введите адрес роутера.'
    }

    # Для удобства разрешаем ввод вида 192.168.1.1:8080 без схемы.
    if ($text -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') {
        $text = 'http://' + $text
    }

    $uri = $null
    if (-not [Uri]::TryCreate($text, [UriKind]::Absolute, [ref]$uri)) {
        throw 'Некорректный адрес роутера. Пример: http://192.168.1.1:8080/'
    }

    if ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') {
        throw 'Адрес должен начинаться с http:// или https://.'
    }

    if ([string]::IsNullOrWhiteSpace($uri.Host)) {
        throw 'В адресе роутера не найдено имя хоста или IP.'
    }

    if (($uri.AbsolutePath -ne '' -and $uri.AbsolutePath -ne '/') -or
        (-not [string]::IsNullOrWhiteSpace($uri.Query)) -or
        (-not [string]::IsNullOrWhiteSpace($uri.Fragment))) {
        throw 'Укажите только корневой адрес роутера без /auth, /rci и других путей.'
    }

    $builder = [UriBuilder]::new($uri)
    $builder.Path = '/'
    $builder.Query = ''
    $builder.Fragment = ''
    return $builder.Uri.AbsoluteUri
}
$WireGuardInterfaceCandidates = 0..19 | ForEach-Object { 'Wireguard{0}' -f $_ }
$WireGuardRouteCountCacheSeconds = 10
$RouteImportBatchSize = 950

$AppName = 'Keenetic WG & Routes'
$AppUserModelId = 'Keenetic.WG.Updater'
[KeeneticWGUpdaterIdentity]::SetCurrentProcessExplicitAppUserModelID($AppUserModelId) | Out-Null

# Fully standalone storage. Nothing is read from or written to PC MultiTool.
$DataDir = Join-Path $env:LOCALAPPDATA 'KeeneticWGUpdater'
$CredentialPath = Join-Path $DataDir 'router-credential.xml'
$RouterUrlPath = Join-Path $DataDir 'router-url.txt'
$LogPath = Join-Path $DataDir 'wg-updater.log'
$WireGuardBackupDir = Join-Path $DataDir 'wireguard-backups'
$RouteBackupDir = Join-Path $DataDir 'route-backups'
$WireGuardRollbackDir = Join-Path $DataDir 'wireguard-rollback'
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path $WireGuardBackupDir -Force | Out-Null
New-Item -ItemType Directory -Path $RouteBackupDir -Force | Out-Null
New-Item -ItemType Directory -Path $WireGuardRollbackDir -Force | Out-Null

$script:RouterBaseUrl = $DefaultRouterBaseUrl
if (Test-Path -LiteralPath $RouterUrlPath) {
    try {
        $savedRouterUrl = (Get-Content -LiteralPath $RouterUrlPath -Raw -ErrorAction Stop).Trim()
        if (-not [string]::IsNullOrWhiteSpace($savedRouterUrl)) {
            $script:RouterBaseUrl = Normalize-KeeneticBaseUrl -Value $savedRouterUrl
        }
    }
    catch {
        $script:RouterBaseUrl = $DefaultRouterBaseUrl
    }
}

$script:RciSession = $null
$script:Busy = $false
$script:LastEvent = 'Приложение запущено'
$script:LoadedWireGuardConfig = $null
$script:LoadedWireGuardConfigPath = $null
$script:WireGuardLastBackupPath = $null
$script:WireGuardRouteCountCache = @{}
$script:WireGuardRouteCountCacheAt = @{}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    $script:LastEvent = $Message
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Get-PlainTextPassword {
    param([Parameter(Mandatory)][Security.SecureString]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-LowerHexHash {
    param(
        [Parameter(Mandatory)][ValidateSet('MD5','SHA256')][string]$Algorithm,
        [Parameter(Mandatory)][string]$Text
    )

    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    if ($Algorithm -eq 'MD5') {
        $hasher = [Security.Cryptography.MD5]::Create()
    }
    else {
        $hasher = [Security.Cryptography.SHA256]::Create()
    }

    try {
        return -join ($hasher.ComputeHash($bytes) | ForEach-Object {
            $_.ToString('x2')
        })
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-ResponseHeader {
    param(
        [Parameter(Mandatory)][System.Net.Http.HttpResponseMessage]$Response,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        return [string](($Response.Headers.GetValues($Name) | Select-Object -First 1))
    }
    catch {
        return $null
    }
}

function Close-KeeneticSession {
    if ($null -ne $script:RciSession) {
        try { $script:RciSession.Client.Dispose() } catch {}
        try { $script:RciSession.Handler.Dispose() } catch {}
        $script:RciSession = $null
    }
}

function New-KeeneticSession {
    param(
        [System.Management.Automation.PSCredential]$Credential,
        [string]$BaseUrl
    )

    if ($null -eq $Credential) {
        if (-not (Test-Path -LiteralPath $CredentialPath)) {
            throw "Не сохранены учётные данные Keenetic. Нажмите «Доступ к Keenetic…»."
        }
        $Credential = Import-Clixml -LiteralPath $CredentialPath
    }

    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        $BaseUrl = $script:RouterBaseUrl
    }
    $BaseUrl = Normalize-KeeneticBaseUrl -Value $BaseUrl

    $plainPassword = Get-PlainTextPassword -SecureString $Credential.Password

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseCookies = $true
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $handler.AllowAutoRedirect = $false

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.BaseAddress = [Uri]$BaseUrl
    $client.Timeout = [TimeSpan]::FromSeconds($HttpTimeoutSeconds)

    try {
        $challengeResponse = $client.GetAsync('auth').GetAwaiter().GetResult()

        if ([int]$challengeResponse.StatusCode -ne 401) {
            if ($challengeResponse.IsSuccessStatusCode) {
                return [pscustomobject]@{
                    Client = $client
                    Handler = $handler
                }
            }

            $body = $challengeResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "Неожиданный ответ /auth: HTTP $([int]$challengeResponse.StatusCode). $body"
        }

        $realm = Get-ResponseHeader -Response $challengeResponse -Name 'X-NDM-Realm'
        $challenge = Get-ResponseHeader -Response $challengeResponse -Name 'X-NDM-Challenge'

        if ([string]::IsNullOrWhiteSpace($realm) -or
            [string]::IsNullOrWhiteSpace($challenge)) {
            throw 'Роутер не вернул X-NDM-Realm или X-NDM-Challenge.'
        }

        $md5 = Get-LowerHexHash `
            -Algorithm MD5 `
            -Text ('{0}:{1}:{2}' -f $Credential.UserName, $realm, $plainPassword)

        $sha256 = Get-LowerHexHash `
            -Algorithm SHA256 `
            -Text ($challenge + $md5)

        $authJson = @{
            login = $Credential.UserName
            password = $sha256
        } | ConvertTo-Json -Compress

        $authContent = [System.Net.Http.StringContent]::new(
            $authJson,
            [Text.Encoding]::UTF8,
            'application/json'
        )

        try {
            $authResponse = $client.PostAsync(
                'auth',
                $authContent
            ).GetAwaiter().GetResult()
        }
        finally {
            $authContent.Dispose()
        }

        if (-not $authResponse.IsSuccessStatusCode) {
            $authBody = $authResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "Авторизация Keenetic не прошла: HTTP $([int]$authResponse.StatusCode). $authBody"
        }

        return [pscustomobject]@{
            Client = $client
            Handler = $handler
        }
    }
    catch {
        $client.Dispose()
        $handler.Dispose()
        throw
    }
    finally {
        $plainPassword = $null
    }
}

function Get-KeeneticSession {
    if ($null -eq $script:RciSession) {
        $script:RciSession = New-KeeneticSession
    }
    return $script:RciSession
}

function Invoke-KeeneticRciOnce {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body
    )

    $session = Get-KeeneticSession

    if ($Method -eq 'GET') {
        $response = $session.Client.GetAsync($Path).GetAwaiter().GetResult()
    }
    else {
        $json = if ($null -eq $Body) {
            '{}'
        }
        else {
            ConvertTo-Json -InputObject $Body -Depth 12 -Compress
        }

        $content = [System.Net.Http.StringContent]::new(
            $json,
            [Text.Encoding]::UTF8,
            'application/json'
        )

        try {
            $response = $session.Client.PostAsync(
                $Path,
                $content
            ).GetAwaiter().GetResult()
        }
        finally {
            $content.Dispose()
        }
    }

    return $response
}

function Invoke-KeeneticRci {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body
    )

    $response = Invoke-KeeneticRciOnce -Method $Method -Path $Path -Body $Body

    if ([int]$response.StatusCode -eq 401) {
        $response.Dispose()
        Close-KeeneticSession
        $response = Invoke-KeeneticRciOnce -Method $Method -Path $Path -Body $Body
    }

    try {
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        if (-not $response.IsSuccessStatusCode) {
            throw "RCI: $Method $Path -> HTTP $([int]$response.StatusCode). $text"
        }

        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }

        try {
            return $text | ConvertFrom-Json
        }
        catch {
            return $text
        }
    }
    finally {
        $response.Dispose()
    }
}

# ---------------- WIREGUARD / AMNEZIAWG ----------------
function Get-NamedPropertyValue {
    param(
        [object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -ieq $Name) { return $Object[$key] }
        }
        return $null
    }

    $property = $Object.PSObject.Properties |
        Where-Object { $_.Name -ieq $Name } |
        Select-Object -First 1

    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-WireGuardConfigValue {
    param(
        [System.Collections.IDictionary]$Map,
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = ''
    )

    if ($null -eq $Map) { return $Default }
    foreach ($key in $Map.Keys) {
        if ([string]$key -ieq $Name) { return [string]$Map[$key] }
    }
    return $Default
}

function Read-WireGuardConfigText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [string]$DisplayName = 'config.conf',
        [string]$Path = ''
    )

    $interface = @{}
    $peers = New-Object System.Collections.ArrayList
    $currentSection = ''
    $currentPeer = $null

    foreach ($rawLine in ($Text -split '\r?\n')) {
        $line = ([string]$rawLine).Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith(';')) { continue }

        if ($line -match '^\[\s*Interface\s*\]$') {
            $currentSection = 'Interface'
            $currentPeer = $null
            continue
        }

        if ($line -match '^\[\s*Peer\s*\]$') {
            $currentSection = 'Peer'
            $currentPeer = @{}
            [void]$peers.Add($currentPeer)
            continue
        }

        $parts = $line -split '=', 2
        if ($parts.Count -ne 2) { continue }

        $name = $parts[0].Trim()
        $value = $parts[1].Trim()

        if ($currentSection -eq 'Interface') {
            $interface[$name] = $value
        }
        elseif ($currentSection -eq 'Peer' -and $null -ne $currentPeer) {
            $currentPeer[$name] = $value
        }
    }

    $privateKey = Get-WireGuardConfigValue -Map $interface -Name 'PrivateKey'
    if ([string]::IsNullOrWhiteSpace($privateKey)) {
        throw 'В [Interface] отсутствует PrivateKey.'
    }

    if ($peers.Count -ne 1) {
        throw "Безопасное обновление поддерживает конфиги ровно с одним [Peer]. Найдено: $($peers.Count)."
    }

    $publicKey = Get-WireGuardConfigValue -Map $peers[0] -Name 'PublicKey'
    if ([string]::IsNullOrWhiteSpace($publicKey)) {
        throw 'В [Peer] отсутствует PublicKey.'
    }

    $awgNames = @('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5')
    $isAwg = $false
    foreach ($name in $awgNames) {
        if (-not [string]::IsNullOrWhiteSpace((Get-WireGuardConfigValue -Map $interface -Name $name))) {
            $isAwg = $true
            break
        }
    }

    $isAwg2 = $false
    foreach ($name in @('S3','S4','I1','I2','I3','I4','I5')) {
        if (-not [string]::IsNullOrWhiteSpace((Get-WireGuardConfigValue -Map $interface -Name $name))) {
            $isAwg2 = $true
            break
        }
    }
    if (-not $isAwg2) {
        foreach ($name in @('H1','H2','H3','H4')) {
            if ((Get-WireGuardConfigValue -Map $interface -Name $name) -match '^\s*-?\d+\s*-\s*-?\d+\s*$') {
                $isAwg2 = $true
                break
            }
        }
    }

    return [pscustomobject]@{
        Path = $Path
        FileName = $DisplayName
        RawText = $Text
        Interface = $interface
        Peers = @($peers)
        IsAmnezia = $isAwg
        IsAmnezia2 = $isAwg2
    }
}

function Read-WireGuardConfigFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Файл не найден: $Path" }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    return Read-WireGuardConfigText -Text $text -DisplayName ([IO.Path]::GetFileName($Path)) -Path $Path
}

function Convert-Ipv4PrefixToMask {
    param([Parameter(Mandatory)][ValidateRange(0,32)][int]$Prefix)

    $mask = [uint32]0
    if ($Prefix -gt 0) { $mask = [uint32]::MaxValue -shl (32 - $Prefix) }

    return ('{0}.{1}.{2}.{3}' -f `
        (($mask -shr 24) -band 255),
        (($mask -shr 16) -band 255),
        (($mask -shr 8) -band 255),
        ($mask -band 255))
}

function Convert-Ipv4MaskToPrefix {
    param([Parameter(Mandatory)][string]$Mask)

    $parts = $Mask.Split('.')
    if ($parts.Count -ne 4) { return $null }
    $bits = ''
    foreach ($part in $parts) {
        $number = 0
        if (-not [int]::TryParse($part, [ref]$number) -or $number -lt 0 -or $number -gt 255) { return $null }
        $bits += [Convert]::ToString($number, 2).PadLeft(8, '0')
    }
    if ($bits -notmatch '^1*0*$') { return $null }
    return @($bits.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

function Convert-Ipv4CidrToAddressMask {
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr.Trim() -split '/', 2
    $ip = $parts[0].Trim()
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Некорректный IPv4: $Cidr"
    }

    $prefix = 32
    if ($parts.Count -eq 2) {
        if (-not [int]::TryParse($parts[1].Trim(), [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) {
            throw "Некорректный IPv4 prefix: $Cidr"
        }
    }

    return [pscustomobject]@{
        Address = $ip
        Prefix = $prefix
        Mask = Convert-Ipv4PrefixToMask -Prefix $prefix
    }
}

function Convert-Ipv6CidrToAddressPrefix {
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr.Trim() -split '/', 2
    $ip = $parts[0].Trim()
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw "Некорректный IPv6: $Cidr"
    }

    $prefix = 128
    if ($parts.Count -eq 2) {
        if (-not [int]::TryParse($parts[1].Trim(), [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 128) {
            throw "Некорректный IPv6 prefix: $Cidr"
        }
    }

    return [pscustomobject]@{ Address = $ip; Prefix = $prefix }
}

function Quote-KeeneticCliArgument {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { $Value = '' }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function Assert-KeeneticRciResult {
    param(
        [object]$Result,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Result) { return }
    $json = $Result | ConvertTo-Json -Depth 30 -Compress
    if ($json -match '(?i)"status"\s*:\s*"error"' -or
        $json -match '(?i)"ndmErrors"\s*:' -or
        $json -match '(?i)"error"\s*:\s*"') {
        throw "Keenetic отклонил операцию ($Description): $json"
    }
}

function Assert-KeeneticCliResult {
    param(
        [object]$Result,
        [Parameter(Mandatory)][string]$CommandDescription
    )
    Assert-KeeneticRciResult -Result $Result -Description $CommandDescription
}

function Invoke-KeeneticCliCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Description
    )

    $result = Invoke-KeeneticRci -Method POST -Path 'rci/parse' -Body $Command
    Assert-KeeneticCliResult -Result $result -CommandDescription $Description
    return $result
}

function Invoke-KeeneticRciChecked {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [Parameter(Mandatory)][string]$Description
    )

    $result = Invoke-KeeneticRci -Method $Method -Path $Path -Body $Body
    Assert-KeeneticRciResult -Result $result -Description $Description
    return $result
}

function Invoke-KeeneticTextGetOnce {
    param([Parameter(Mandatory)][string]$Path)
    $session = Get-KeeneticSession
    return $session.Client.GetAsync($Path).GetAwaiter().GetResult()
}

function Invoke-KeeneticTextGet {
    param([Parameter(Mandatory)][string]$Path)

    $response = Invoke-KeeneticTextGetOnce -Path $Path
    if ([int]$response.StatusCode -eq 401) {
        $response.Dispose()
        Close-KeeneticSession
        $response = Invoke-KeeneticTextGetOnce -Path $Path
    }

    try {
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "GET $Path -> HTTP $([int]$response.StatusCode). $text"
        }
        return $text
    }
    finally { $response.Dispose() }
}

function Get-WireGuardInterfaceConfig {
    param([Parameter(Mandatory)][string]$InterfaceName)
    return Invoke-KeeneticRci -Method GET -Path ("rci/interface/{0}" -f $InterfaceName)
}

function Get-WireGuardPeerList {
    param([object]$Config)
    $wireguard = Get-NamedPropertyValue -Object $Config -Name 'wireguard'
    if ($null -eq $wireguard) { return @() }
    $peer = Get-NamedPropertyValue -Object $wireguard -Name 'peer'
    if ($null -eq $peer) { return @() }
    return @($peer)
}

function Get-WireGuardPeerKeysFromRouterConfig {
    param([object]$Config)
    $keys = New-Object System.Collections.ArrayList
    foreach ($item in (Get-WireGuardPeerList -Config $Config)) {
        if ($null -eq $item) { continue }
        $key = Get-NamedPropertyValue -Object $item -Name 'key'
        if ([string]::IsNullOrWhiteSpace([string]$key)) {
            $key = Get-NamedPropertyValue -Object $item -Name 'public-key'
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$key) -and -not $keys.Contains([string]$key)) {
            [void]$keys.Add([string]$key)
        }
    }
    return @($keys)
}

function Find-WireGuardPeerByKey {
    param(
        [object]$Config,
        [Parameter(Mandatory)][string]$Key
    )

    foreach ($peer in (Get-WireGuardPeerList -Config $Config)) {
        $peerKey = [string](Get-NamedPropertyValue -Object $peer -Name 'key')
        if ($peerKey -eq $Key) { return $peer }
    }
    return $null
}

function Get-WireGuardInterfaceNames {
    $names = New-Object System.Collections.ArrayList
    foreach ($name in $WireGuardInterfaceCandidates) {
        try {
            $config = Get-WireGuardInterfaceConfig -InterfaceName $name
            if ($null -ne $config -and -not ($config -is [string]) -and @($config).Count -gt 0) {
                [void]$names.Add($name)
            }
        }
        catch {}
    }
    return @($names)
}

function Protect-WireGuardText {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return [Security.Cryptography.ProtectedData]::Protect(
        $bytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Unprotect-WireGuardText {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $Bytes,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Text.Encoding]::UTF8.GetString($plain)
}

function Get-WireGuardBaselinePath {
    param([Parameter(Mandatory)][string]$InterfaceName)
    return Join-Path $WireGuardRollbackDir ("{0}-current.dpapi" -f $InterfaceName)
}

function Get-WireGuardBaselineRouterPath {
    param([Parameter(Mandatory)][string]$InterfaceName)
    return Join-Path $WireGuardRollbackDir ("{0}-router-url.txt" -f $InterfaceName)
}

function Test-WireGuardBaselineRouterMatch {
    param([Parameter(Mandatory)][string]$InterfaceName)

    $markerPath = Get-WireGuardBaselineRouterPath -InterfaceName $InterfaceName
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { return $false }

    try {
        $savedUrl = Normalize-KeeneticBaseUrl -Value (Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop)
        $currentUrl = Normalize-KeeneticBaseUrl -Value $script:RouterBaseUrl
        return $savedUrl -eq $currentUrl
    }
    catch { return $false }
}

function Save-WireGuardBaselineConfig {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$Config
    )

    if ([string]::IsNullOrWhiteSpace([string]$Config.RawText)) {
        throw 'В загруженном конфиге нет исходного текста.'
    }

    $path = Get-WireGuardBaselinePath -InterfaceName $InterfaceName
    $protected = Protect-WireGuardText -Text ([string]$Config.RawText)
    [IO.File]::WriteAllBytes($path, $protected)
    Set-Content -LiteralPath (Get-WireGuardBaselineRouterPath -InterfaceName $InterfaceName) -Value $script:RouterBaseUrl -Encoding UTF8
    Write-Log "WireGuard: rollback-база $InterfaceName обновлена (DPAPI) для $($script:RouterBaseUrl)."
    return $path
}

function Get-WireGuardBaselineConfig {
    param([Parameter(Mandatory)][string]$InterfaceName)

    $path = Get-WireGuardBaselinePath -InterfaceName $InterfaceName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    if (-not (Test-WireGuardBaselineRouterMatch -InterfaceName $InterfaceName)) { return $null }
    $text = Unprotect-WireGuardText -Bytes ([IO.File]::ReadAllBytes($path))
    return Read-WireGuardConfigText -Text $text -DisplayName ("rollback-{0}.conf" -f $InterfaceName)
}

function Get-WireGuardRouteLines {
    param(
        [Parameter(Mandatory)][string]$ConfigText,
        [Parameter(Mandatory)][string]$InterfaceName
    )

    $escaped = [regex]::Escape($InterfaceName)
    return @(
        $ConfigText -split '\r?\n' |
            Where-Object {
                $_ -match '^\s*(?:ip|ipv6)\s+route\b' -and
                $_ -match ("(?i)\b{0}\b" -f $escaped)
            } |
            ForEach-Object { $_.Trim() } |
            Sort-Object
    )
}

function Get-WireGuardCurrentRouteCount {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [switch]$Force
    )

    if ($InterfaceName -notmatch '^Wireguard\d+$') {
        throw "Некорректное имя интерфейса: $InterfaceName"
    }

    $now = Get-Date
    if (-not $Force -and
        $script:WireGuardRouteCountCache.ContainsKey($InterfaceName) -and
        $script:WireGuardRouteCountCacheAt.ContainsKey($InterfaceName)) {
        $ageSeconds = ($now - [datetime]$script:WireGuardRouteCountCacheAt[$InterfaceName]).TotalSeconds
        if ($ageSeconds -lt $WireGuardRouteCountCacheSeconds) {
            return [int]$script:WireGuardRouteCountCache[$InterfaceName]
        }
    }

    $runningText = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
    if ([string]::IsNullOrWhiteSpace($runningText) -or $runningText.Length -lt 200) {
        throw 'Keenetic вернул подозрительно пустой running-config при подсчёте маршрутов.'
    }

    $count = @(Get-WireGuardRouteLines -ConfigText $runningText -InterfaceName $InterfaceName).Count
    $script:WireGuardRouteCountCache[$InterfaceName] = [int]$count
    $script:WireGuardRouteCountCacheAt[$InterfaceName] = $now
    return [int]$count
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Save-WireGuardSafetyBackup {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$RouterConfig,
        [Parameter(Mandatory)][object]$BaselineConfig,
        [ValidateSet('update','rollback')][string]$Operation = 'update'
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $folder = Join-Path $WireGuardBackupDir ("{0}-{1}" -f $stamp, $InterfaceName)
    New-Item -ItemType Directory -Path $folder -Force | Out-Null

    $startupText = Invoke-KeeneticTextGet -Path 'ci/startup-config.txt'
    if ([string]::IsNullOrWhiteSpace($startupText) -or $startupText.Length -lt 200) {
        throw 'Keenetic вернул подозрительно пустой startup-config. Обновление остановлено до любых изменений.'
    }

    try {
        $runningText = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
    }
    catch {
        throw "Не удалось скачать running-config перед изменением. Без него безопасная проверка маршрутов невозможна, поэтому обновление не начато. $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($runningText) -or $runningText.Length -lt 200) {
        throw 'Keenetic вернул подозрительно пустой running-config. Обновление остановлено до любых изменений.'
    }

    $startupPath = Join-Path $folder 'startup-config.txt'
    $runningPath = Join-Path $folder 'running-config-before.txt'
    $interfacePath = Join-Path $folder ("{0}-before.json" -f $InterfaceName)
    $routesPath = Join-Path $folder ("{0}-routes-before.txt" -f $InterfaceName)
    $baselineCopy = Join-Path $folder ("{0}-rollback.dpapi" -f $InterfaceName)
    $metaPath = Join-Path $folder 'backup-meta.json'

    [IO.File]::WriteAllText($startupPath, $startupText, [Text.Encoding]::UTF8)
    [IO.File]::WriteAllText($runningPath, $runningText, [Text.Encoding]::UTF8)
    $RouterConfig | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $interfacePath -Encoding UTF8

    $routes = @(Get-WireGuardRouteLines -ConfigText $runningText -InterfaceName $InterfaceName)
    [IO.File]::WriteAllLines($routesPath, $routes, [Text.Encoding]::UTF8)

    $baselinePath = Get-WireGuardBaselinePath -InterfaceName $InterfaceName
    if (-not (Test-Path -LiteralPath $baselinePath)) {
        throw 'Rollback-база исчезла перед созданием бэкапа. Обновление остановлено.'
    }
    Copy-Item -LiteralPath $baselinePath -Destination $baselineCopy -Force

    $meta = [ordered]@{
        version = '1.2.0'
        created = (Get-Date).ToString('o')
        interface = $InterfaceName
        router_url = $script:RouterBaseUrl
        operation = $Operation
        result = 'pending'
        startup_sha256 = Get-TextSha256 -Text $startupText
        running_sha256 = Get-TextSha256 -Text $runningText
        route_count = $routes.Count
        baseline_file = [IO.Path]::GetFileName($baselineCopy)
        note = 'Полный startup/running backup + DPAPI rollback config. PrivateKey хранится только в DPAPI-файле.'
    }
    $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metaPath -Encoding UTF8

    $script:WireGuardLastBackupPath = $folder
    return [pscustomobject]@{
        Folder = $folder
        StartupPath = $startupPath
        RunningBefore = $runningText
        RoutesBefore = $routes
    }
}


function Update-WireGuardBackupMeta {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [hashtable]$Values
    )

    $metaPath = Join-Path $Folder 'backup-meta.json'
    if (-not (Test-Path -LiteralPath $metaPath -PathType Leaf)) { return }

    try {
        $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($name in $Values.Keys) {
            $meta | Add-Member -NotePropertyName $name -NotePropertyValue $Values[$name] -Force
        }
        $meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metaPath -Encoding UTF8
    }
    catch {
        Write-Log "WireGuard: не удалось обновить metadata бэкапа ${Folder}: $($_.Exception.Message)"
    }
}

function Mark-WireGuardSafetyBackupSuccess {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][ValidateSet('update','rollback')][string]$Operation
    )
    Update-WireGuardBackupMeta -Folder $Folder -Values @{
        operation = $Operation
        result = 'success'
        completed = (Get-Date).ToString('o')
    }
}

function Mark-WireGuardUpdateBackupRolledBack {
    param([Parameter(Mandatory)][string]$Folder)
    Update-WireGuardBackupMeta -Folder $Folder -Values @{
        rolled_back = $true
        rolled_back_at = (Get-Date).ToString('o')
    }
}

function Get-LatestWireGuardSuccessfulUpdateBackup {
    param([Parameter(Mandatory)][string]$InterfaceName)

    if (-not (Test-Path -LiteralPath $WireGuardBackupDir -PathType Container)) { return $null }
    $escaped = [regex]::Escape($InterfaceName)
    $folders = @(
        Get-ChildItem -LiteralPath $WireGuardBackupDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match ("-{0}$" -f $escaped) } |
            Sort-Object LastWriteTime -Descending
    )

    foreach ($folderInfo in $folders) {
        $folder = $folderInfo.FullName
        $metaPath = Join-Path $folder 'backup-meta.json'
        $rollbackPath = Join-Path $folder ("{0}-rollback.dpapi" -f $InterfaceName)
        $runningAfterPath = Join-Path $folder 'running-config-after.txt'
        $routesAfterPath = Join-Path $folder ("{0}-routes-after.txt" -f $InterfaceName)

        if (-not (Test-Path -LiteralPath $rollbackPath -PathType Leaf)) { continue }
        if (-not (Test-Path -LiteralPath $runningAfterPath -PathType Leaf)) { continue }
        if (-not (Test-Path -LiteralPath $routesAfterPath -PathType Leaf)) { continue }

        $meta = $null
        if (Test-Path -LiteralPath $metaPath -PathType Leaf) {
            try { $meta = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json }
            catch { $meta = $null }
        }

        $operation = ''
        $result = ''
        $rolledBack = $false
        if ($null -ne $meta) {
            $metaRouterUrl = [string](Get-NamedPropertyValue -Object $meta -Name 'router_url')
            if ([string]::IsNullOrWhiteSpace($metaRouterUrl)) { continue }
            try {
                if ((Normalize-KeeneticBaseUrl -Value $metaRouterUrl) -ne (Normalize-KeeneticBaseUrl -Value $script:RouterBaseUrl)) { continue }
            }
            catch { continue }

            $operation = [string](Get-NamedPropertyValue -Object $meta -Name 'operation')
            $result = [string](Get-NamedPropertyValue -Object $meta -Name 'result')
            $rolledValue = Get-NamedPropertyValue -Object $meta -Name 'rolled_back'
            if ($rolledValue -is [bool]) { $rolledBack = [bool]$rolledValue }
            elseif ([string]$rolledValue -match '^(?i:true|yes|1)$') { $rolledBack = $true }
        }

        # Старые v2.2.x backup-meta не имели operation/result. Если есть after-файлы,
        # считаем самый свежий такой бэкап успешным обновлением.
        if (-not [string]::IsNullOrWhiteSpace($operation) -and $operation -ne 'update') { continue }
        if (-not [string]::IsNullOrWhiteSpace($result) -and $result -ne 'success') {
            # Это более свежая попытка обновления, но она не была успешно завершена.
            # Не предлагаем откат какого-то более старого апдейта под видом «последнего».
            return $null
        }

        # Если самое свежее успешное обновление уже откатывали, к более старым
        # автоматически не проваливаемся: кнопка означает именно последний апдейт.
        if ($rolledBack) { return $null }

        $routeCount = -1
        if ($null -ne $meta) {
            $routeValue = Get-NamedPropertyValue -Object $meta -Name 'route_count'
            [void][int]::TryParse([string]$routeValue, [ref]$routeCount)
        }

        return [pscustomobject]@{
            Folder = $folder
            RollbackPath = $rollbackPath
            Created = $folderInfo.LastWriteTime
            RouteCount = $routeCount
            Meta = $meta
        }
    }

    return $null
}

function Read-WireGuardDpapiConfig {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$InterfaceName
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "DPAPI rollback-файл не найден: $Path" }
    $text = Unprotect-WireGuardText -Bytes ([IO.File]::ReadAllBytes($Path))
    return Read-WireGuardConfigText -Text $text -DisplayName ("rollback-last-update-{0}.conf" -f $InterfaceName)
}

function Get-WireGuardShowInterface {
    param([Parameter(Mandatory)][string]$InterfaceName)
    $result = $null
    try {
        $result = Invoke-KeeneticRci -Method GET -Path ("rci/show/interface/{0}" -f $InterfaceName)
    }
    catch {
        $result = Invoke-KeeneticRci -Method GET -Path ("rci/show/interface?name={0}" -f $InterfaceName)
    }

    # Некоторые RCI-варианты возвращают объект сразу, другие — обёртку { WireguardX: {...} }.
    $wrapped = Get-NamedPropertyValue -Object $result -Name $InterfaceName
    if ($null -ne $wrapped) { return $wrapped }
    return $result
}

function ConvertTo-KeeneticBoolean {
    param($Value)
    if ($Value -is [bool]) { return [bool]$Value }
    return ([string]$Value -match '^(?i:true|yes|1|up|online)$')
}

function Get-WireGuardRuntimeStatus {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [string]$PublicKey
    )

    $live = Get-WireGuardShowInterface -InterfaceName $InterfaceName
    $config = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName

    if ([string]::IsNullOrWhiteSpace($PublicKey)) {
        $keys = @(Get-WireGuardPeerKeysFromRouterConfig -Config $config)
        if ($keys.Count -gt 0) { $PublicKey = [string]$keys[0] }
    }

    $configuredPeer = $null
    if (-not [string]::IsNullOrWhiteSpace($PublicKey)) {
        $configuredPeer = Find-WireGuardPeerByKey -Config $config -Key $PublicKey
    }

    $endpoint = ''
    if ($null -ne $configuredPeer) {
        $endpointNode = Get-NamedPropertyValue -Object $configuredPeer -Name 'endpoint'
        $endpoint = [string](Get-NamedPropertyValue -Object $endpointNode -Name 'address')
    }

    $liveWg = Get-NamedPropertyValue -Object $live -Name 'wireguard'
    $livePeersNode = Get-NamedPropertyValue -Object $liveWg -Name 'peer'
    $livePeers = @()
    if ($null -ne $livePeersNode) { $livePeers = @($livePeersNode) }
    $livePeer = $null
    foreach ($candidate in $livePeers) {
        $candidateKey = [string](Get-NamedPropertyValue -Object $candidate -Name 'public-key')
        if ([string]::IsNullOrWhiteSpace($candidateKey)) {
            $candidateKey = [string](Get-NamedPropertyValue -Object $candidate -Name 'key')
        }
        if ([string]::IsNullOrWhiteSpace($PublicKey) -or $candidateKey -eq $PublicKey) {
            $livePeer = $candidate
            if (-not [string]::IsNullOrWhiteSpace($PublicKey)) { break }
        }
    }

    $connected = ConvertTo-KeeneticBoolean (Get-NamedPropertyValue -Object $live -Name 'connected')
    $linkUp = ([string](Get-NamedPropertyValue -Object $live -Name 'link')) -eq 'up'
    $online = $false
    $hasHandshake = $false
    $lastHandshake = -1L
    $remoteEndpoint = ''
    $rxBytes = 0L
    $txBytes = 0L

    if ($null -ne $livePeer) {
        $online = ConvertTo-KeeneticBoolean (Get-NamedPropertyValue -Object $livePeer -Name 'online')
        $hsText = [string](Get-NamedPropertyValue -Object $livePeer -Name 'last-handshake')
        if (-not [string]::IsNullOrWhiteSpace($hsText)) {
            $parsedHs = 0L
            if ([int64]::TryParse($hsText, [ref]$parsedHs)) {
                $lastHandshake = $parsedHs
                $hasHandshake = $true
            }
        }
        $remoteAddress = [string](Get-NamedPropertyValue -Object $livePeer -Name 'remote-endpoint-address')
        $remotePort = [string](Get-NamedPropertyValue -Object $livePeer -Name 'remote-port')
        if (-not [string]::IsNullOrWhiteSpace($remoteAddress) -and $remoteAddress -ne '0.0.0.0' -and $remoteAddress -ne '::') {
            $remoteEndpoint = if ([string]::IsNullOrWhiteSpace($remotePort)) { $remoteAddress } else { "${remoteAddress}:$remotePort" }
        }
        [void][int64]::TryParse([string](Get-NamedPropertyValue -Object $livePeer -Name 'rxbytes'), [ref]$rxBytes)
        [void][int64]::TryParse([string](Get-NamedPropertyValue -Object $livePeer -Name 'txbytes'), [ref]$txBytes)
    }

    if ([string]::IsNullOrWhiteSpace($endpoint)) { $endpoint = $remoteEndpoint }

    return [pscustomobject]@{
        Interface = $InterfaceName
        PublicKey = $PublicKey
        Connected = $connected
        LinkUp = $linkUp
        Online = $online
        HasHandshake = $hasHandshake
        LastHandshakeSeconds = $lastHandshake
        Endpoint = $endpoint
        RemoteEndpoint = $remoteEndpoint
        RxBytes = $rxBytes
        TxBytes = $txBytes
    }
}

function Format-WireGuardRuntimeStatus {
    param(
        [Parameter(Mandatory)][object]$Runtime,
        [int]$RouteCount = -1
    )

    $stateText = if ($Runtime.Online) { 'online ✓' } elseif ($Runtime.Connected -or $Runtime.LinkUp) { 'интерфейс поднят' } else { 'offline' }
    $handshakeText = if ($Runtime.Online -and $Runtime.HasHandshake) {
        "OK, $($Runtime.LastHandshakeSeconds) сек. назад"
    }
    elseif ($Runtime.HasHandshake) {
        "$($Runtime.LastHandshakeSeconds) сек. назад (peer offline)"
    }
    else { 'ещё нет / нет данных' }
    $routesText = if ($RouteCount -ge 0) { [string]$RouteCount } else { '—' }
    $endpointText = if ([string]::IsNullOrWhiteSpace([string]$Runtime.Endpoint)) { '—' } else { [string]$Runtime.Endpoint }

    return "$($Runtime.Interface): $stateText | Handshake: $handshakeText | Routes: $routesText`r`nEndpoint: $endpointText"
}

function Wait-WireGuardRuntimeStatus {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [string]$PublicKey,
        [int]$Attempts = 6
    )

    $last = $null
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            $last = Get-WireGuardRuntimeStatus -InterfaceName $InterfaceName -PublicKey $PublicKey
            if ($last.Online -and $last.HasHandshake) { return $last }
        }
        catch {
            if ($i -eq ($Attempts - 1)) { throw }
        }
        if ($i -lt ($Attempts - 1)) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1
        }
    }
    return $last
}

function Update-WireGuardRuntimeStatusLabel {
    param([int]$RouteCount = -1)

    if ($null -eq $wireGuardStatusLabel -or $null -eq $wireGuardInterfaceCombo) { return }
    $interfaceName = [string]$wireGuardInterfaceCombo.SelectedItem
    if ([string]::IsNullOrWhiteSpace($interfaceName)) { return }

    try {
        $baseline = Get-WireGuardBaselineConfig -InterfaceName $interfaceName
        $key = ''
        if ($null -ne $baseline -and $baseline.Peers.Count -gt 0) {
            $key = Get-WireGuardConfigValue -Map $baseline.Peers[0] -Name 'PublicKey'
        }
        if ($RouteCount -lt 0) {
            try {
                $RouteCount = Get-WireGuardCurrentRouteCount -InterfaceName $interfaceName
            }
            catch {
                Write-Log "WireGuard: не удалось посчитать текущие маршруты ${interfaceName}: $($_.Exception.Message)"
            }
        }
        else {
            $script:WireGuardRouteCountCache[$interfaceName] = [int]$RouteCount
            $script:WireGuardRouteCountCacheAt[$interfaceName] = Get-Date
        }

        $runtime = Get-WireGuardRuntimeStatus -InterfaceName $interfaceName -PublicKey $key
        $wireGuardStatusLabel.Text = Format-WireGuardRuntimeStatus -Runtime $runtime -RouteCount $RouteCount
        if ($runtime.Online) { $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DarkGreen }
        elseif ($runtime.Connected -or $runtime.LinkUp) { $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DarkOrange }
        else { $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::Firebrick }
    }
    catch {
        $wireGuardStatusLabel.Text = "Статус ${interfaceName}: $($_.Exception.Message)"
        $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DimGray
    }
}

function Get-ScalarAwgNumber {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$Value,
        [System.Collections.ArrayList]$Warnings
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { throw "В AmneziaWG отсутствует параметр $Name." }
    $trimmed = $Value.Trim()
    if ($trimmed -match '^(-?\d+)\s*-\s*(-?\d+)$') {
        $a = [int64]$matches[1]
        $b = [int64]$matches[2]
        $mid = [int64][Math]::Round(($a + $b) / 2.0)
        if ($null -ne $Warnings) { [void]$Warnings.Add("$Name=$trimmed -> выбран $mid (Keenetic ожидает одно число).") }
        return [string]$mid
    }
    $number = 0L
    if (-not [int64]::TryParse($trimmed, [ref]$number)) { throw "Параметр $Name должен быть числом: '$Value'." }
    return [string]$number
}

function Get-LegacyAwgHValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [System.Collections.ArrayList]$Warnings
    )

    $trimmed = $Value.Trim()
    if ($trimmed -match '^(-?\d+)\s*-\s*(-?\d+)$') {
        $a = [int64]$matches[1]
        $b = [int64]$matches[2]
        $mid = [int64][Math]::Round(($a + $b) / 2.0)
        if ($null -ne $Warnings) { [void]$Warnings.Add("$Name=$trimmed -> legacy fallback использует $mid.") }
        return [string]$mid
    }
    return Get-ScalarAwgNumber -Name $Name -Value $trimmed -Warnings $Warnings
}

function Test-AwgExtendedFallbackSafe {
    param([System.Collections.IDictionary]$InterfaceMap)
    foreach ($name in @('S3','S4')) {
        $value = (Get-WireGuardConfigValue -Map $InterfaceMap -Name $name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '0') { return $false }
    }
    foreach ($name in @('I1','I2','I3','I4','I5')) {
        $value = (Get-WireGuardConfigValue -Map $InterfaceMap -Name $name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '0') { return $false }
    }
    return $true
}

function New-AwgAscCommand {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][System.Collections.IDictionary]$InterfaceMap,
        [Parameter(Mandatory)][bool]$Extended,
        [System.Collections.ArrayList]$Warnings
    )

    $jc = Get-ScalarAwgNumber -Name 'Jc' -Value (Get-WireGuardConfigValue -Map $InterfaceMap -Name 'Jc') -Warnings $Warnings
    $jmin = Get-ScalarAwgNumber -Name 'Jmin' -Value (Get-WireGuardConfigValue -Map $InterfaceMap -Name 'Jmin') -Warnings $Warnings
    $jmax = Get-ScalarAwgNumber -Name 'Jmax' -Value (Get-WireGuardConfigValue -Map $InterfaceMap -Name 'Jmax') -Warnings $Warnings
    $s1 = Get-ScalarAwgNumber -Name 'S1' -Value (Get-WireGuardConfigValue -Map $InterfaceMap -Name 'S1') -Warnings $Warnings
    $s2 = Get-ScalarAwgNumber -Name 'S2' -Value (Get-WireGuardConfigValue -Map $InterfaceMap -Name 'S2') -Warnings $Warnings

    $hValues = @()
    foreach ($name in @('H1','H2','H3','H4')) {
        $value = Get-WireGuardConfigValue -Map $InterfaceMap -Name $name
        if ([string]::IsNullOrWhiteSpace($value)) { throw "В AmneziaWG отсутствует параметр $name." }
        if ($Extended) {
            if ($value.Trim() -notmatch '^-?\d+(\s*-\s*-?\d+)?$') { throw "Некорректный ${name}: '$value'." }
            $hValues += ($value.Trim() -replace '\s+', '')
        }
        else { $hValues += Get-LegacyAwgHValue -Name $name -Value $value -Warnings $Warnings }
    }

    $base = "interface $InterfaceName wireguard asc $jc $jmin $jmax $s1 $s2 $($hValues -join ' ')"
    if (-not $Extended) { return $base }

    $s3Raw = Get-WireGuardConfigValue -Map $InterfaceMap -Name 'S3' -Default '0'
    $s4Raw = Get-WireGuardConfigValue -Map $InterfaceMap -Name 'S4' -Default '0'
    if ([string]::IsNullOrWhiteSpace($s3Raw)) { $s3Raw = '0' }
    if ([string]::IsNullOrWhiteSpace($s4Raw)) { $s4Raw = '0' }
    $s3 = Get-ScalarAwgNumber -Name 'S3' -Value $s3Raw -Warnings $Warnings
    $s4 = Get-ScalarAwgNumber -Name 'S4' -Value $s4Raw -Warnings $Warnings

    $iArgs = @()
    foreach ($name in @('I1','I2','I3','I4','I5')) {
        $value = (Get-WireGuardConfigValue -Map $InterfaceMap -Name $name).Trim()
        if ($value -eq '0') { $value = '' }
        $iArgs += Quote-KeeneticCliArgument -Value $value
    }
    return "$base $s3 $s4 $($iArgs -join ' ')"
}

function Set-WireGuardAscFromConfig {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.ArrayList]$Warnings
    )

    if (-not $Config.IsAmnezia) {
        try { Invoke-KeeneticCliCommand -Command "interface $InterfaceName no wireguard asc" -Description 'отключение ASC' | Out-Null }
        catch { [void]$Warnings.Add('Не удалось очистить ASC обычного WireGuard.') }
        return
    }

    if ($Config.IsAmnezia2) {
        $extended = New-AwgAscCommand -InterfaceName $InterfaceName -InterfaceMap $Config.Interface -Extended $true -Warnings $Warnings
        try {
            Invoke-KeeneticCliCommand -Command $extended -Description 'AmneziaWG 2.0 ASC' | Out-Null
            return
        }
        catch {
            if (-not (Test-AwgExtendedFallbackSafe -InterfaceMap $Config.Interface)) {
                throw "Keenetic не принял extended ASC этого AmneziaWG 2.0 конфига. Legacy fallback небезопасен. $($_.Exception.Message)"
            }
            [void]$Warnings.Add('Extended ASC не принят; используется совместимый legacy fallback.')
        }
        $legacy = New-AwgAscCommand -InterfaceName $InterfaceName -InterfaceMap $Config.Interface -Extended $false -Warnings $Warnings
        Invoke-KeeneticCliCommand -Command $legacy -Description 'AmneziaWG legacy ASC fallback' | Out-Null
        return
    }

    $legacy = New-AwgAscCommand -InterfaceName $InterfaceName -InterfaceMap $Config.Interface -Extended $false -Warnings $Warnings
    try {
        Invoke-KeeneticCliCommand -Command $legacy -Description 'AmneziaWG ASC' | Out-Null
        return
    }
    catch { [void]$Warnings.Add('Legacy ASC не принят; пробуем extended-синтаксис.') }

    $extendedCompat = New-AwgAscCommand -InterfaceName $InterfaceName -InterfaceMap $Config.Interface -Extended $true -Warnings $Warnings
    Invoke-KeeneticCliCommand -Command $extendedCompat -Description 'AmneziaWG ASC extended compatibility' | Out-Null
}

function Set-WireGuardInterfaceAddresses {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][string]$AddressText,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.ArrayList]$Warnings
    )

    if ([string]::IsNullOrWhiteSpace($AddressText)) { return }
    $addresses = @($AddressText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $ipv4 = @($addresses | Where-Object { $_ -notmatch ':' })
    $ipv6 = @($addresses | Where-Object { $_ -match ':' })

    if ($ipv4.Count -gt 0) {
        if ($ipv4.Count -gt 1) { [void]$Warnings.Add("Несколько IPv4 Address; используется первый: $($ipv4[0]).") }
        $parsed = Convert-Ipv4CidrToAddressMask -Cidr $ipv4[0]
        Invoke-KeeneticCliCommand -Command "interface $InterfaceName no ip address" -Description 'очистка IPv4 адреса' | Out-Null
        Invoke-KeeneticCliCommand -Command ("interface {0} ip address {1} {2}" -f $InterfaceName,$parsed.Address,$parsed.Mask) -Description 'IPv4 адрес WireGuard' | Out-Null
    }

    # IPv6 сначала очищаем всегда. Это важно для rollback: если новый конфиг добавил IPv6,
    # а исходный рабочий конфиг его не содержал, rollback должен убрать новый адрес.
    try { Invoke-KeeneticCliCommand -Command "interface $InterfaceName no ipv6 address" -Description 'очистка IPv6 адресов' | Out-Null }
    catch {
        if ($ipv6.Count -gt 0) { [void]$Warnings.Add('Не удалось очистить старые IPv6-адреса; новые будут добавлены.') }
    }
    foreach ($item in $ipv6) {
        $parsed6 = Convert-Ipv6CidrToAddressPrefix -Cidr $item
        Invoke-KeeneticCliCommand -Command ("interface {0} ipv6 address {1}/{2}" -f $InterfaceName,$parsed6.Address,$parsed6.Prefix) -Description 'IPv6 адрес WireGuard' | Out-Null
    }
}

function New-WireGuardPeerShell {
    param([Parameter(Mandatory)][object]$PeerMap)

    $key = Get-WireGuardConfigValue -Map $PeerMap -Name 'PublicKey'
    if ([string]::IsNullOrWhiteSpace($key)) { throw 'В [Peer] отсутствует PublicKey.' }

    $peer = [ordered]@{ key = $key; comment = '' }

    $endpoint = Get-WireGuardConfigValue -Map $PeerMap -Name 'Endpoint'
    if (-not [string]::IsNullOrWhiteSpace($endpoint)) { $peer['endpoint'] = @{ address = $endpoint.Trim() } }

    $psk = Get-WireGuardConfigValue -Map $PeerMap -Name 'PresharedKey'
    if (-not [string]::IsNullOrWhiteSpace($psk)) { $peer['preshared-key'] = $psk.Trim() }

    $keepaliveText = Get-WireGuardConfigValue -Map $PeerMap -Name 'PersistentKeepalive'
    if (-not [string]::IsNullOrWhiteSpace($keepaliveText)) {
        $keepalive = 0
        if (-not [int]::TryParse($keepaliveText.Trim(), [ref]$keepalive) -or $keepalive -lt 0) {
            throw "Некорректный PersistentKeepalive: $keepaliveText"
        }
        if ($keepalive -gt 0) { $peer['keepalive-interval'] = @{ interval = $keepalive } }
    }

    return $peer
}

function Stage-WireGuardPeerWithoutAllowedIps {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$PeerMap
    )

    $newKey = Get-WireGuardConfigValue -Map $PeerMap -Name 'PublicKey'
    $peer = New-WireGuardPeerShell -PeerMap $PeerMap
    $body = [object[]]@([ordered]@{ wireguard = @{ peer = [object[]]@($peer) } })
    Invoke-KeeneticRciChecked -Method POST -Path ("rci/interface/{0}" -f $InterfaceName) -Body $body -Description 'подготовка нового peer через RCI' | Out-Null

    $after = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
    if ($null -eq (Find-WireGuardPeerByKey -Config $after -Key $newKey)) {
        throw 'RCI не вернул новый peer после его подготовки. Старый peer ещё не удалён; обновление остановлено.'
    }
}

function Set-WireGuardAllowedIps {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$PeerMap
    )

    $key = Get-WireGuardConfigValue -Map $PeerMap -Name 'PublicKey'
    $quotedKey = Quote-KeeneticCliArgument -Value $key

    try {
        Invoke-KeeneticCliCommand -Command "interface $InterfaceName wireguard peer $quotedKey no allow-ips" -Description 'очистка AllowedIPs нового peer' | Out-Null
    }
    catch {
        # Новый peer может не иметь AllowedIPs; это не ошибка.
    }

    $allowedText = Get-WireGuardConfigValue -Map $PeerMap -Name 'AllowedIPs'
    $allowedItems = @($allowedText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($allowedItems.Count -eq 0) { throw 'В [Peer] отсутствуют AllowedIPs.' }

    foreach ($allowed in $allowedItems) {
        if ($allowed -match ':') {
            $parsed6 = Convert-Ipv6CidrToAddressPrefix -Cidr $allowed
            Invoke-KeeneticCliCommand -Command ("interface {0} wireguard peer {1} allow-ips {2} {3}" -f $InterfaceName,$quotedKey,$parsed6.Address,$parsed6.Prefix) -Description 'IPv6 AllowedIPs' | Out-Null
        }
        else {
            $parsed4 = Convert-Ipv4CidrToAddressMask -Cidr $allowed
            Invoke-KeeneticCliCommand -Command ("interface {0} wireguard peer {1} allow-ips {2} {3}" -f $InterfaceName,$quotedKey,$parsed4.Address,$parsed4.Mask) -Description 'IPv4 AllowedIPs' | Out-Null
        }
    }
}

function Connect-WireGuardPeer {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][string]$Key
    )
    $quotedKey = Quote-KeeneticCliArgument -Value $Key
    Invoke-KeeneticCliCommand -Command "interface $InterfaceName wireguard peer $quotedKey connect" -Description 'активация peer' | Out-Null
}

function Remove-WireGuardPeer {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][string]$Key
    )
    $quotedKey = Quote-KeeneticCliArgument -Value $Key
    Invoke-KeeneticCliCommand -Command "interface $InterfaceName no wireguard peer $quotedKey" -Description 'удаление старого peer' | Out-Null
}

function Get-WireGuardDesiredAllowedTokens {
    param([Parameter(Mandatory)][object]$PeerMap)
    $tokens = New-Object System.Collections.ArrayList
    $text = Get-WireGuardConfigValue -Map $PeerMap -Name 'AllowedIPs'
    foreach ($item in @($text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($item -match ':') {
            $p6 = Convert-Ipv6CidrToAddressPrefix -Cidr $item
            [void]$tokens.Add(("v6:{0}/{1}" -f $p6.Address.ToLowerInvariant(),$p6.Prefix))
        }
        else {
            $p4 = Convert-Ipv4CidrToAddressMask -Cidr $item
            [void]$tokens.Add(("v4:{0}/{1}" -f $p4.Address,$p4.Prefix))
        }
    }
    return @($tokens | Sort-Object)
}

function Get-WireGuardLiveAllowedTokens {
    param([Parameter(Mandatory)][object]$Peer)
    $tokens = New-Object System.Collections.ArrayList
    foreach ($item in @((Get-NamedPropertyValue -Object $Peer -Name 'allow-ips'))) {
        if ($null -eq $item) { continue }
        $address = [string](Get-NamedPropertyValue -Object $item -Name 'address')
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        $mask = [string](Get-NamedPropertyValue -Object $item -Name 'mask')
        $prefixLength = Get-NamedPropertyValue -Object $item -Name 'prefix-length'

        if ($address -match ':') {
            $prefix = 128
            if ($null -ne $prefixLength) { $prefix = [int]$prefixLength }
            elseif (-not [string]::IsNullOrWhiteSpace($mask)) {
                $tmp = 0
                if ([int]::TryParse($mask, [ref]$tmp)) { $prefix = $tmp }
            }
            [void]$tokens.Add(("v6:{0}/{1}" -f $address.ToLowerInvariant(),$prefix))
        }
        else {
            $prefix = Convert-Ipv4MaskToPrefix -Mask $mask
            if ($null -eq $prefix) { continue }
            [void]$tokens.Add(("v4:{0}/{1}" -f $address,$prefix))
        }
    }
    return @($tokens | Sort-Object)
}

function Assert-WireGuardPeerMatchesConfig {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$PeerMap
    )

    $key = Get-WireGuardConfigValue -Map $PeerMap -Name 'PublicKey'
    $live = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
    $peer = Find-WireGuardPeerByKey -Config $live -Key $key
    if ($null -eq $peer) { throw 'Новый peer отсутствует после применения.' }

    $wantedEndpoint = (Get-WireGuardConfigValue -Map $PeerMap -Name 'Endpoint').Trim()
    if (-not [string]::IsNullOrWhiteSpace($wantedEndpoint)) {
        $endpointNode = Get-NamedPropertyValue -Object $peer -Name 'endpoint'
        $liveEndpoint = [string](Get-NamedPropertyValue -Object $endpointNode -Name 'address')
        if ($liveEndpoint -ne $wantedEndpoint) { throw "Endpoint не прошёл проверку: '$liveEndpoint' вместо '$wantedEndpoint'." }
    }

    $wantedAllowed = @(Get-WireGuardDesiredAllowedTokens -PeerMap $PeerMap)
    $liveAllowed = @(Get-WireGuardLiveAllowedTokens -Peer $peer)
    if (($wantedAllowed -join '|') -ne ($liveAllowed -join '|')) {
        throw "AllowedIPs не прошли проверку. Нужно: $($wantedAllowed -join ', '); Keenetic: $($liveAllowed -join ', ')."
    }
}

function Test-WireGuardConfigMatchesRouter {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$Config
    )

    $live = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
    $keys = @(Get-WireGuardPeerKeysFromRouterConfig -Config $live)
    $wantedKey = Get-WireGuardConfigValue -Map $Config.Peers[0] -Name 'PublicKey'
    if ($keys.Count -ne 1 -or $keys[0] -ne $wantedKey) {
        return [pscustomobject]@{ Match = $false; Reason = 'PublicKey текущего peer не совпадает.' }
    }

    $addressText = Get-WireGuardConfigValue -Map $Config.Interface -Name 'Address'
    $wantedIpv4 = @($addressText -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch ':' } | Select-Object -First 1)
    if ($wantedIpv4.Count -gt 0) {
        $wanted = Convert-Ipv4CidrToAddressMask -Cidr $wantedIpv4[0]
        $ipNode = Get-NamedPropertyValue -Object $live -Name 'ip'
        $addressNode = Get-NamedPropertyValue -Object $ipNode -Name 'address'
        $liveAddress = [string](Get-NamedPropertyValue -Object $addressNode -Name 'address')
        $liveMask = [string](Get-NamedPropertyValue -Object $addressNode -Name 'mask')
        if ($liveAddress -ne $wanted.Address -or $liveMask -ne $wanted.Mask) {
            return [pscustomobject]@{ Match = $false; Reason = "IPv4 текущего интерфейса $liveAddress/$liveMask не совпадает с конфигом." }
        }
    }

    $peer = Find-WireGuardPeerByKey -Config $live -Key $wantedKey
    $wantedEndpoint = (Get-WireGuardConfigValue -Map $Config.Peers[0] -Name 'Endpoint').Trim()
    if (-not [string]::IsNullOrWhiteSpace($wantedEndpoint)) {
        $endpointNode = Get-NamedPropertyValue -Object $peer -Name 'endpoint'
        $liveEndpoint = [string](Get-NamedPropertyValue -Object $endpointNode -Name 'address')
        if ($liveEndpoint -ne $wantedEndpoint) {
            return [pscustomobject]@{ Match = $false; Reason = 'Endpoint текущего peer не совпадает.' }
        }
    }

    $wantedAllowed = @(Get-WireGuardDesiredAllowedTokens -PeerMap $Config.Peers[0])
    $liveAllowed = @(Get-WireGuardLiveAllowedTokens -Peer $peer)
    if (($wantedAllowed -join '|') -ne ($liveAllowed -join '|')) {
        return [pscustomobject]@{ Match = $false; Reason = 'AllowedIPs текущего peer не совпадают.' }
    }

    $wantedPsk = (Get-WireGuardConfigValue -Map $Config.Peers[0] -Name 'PresharedKey').Trim()
    if (-not [string]::IsNullOrWhiteSpace($wantedPsk)) {
        $livePsk = [string](Get-NamedPropertyValue -Object $peer -Name 'preshared-key')
        if ($livePsk -ne $wantedPsk) {
            return [pscustomobject]@{ Match = $false; Reason = 'PresharedKey текущего peer не совпадает.' }
        }
    }

    $wantedKeepalive = (Get-WireGuardConfigValue -Map $Config.Peers[0] -Name 'PersistentKeepalive').Trim()
    if (-not [string]::IsNullOrWhiteSpace($wantedKeepalive)) {
        $keepaliveNode = Get-NamedPropertyValue -Object $peer -Name 'keepalive-interval'
        $liveKeepalive = [string](Get-NamedPropertyValue -Object $keepaliveNode -Name 'interval')
        if ($liveKeepalive -ne $wantedKeepalive) {
            return [pscustomobject]@{ Match = $false; Reason = 'PersistentKeepalive текущего peer не совпадает.' }
        }
    }

    if ($Config.IsAmnezia) {
        $wg = Get-NamedPropertyValue -Object $live -Name 'wireguard'
        $asc = Get-NamedPropertyValue -Object $wg -Name 'asc'
        if ($null -eq $asc) { return [pscustomobject]@{ Match = $false; Reason = 'На роутере нет ASC.' } }
        foreach ($name in @('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4')) {
            $wantedValue = (Get-WireGuardConfigValue -Map $Config.Interface -Name $name).Trim()
            if ([string]::IsNullOrWhiteSpace($wantedValue)) { continue }
            $liveValue = [string](Get-NamedPropertyValue -Object $asc -Name $name.ToLowerInvariant())
            if ($liveValue -ne $wantedValue) {
                return [pscustomobject]@{ Match = $false; Reason = "ASC $name не совпадает: Keenetic='$liveValue', conf='$wantedValue'." }
            }
        }
    }

    return [pscustomobject]@{ Match = $true; Reason = 'Совпадает с текущим WireGuard.' }
}

function Apply-WireGuardConfigCore {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.ArrayList]$Warnings
    )

    if ($InterfaceName -notmatch '^Wireguard\d+$') { throw "Некорректное имя интерфейса: $InterfaceName" }

    $before = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
    $oldKeys = @(Get-WireGuardPeerKeysFromRouterConfig -Config $before)
    if ($oldKeys.Count -gt 2) { throw 'На интерфейсе больше двух peer. Автоматическое обновление остановлено.' }

    $newKey = Get-WireGuardConfigValue -Map $Config.Peers[0] -Name 'PublicKey'
    $interfaceWasDisabled = $false
    try {
        Invoke-KeeneticRciChecked -Method POST -Path ("rci/interface/{0}" -f $InterfaceName) -Body @{ down = $true } -Description 'выключение WireGuard перед обновлением' | Out-Null
        $interfaceWasDisabled = $true

        # ВАЖНО: новый peer сначала создаётся через JSON RCI БЕЗ AllowedIPs.
        # Старый peer на этом этапе не удаляется.
        Stage-WireGuardPeerWithoutAllowedIps -InterfaceName $InterfaceName -PeerMap $Config.Peers[0]

        $afterStage = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
        $stageKeys = @(Get-WireGuardPeerKeysFromRouterConfig -Config $afterStage)
        foreach ($oldKey in $oldKeys) {
            if ($oldKey -ne $newKey -and -not ($stageKeys -contains $oldKey)) {
                throw 'Keenetic неожиданно удалил старый peer при подготовке нового. Запускаем rollback.'
            }
        }

        $address = Get-WireGuardConfigValue -Map $Config.Interface -Name 'Address'
        Set-WireGuardInterfaceAddresses -InterfaceName $InterfaceName -AddressText $address -Warnings $Warnings

        $mtuText = Get-WireGuardConfigValue -Map $Config.Interface -Name 'MTU'
        if (-not [string]::IsNullOrWhiteSpace($mtuText)) {
            $mtu = 0
            if (-not [int]::TryParse($mtuText.Trim(), [ref]$mtu) -or $mtu -lt 576 -or $mtu -gt 9000) {
                throw "Некорректный MTU: $mtuText"
            }
            Invoke-KeeneticCliCommand -Command "interface $InterfaceName ip mtu $mtu" -Description 'MTU WireGuard' | Out-Null
        }

        $listenPortText = Get-WireGuardConfigValue -Map $Config.Interface -Name 'ListenPort'
        if (-not [string]::IsNullOrWhiteSpace($listenPortText)) {
            $listenPort = 0
            if (-not [int]::TryParse($listenPortText.Trim(), [ref]$listenPort) -or $listenPort -lt 1 -or $listenPort -gt 65535) {
                throw "Некорректный ListenPort: $listenPortText"
            }
            Invoke-KeeneticCliCommand -Command "interface $InterfaceName wireguard listen-port $listenPort" -Description 'ListenPort WireGuard' | Out-Null
        }

        Set-WireGuardAscFromConfig -InterfaceName $InterfaceName -Config $Config -Warnings $Warnings

        # PrivateKey меняется только после успешной подготовки peer/адресов/ASC.
        $privateKey = Get-WireGuardConfigValue -Map $Config.Interface -Name 'PrivateKey'
        $quotedPrivateKey = Quote-KeeneticCliArgument -Value $privateKey
        Invoke-KeeneticCliCommand -Command "interface $InterfaceName wireguard private-key $quotedPrivateKey" -Description 'private key WireGuard' | Out-Null

        Set-WireGuardAllowedIps -InterfaceName $InterfaceName -PeerMap $Config.Peers[0]
        Connect-WireGuardPeer -InterfaceName $InterfaceName -Key $newKey
        Assert-WireGuardPeerMatchesConfig -InterfaceName $InterfaceName -PeerMap $Config.Peers[0]

        # Только теперь удаляем старый peer, если PublicKey изменился.
        foreach ($oldKey in $oldKeys) {
            if ($oldKey -ne $newKey) { Remove-WireGuardPeer -InterfaceName $InterfaceName -Key $oldKey }
        }

        $finalConfig = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
        $finalKeys = @(Get-WireGuardPeerKeysFromRouterConfig -Config $finalConfig)
        if ($finalKeys.Count -ne 1 -or $finalKeys[0] -ne $newKey) {
            throw 'После обновления набор peer не прошёл финальную проверку.'
        }

        Invoke-KeeneticRciChecked -Method POST -Path ("rci/interface/{0}" -f $InterfaceName) -Body @{ up = $true } -Description 'включение WireGuard' | Out-Null
        $interfaceWasDisabled = $false
    }
    finally {
        if ($interfaceWasDisabled) {
            try { Invoke-KeeneticRci -Method POST -Path ("rci/interface/{0}" -f $InterfaceName) -Body @{ up = $true } | Out-Null }
            catch {}
        }
    }
}

function Restore-WireGuardFromBaseline {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$BaselineConfig,
        [object]$RouterConfigBefore
    )

    # Если рабочий .conf не содержал MTU, всё равно восстанавливаем фактический MTU,
    # который был на Keenetic до обновления.
    if ($null -ne $RouterConfigBefore -and
        [string]::IsNullOrWhiteSpace((Get-WireGuardConfigValue -Map $BaselineConfig.Interface -Name 'MTU'))) {
        $oldIp = Get-NamedPropertyValue -Object $RouterConfigBefore -Name 'ip'
        $oldMtu = [string](Get-NamedPropertyValue -Object $oldIp -Name 'mtu')
        if (-not [string]::IsNullOrWhiteSpace($oldMtu)) { $BaselineConfig.Interface['MTU'] = $oldMtu }
    }

    $warnings = New-Object System.Collections.ArrayList
    Apply-WireGuardConfigCore -InterfaceName $InterfaceName -Config $BaselineConfig -Warnings $warnings
    Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение rollback-конфигурации' | Out-Null
    $check = Test-WireGuardConfigMatchesRouter -InterfaceName $InterfaceName -Config $BaselineConfig
    if (-not $check.Match) { throw "Rollback применён, но проверка не пройдена: $($check.Reason)" }
    return @($warnings)
}

function Apply-WireGuardConfigSafely {
    param(
        [Parameter(Mandatory)][string]$InterfaceName,
        [Parameter(Mandatory)][object]$Config,
        [ValidateSet('update','rollback')][string]$Operation = 'update'
    )

    $baseline = Get-WireGuardBaselineConfig -InterfaceName $InterfaceName
    if ($null -eq $baseline) {
        throw 'Нет rollback-базы. Сначала загрузите ТЕКУЩИЙ рабочий .conf и нажмите «Сделать rollback-базой».'
    }

    $baselineCheck = Test-WireGuardConfigMatchesRouter -InterfaceName $InterfaceName -Config $baseline
    if (-not $baselineCheck.Match) {
        throw "Rollback-база не соответствует текущему ${InterfaceName}: $($baselineCheck.Reason) Сначала сохраните текущий рабочий .conf как rollback-базу."
    }

    $routerConfig = Get-WireGuardInterfaceConfig -InterfaceName $InterfaceName
    $backup = Save-WireGuardSafetyBackup -InterfaceName $InterfaceName -RouterConfig $routerConfig -BaselineConfig $baseline -Operation $Operation
    Write-Log "WireGuard: полный safety-backup $InterfaceName -> $($backup.Folder)"

    $warnings = New-Object System.Collections.ArrayList
    try {
        Apply-WireGuardConfigCore -InterfaceName $InterfaceName -Config $Config -Warnings $warnings

        # Проверка маршрутов выполняется ДО system configuration save.
        $runningAfter = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
        [IO.File]::WriteAllText((Join-Path $backup.Folder 'running-config-after.txt'), $runningAfter, [Text.Encoding]::UTF8)
        $routesAfter = @(Get-WireGuardRouteLines -ConfigText $runningAfter -InterfaceName $InterfaceName)
        [IO.File]::WriteAllLines((Join-Path $backup.Folder ("{0}-routes-after.txt" -f $InterfaceName)), $routesAfter, [Text.Encoding]::UTF8)

        if (($backup.RoutesBefore -join "`n") -ne ($routesAfter -join "`n")) {
            throw "Маршруты $InterfaceName изменились во время обновления. Сохранение startup-config ЗАПРЕЩЕНО; запускаем rollback. До: $($backup.RoutesBefore.Count), после: $($routesAfter.Count)."
        }

        Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение проверенной конфигурации Keenetic' | Out-Null
        Save-WireGuardBaselineConfig -InterfaceName $InterfaceName -Config $Config | Out-Null
        Mark-WireGuardSafetyBackupSuccess -Folder $backup.Folder -Operation $Operation

        Write-Log "WireGuard: $InterfaceName безопасно обновлён из $($Config.FileName); маршруты совпали ($($routesAfter.Count)); операция=$Operation."
        return [pscustomobject]@{
            BackupFolder = $backup.Folder
            Warnings = @($warnings)
            RouteCount = $routesAfter.Count
            Operation = $Operation
        }
    }
    catch {
        $originalError = $_.Exception.Message
        Write-Log "WireGuard: ошибка безопасного обновления ${InterfaceName}: $originalError"
        try {
            $rollbackWarnings = @(Restore-WireGuardFromBaseline -InterfaceName $InterfaceName -BaselineConfig $baseline -RouterConfigBefore $routerConfig)
            Write-Log "WireGuard: автоматический rollback $InterfaceName успешно завершён."
            throw "Обновление отменено: $originalError`r`n`r`nАвтоматический rollback выполнен успешно.`r`nПолный бэкап: $($backup.Folder)"
        }
        catch {
            $rollbackError = $_.Exception.Message
            if ($rollbackError -like 'Обновление отменено:*') { throw }
            Write-Log "WireGuard: ОШИБКА rollback ${InterfaceName}: $rollbackError"
            throw "Обновление завершилось ошибкой: $originalError`r`n`r`nАВТОМАТИЧЕСКИЙ ROLLBACK НЕ УДАЛСЯ: $rollbackError`r`n`r`nНЕ нажимайте Save в Keenetic. Полный startup-config до изменений лежит здесь:`r`n$($backup.StartupPath)"
        }
    }
}

function Get-WireGuardConfigTypeText {
    param([object]$Config)
    if ($null -eq $Config) { return '—' }
    if ($Config.IsAmnezia2) { return 'AmneziaWG 2.0 / extended ASC' }
    if ($Config.IsAmnezia) { return 'AmneziaWG / ASC' }
    return 'WireGuard'
}

function Get-WireGuardPreviewText {
    param([Parameter(Mandatory)][object]$Config)

    $peer = $Config.Peers[0]
    $address = Get-WireGuardConfigValue -Map $Config.Interface -Name 'Address' -Default '—'
    $endpoint = Get-WireGuardConfigValue -Map $peer -Name 'Endpoint' -Default '—'
    $allowed = Get-WireGuardConfigValue -Map $peer -Name 'AllowedIPs' -Default '—'
    $dns = Get-WireGuardConfigValue -Map $Config.Interface -Name 'DNS' -Default '—'
    $mtu = Get-WireGuardConfigValue -Map $Config.Interface -Name 'MTU' -Default 'не задан — оставим текущий'

    $asc = 'нет'
    if ($Config.IsAmnezia) {
        $ascParts = @()
        foreach ($name in @('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4','I1','I2','I3','I4','I5')) {
            $value = Get-WireGuardConfigValue -Map $Config.Interface -Name $name
            if (-not [string]::IsNullOrWhiteSpace($value)) { $ascParts += "$name=$value" }
        }
        $asc = $ascParts -join '; '
    }

    return @(
        "Файл: $($Config.FileName)",
        "Тип: $(Get-WireGuardConfigTypeText -Config $Config)",
        "Address: $address",
        "MTU: $mtu",
        "Endpoint: $endpoint",
        "AllowedIPs: $allowed",
        'PrivateKey / PublicKey: найдены ✓',
        "ASC: $asc",
        "DNS из файла: $dns (НЕ применяем)",
        'Перед обновлением: startup + running + routes + DPAPI rollback',
        'Старый peer удаляется ТОЛЬКО после проверки нового'
    ) -join "`r`n"
}

function Test-WireGuardBaselineExists {
    param([Parameter(Mandatory)][string]$InterfaceName)
    $path = Get-WireGuardBaselinePath -InterfaceName $InterfaceName
    return (Test-Path -LiteralPath $path -PathType Leaf) -and (Test-WireGuardBaselineRouterMatch -InterfaceName $InterfaceName)
}

function Update-WireGuardUiState {
    if ($null -eq $wireGuardApplyButton) { return }
    $interfaceName = [string]$wireGuardInterfaceCombo.SelectedItem
    $hasConfig = $null -ne $script:LoadedWireGuardConfig
    $hasInterface = -not [string]::IsNullOrWhiteSpace($interfaceName)
    $hasBaseline = $false
    if ($hasInterface) { $hasBaseline = Test-WireGuardBaselineExists -InterfaceName $interfaceName }

    $wireGuardApplyButton.Enabled = $hasConfig -and $hasInterface -and $hasBaseline
    if ($null -ne $wireGuardBaselineButton) { $wireGuardBaselineButton.Enabled = $hasConfig -and $hasInterface }
    if ($null -ne $wireGuardRollbackButton) {
        $wireGuardRollbackButton.Enabled = $false
        if ($hasInterface -and $hasBaseline) {
            try { $wireGuardRollbackButton.Enabled = $null -ne (Get-LatestWireGuardSuccessfulUpdateBackup -InterfaceName $interfaceName) }
            catch { $wireGuardRollbackButton.Enabled = $false }
        }
    }

    if ($hasInterface) {
        $baselineText = if ($hasBaseline) { 'Rollback: готов ✓' } else { 'Rollback: НЕ задан' }
        if ($null -ne $wireGuardBaselineStateLabel) {
            $wireGuardBaselineStateLabel.Text = $baselineText
            $wireGuardBaselineStateLabel.ForeColor = if ($hasBaseline) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::DarkOrange }
        }
    }
}

function Refresh-WireGuardInterfaces {
    if ($null -eq $wireGuardInterfaceCombo) { return }
    $previous = [string]$wireGuardInterfaceCombo.SelectedItem
    $wireGuardInterfaceCombo.Items.Clear()

    try {
        foreach ($name in (Get-WireGuardInterfaceNames)) { [void]$wireGuardInterfaceCombo.Items.Add($name) }
        if ($wireGuardInterfaceCombo.Items.Count -eq 0) {
            $wireGuardStatusLabel.Text = 'WireGuard-интерфейсы не найдены или Keenetic недоступен.'
            Update-WireGuardUiState
            return
        }
        $targetIndex = 0
        if (-not [string]::IsNullOrWhiteSpace($previous)) {
            $foundIndex = $wireGuardInterfaceCombo.Items.IndexOf($previous)
            if ($foundIndex -ge 0) { $targetIndex = $foundIndex }
        }
        $wireGuardInterfaceCombo.SelectedIndex = $targetIndex
        Update-WireGuardUiState
        Update-WireGuardRuntimeStatusLabel
    }
    catch {
        Close-KeeneticSession
        $wireGuardStatusLabel.Text = "Ошибка чтения Keenetic: $($_.Exception.Message)"
        Update-WireGuardUiState
    }
}

function Load-WireGuardConfigPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$RequireConfExtension
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Путь к конфигу пуст.' }
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) { throw "Файл не найден: $resolvedPath" }
        if ($RequireConfExtension -and -not [string]::Equals([System.IO.Path]::GetExtension($resolvedPath),'.conf',[System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Для Drag & Drop перетащите файл с расширением .conf.'
        }

        $config = Read-WireGuardConfigFile -Path $resolvedPath
        $script:LoadedWireGuardConfig = $config
        $script:LoadedWireGuardConfigPath = $resolvedPath
        $wireGuardConfigPathBox.Text = $resolvedPath
        $wireGuardPreviewBox.Text = Get-WireGuardPreviewText -Config $config
        $wireGuardStatusLabel.Text = "Конфиг загружен: $(Get-WireGuardConfigTypeText -Config $config)."
        $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DimGray
        Update-WireGuardUiState
        return $true
    }
    catch {
        $script:LoadedWireGuardConfig = $null
        $script:LoadedWireGuardConfigPath = $null
        Update-WireGuardUiState
        $wireGuardStatusLabel.Text = "Ошибка конфига: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Не удалось открыть конфиг:`r`n$($_.Exception.Message)",$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return $false
    }
}

function Select-WireGuardConfigFile {
    $dialog = [System.Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = 'Выберите WireGuard / AmneziaWG конфиг'
    $dialog.Filter = 'WireGuard / AmneziaWG (*.conf)|*.conf|Все файлы (*.*)|*.*'
    $dialog.CheckFileExists = $true
    $dialog.Multiselect = $false
    try {
        if ($dialog.ShowDialog($mainForm) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        [void](Load-WireGuardConfigPath -Path $dialog.FileName)
    }
    finally { $dialog.Dispose() }
}

function Handle-WireGuardDragEnter {
    param($Sender, $EventArgs)
    try {
        if ($EventArgs.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $files = @($EventArgs.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
            if ($files.Count -gt 0 -and [string]::Equals([System.IO.Path]::GetExtension([string]$files[0]),'.conf',[System.StringComparison]::OrdinalIgnoreCase)) {
                $EventArgs.Effect = [System.Windows.Forms.DragDropEffects]::Copy
                return
            }
        }
    }
    catch {}
    $EventArgs.Effect = [System.Windows.Forms.DragDropEffects]::None
}

function Handle-WireGuardDragDrop {
    param($Sender, $EventArgs)
    try {
        if (-not $EventArgs.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { return }
        $files = @($EventArgs.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
        if ($files.Count -eq 0) { return }
        if ($files.Count -gt 1) {
            [System.Windows.Forms.MessageBox]::Show('Перетащите один .conf за раз.',$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }
        [void](Load-WireGuardConfigPath -Path ([string]$files[0]) -RequireConfExtension)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Не удалось обработать файл:`r`n$($_.Exception.Message)",$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function Save-LoadedWireGuardAsBaseline {
    if ($null -eq $script:LoadedWireGuardConfig) {
        [System.Windows.Forms.MessageBox]::Show('Сначала загрузите ТЕКУЩИЙ рабочий .conf.',$AppName) | Out-Null
        return
    }
    $interfaceName = [string]$wireGuardInterfaceCombo.SelectedItem
    if ([string]::IsNullOrWhiteSpace($interfaceName)) { return }

    try {
        $match = Test-WireGuardConfigMatchesRouter -InterfaceName $interfaceName -Config $script:LoadedWireGuardConfig
        if (-not $match.Match) {
            throw "Этот .conf НЕ похож на текущую конфигурацию ${interfaceName}: $($match.Reason)"
        }
        Save-WireGuardBaselineConfig -InterfaceName $interfaceName -Config $script:LoadedWireGuardConfig | Out-Null
        Update-WireGuardUiState
        $wireGuardStatusLabel.Text = "Rollback-база $interfaceName сохранена через Windows DPAPI."
        [System.Windows.Forms.MessageBox]::Show(
            "Готово. Этот .conf сохранён как текущая rollback-база для $interfaceName.`r`n`r`nPrivateKey хранится локально в зашифрованном виде Windows DPAPI.",
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Rollback-база НЕ сохранена:`r`n$($_.Exception.Message)",'WireGuard / AmneziaWG',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function Restore-KeeneticStartupConfigFile {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 200) { throw 'Файл startup-config слишком маленький.' }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -notmatch '(?m)^interface\s+' -and $text -notmatch '(?m)^system\s+') {
        throw 'Файл не похож на startup-config Keenetic.'
    }

    $putResult = Invoke-KeeneticRciChecked -Method POST -Path 'rci/' -Body @{ put = @{ filename = 'flash:startup-config'; size = $bytes.Length } } -Description 'подготовка загрузки startup-config'
    $put = Get-NamedPropertyValue -Object $putResult -Name 'put'
    $portNode = Get-NamedPropertyValue -Object $put -Name 'port'
    $port = [string](Get-NamedPropertyValue -Object $portNode -Name 'port')
    if ([string]::IsNullOrWhiteSpace($port)) { throw 'Keenetic не вернул порт для загрузки startup-config.' }

    $session = Get-KeeneticSession
    $multipart = [System.Net.Http.MultipartFormDataContent]::new()
    $fileContent = [System.Net.Http.ByteArrayContent]::new($bytes)
    $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('text/plain')
    $multipart.Add($fileContent, 'Filedata', 'startup-config.txt')
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, 'fui/')
    $request.Headers.Add('port', $port)
    $request.Content = $multipart

    try {
        $response = $session.Client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $response.IsSuccessStatusCode) { throw "Загрузка startup-config: HTTP $([int]$response.StatusCode). $body" }
        }
        finally { $response.Dispose() }
    }
    finally {
        $request.Dispose()
        $multipart.Dispose()
    }

    Invoke-KeeneticRciChecked -Method POST -Path 'rci/' -Body @{ system = @{ reboot = @{} } } -Description 'перезагрузка после восстановления startup-config' | Out-Null
}

function Select-AndRestoreStartupBackup {
    $dialog = [System.Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = 'Выберите startup-config.txt из safety-backup'
    $dialog.Filter = 'Keenetic startup-config (startup-config.txt)|startup-config.txt|Text (*.txt)|*.txt'
    $dialog.CheckFileExists = $true
    try {
        if ($dialog.ShowDialog($mainForm) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Восстановить ВЕСЬ startup-config из:`r`n$($dialog.FileName)`r`n`r`nРоутер будет перезагружен. Это откатит маршруты и остальные настройки из файла. PrivateKey WireGuard в startup-config не хранится — для него используется отдельная rollback-база.",
            'Восстановление Keenetic',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        Restore-KeeneticStartupConfigFile -Path $dialog.FileName
        [System.Windows.Forms.MessageBox]::Show('startup-config загружен. Keenetic перезагружается.',$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Не удалось восстановить startup-config:`r`n$($_.Exception.Message)",$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
    finally { $dialog.Dispose() }
}


function Start-WireGuardLastUpdateRollback {
    $interfaceName = [string]$wireGuardInterfaceCombo.SelectedItem
    if ([string]::IsNullOrWhiteSpace($interfaceName)) {
        [System.Windows.Forms.MessageBox]::Show('Выберите WireGuard-интерфейс.',$AppName) | Out-Null
        return
    }

    $backupInfo = Get-LatestWireGuardSuccessfulUpdateBackup -InterfaceName $interfaceName
    if ($null -eq $backupInfo) {
        [System.Windows.Forms.MessageBox]::Show(
            'Нет последнего успешного обновления, доступного для быстрого отката.',
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        Update-WireGuardUiState
        return
    }

    try {
        $targetConfig = Read-WireGuardDpapiConfig -Path $backupInfo.RollbackPath -InterfaceName $interfaceName
        $targetPeer = $targetConfig.Peers[0]
        $targetEndpoint = Get-WireGuardConfigValue -Map $targetPeer -Name 'Endpoint' -Default '—'
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "Откатить ПОСЛЕДНЕЕ успешное обновление $interfaceName?`r`n`r`nВернём конфиг, который был до обновления.`r`nEndpoint: $targetEndpoint`r`nSafety-backup: $($backupInfo.Folder)`r`n`r`nПеред откатом программа ещё раз сохранит ТЕКУЩЕЕ состояние и проверит маршруты.",
            'Откат последнего WireGuard-обновления',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $wireGuardApplyButton.Enabled = $false
        $wireGuardRollbackButton.Enabled = $false
        $wireGuardRefreshButton.Enabled = $false
        $wireGuardBrowseButton.Enabled = $false
        $wireGuardBaselineButton.Enabled = $false
        $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DimGray
        $wireGuardStatusLabel.Text = "Safety backup + откат $interfaceName…"
        [System.Windows.Forms.Application]::DoEvents()

        $result = Apply-WireGuardConfigSafely -InterfaceName $interfaceName -Config $targetConfig -Operation 'rollback'
        Mark-WireGuardUpdateBackupRolledBack -Folder $backupInfo.Folder

        $key = Get-WireGuardConfigValue -Map $targetPeer -Name 'PublicKey'
        $runtime = $null
        try { $runtime = Wait-WireGuardRuntimeStatus -InterfaceName $interfaceName -PublicKey $key }
        catch { Write-Log "WireGuard: статус после rollback недоступен: $($_.Exception.Message)" }

        if ($null -ne $runtime) {
            $wireGuardStatusLabel.Text = Format-WireGuardRuntimeStatus -Runtime $runtime -RouteCount $result.RouteCount
            $wireGuardStatusLabel.ForeColor = if ($runtime.Online) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::DarkOrange }
        }
        else {
            $wireGuardStatusLabel.Text = "$interfaceName откатан. Маршруты проверены: $($result.RouteCount)."
        }

        $runtimeText = if ($null -ne $runtime) { "`r`n`r`n" + (Format-WireGuardRuntimeStatus -Runtime $runtime -RouteCount $result.RouteCount) } else { '' }
        [System.Windows.Forms.MessageBox]::Show(
            "Готово. Последнее обновление $interfaceName откатано.`r`nМаршруты до/после совпали.`r`nПеред откатом также создан новый safety-backup:`r`n$($result.BackupFolder)$runtimeText",
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
    catch {
        Close-KeeneticSession
        $wireGuardStatusLabel.Text = "Откат не выполнен: $($_.Exception.Message)"
        $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::Firebrick
        [System.Windows.Forms.MessageBox]::Show(
            "Не удалось откатить последнее обновление:`r`n$($_.Exception.Message)",
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
    finally {
        $wireGuardRefreshButton.Enabled = $true
        $wireGuardBrowseButton.Enabled = $true
        Update-WireGuardUiState
    }
}

function Start-WireGuardConfigUpdate {
    if ($null -eq $script:LoadedWireGuardConfig) {
        [System.Windows.Forms.MessageBox]::Show('Сначала выберите НОВЫЙ .conf файл.',$AppName) | Out-Null
        return
    }

    $interfaceName = [string]$wireGuardInterfaceCombo.SelectedItem
    if ([string]::IsNullOrWhiteSpace($interfaceName)) {
        [System.Windows.Forms.MessageBox]::Show('Выберите существующий WireGuard-интерфейс.',$AppName) | Out-Null
        return
    }

    if (-not (Test-WireGuardBaselineExists -InterfaceName $interfaceName)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Сначала нужна rollback-база.`r`n`r`n1. Загрузите ТЕКУЩИЙ рабочий .conf для $interfaceName.`r`n2. Нажмите «Сделать rollback-базой».`r`n3. Затем загрузите новый .conf и обновляйте.",
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }

    try {
        $baseline = Get-WireGuardBaselineConfig -InterfaceName $interfaceName
        $baselineCheck = Test-WireGuardConfigMatchesRouter -InterfaceName $interfaceName -Config $baseline
        if (-not $baselineCheck.Match) { throw "Rollback-база устарела: $($baselineCheck.Reason)" }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Обновление запрещено:`r`n$($_.Exception.Message)`r`n`r`nСохраните текущий рабочий .conf как rollback-базу.",'WireGuard / AmneziaWG',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }

    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Безопасно обновить $interfaceName из '$($script:LoadedWireGuardConfig.FileName)'?`r`n`r`nПеред изменениями программа скачает startup-config + running-config, сохранит маршруты и DPAPI rollback.`r`nСтарый peer не удаляется, пока новый полностью не проверен.`r`nПри ошибке выполняется автоматический rollback.",
        'WireGuard / AmneziaWG',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $wireGuardApplyButton.Enabled = $false
    $wireGuardRefreshButton.Enabled = $false
    $wireGuardBrowseButton.Enabled = $false
    $wireGuardBaselineButton.Enabled = $false
    $wireGuardStatusLabel.Text = "Safety backup + обновление $interfaceName…"
    [System.Windows.Forms.Application]::DoEvents()

    try {
        $result = Apply-WireGuardConfigSafely -InterfaceName $interfaceName -Config $script:LoadedWireGuardConfig -Operation 'update'
        $warningText = ''
        if ($result.Warnings.Count -gt 0) { $warningText = "`r`n`r`nПредупреждения:`r`n- " + ($result.Warnings -join "`r`n- ") }

        $newPeerKey = Get-WireGuardConfigValue -Map $script:LoadedWireGuardConfig.Peers[0] -Name 'PublicKey'
        $runtime = $null
        try { $runtime = Wait-WireGuardRuntimeStatus -InterfaceName $interfaceName -PublicKey $newPeerKey }
        catch { Write-Log "WireGuard: статус после обновления недоступен: $($_.Exception.Message)" }

        if ($null -ne $runtime) {
            $wireGuardStatusLabel.Text = Format-WireGuardRuntimeStatus -Runtime $runtime -RouteCount $result.RouteCount
            $wireGuardStatusLabel.ForeColor = if ($runtime.Online) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::DarkOrange }
        }
        else {
            $wireGuardStatusLabel.Text = "$interfaceName обновлён. Маршруты проверены: $($result.RouteCount). Handshake: нет данных."
            $wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        }

        $runtimeText = if ($null -ne $runtime) { "`r`n`r`n" + (Format-WireGuardRuntimeStatus -Runtime $runtime -RouteCount $result.RouteCount) } else { '' }
        [System.Windows.Forms.MessageBox]::Show(
            "Готово. $interfaceName обновлён.`r`n`r`nМаршруты до/после совпали.`r`nПолный safety-backup:`r`n$($result.BackupFolder)$runtimeText$warningText",
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
    catch {
        Close-KeeneticSession
        $wireGuardStatusLabel.Text = "Обновление отменено: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'WireGuard / AmneziaWG',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
    finally {
        $wireGuardRefreshButton.Enabled = $true
        $wireGuardBrowseButton.Enabled = $true
        Update-WireGuardUiState
    }
}


function Show-KeeneticCredentialDialog {
    $dialog = [System.Windows.Forms.Form]::new()
    $dialog.Text = 'Доступ к Keenetic'
    $dialog.ClientSize = [System.Drawing.Size]::new(500, 310)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.StartPosition = 'CenterParent'

    $info = [System.Windows.Forms.Label]::new()
    $info.Text = 'Укажите локальный адрес роутера и данные администратора Keenetic.'
    $info.Location = [System.Drawing.Point]::new(20, 16)
    $info.Size = [System.Drawing.Size]::new(455, 30)
    $dialog.Controls.Add($info)

    $addressLabel = [System.Windows.Forms.Label]::new()
    $addressLabel.Text = 'Адрес роутера:'
    $addressLabel.AutoSize = $true
    $addressLabel.Location = [System.Drawing.Point]::new(22, 58)
    $dialog.Controls.Add($addressLabel)

    $addressBox = [System.Windows.Forms.TextBox]::new()
    $addressBox.Location = [System.Drawing.Point]::new(125, 54)
    $addressBox.Size = [System.Drawing.Size]::new(350, 27)
    $addressBox.Text = $script:RouterBaseUrl
    $dialog.Controls.Add($addressBox)

    $addressHint = [System.Windows.Forms.Label]::new()
    $addressHint.Text = "Пример: http://192.168.1.1:8080/`r`nМожно также: http://192.168.1.1/ или 192.168.1.1:8080"
    $addressHint.Font = [System.Drawing.Font]::new('Segoe UI', 8)
    $addressHint.ForeColor = [System.Drawing.Color]::DimGray
    $addressHint.Location = [System.Drawing.Point]::new(125, 84)
    $addressHint.Size = [System.Drawing.Size]::new(350, 40)
    $dialog.Controls.Add($addressHint)

    $loginLabel = [System.Windows.Forms.Label]::new()
    $loginLabel.Text = 'Логин:'
    $loginLabel.AutoSize = $true
    $loginLabel.Location = [System.Drawing.Point]::new(22, 142)
    $dialog.Controls.Add($loginLabel)

    $loginBox = [System.Windows.Forms.TextBox]::new()
    $loginBox.Location = [System.Drawing.Point]::new(125, 138)
    $loginBox.Size = [System.Drawing.Size]::new(350, 27)
    $loginBox.Text = 'admin'
    $dialog.Controls.Add($loginBox)

    if (Test-Path -LiteralPath $CredentialPath) {
        try { $loginBox.Text = (Import-Clixml -LiteralPath $CredentialPath).UserName } catch {}
    }

    $passwordLabel = [System.Windows.Forms.Label]::new()
    $passwordLabel.Text = 'Пароль:'
    $passwordLabel.AutoSize = $true
    $passwordLabel.Location = [System.Drawing.Point]::new(22, 182)
    $dialog.Controls.Add($passwordLabel)

    $passwordBox = [System.Windows.Forms.TextBox]::new()
    $passwordBox.Location = [System.Drawing.Point]::new(125, 178)
    $passwordBox.Size = [System.Drawing.Size]::new(350, 27)
    $passwordBox.UseSystemPasswordChar = $true
    $dialog.Controls.Add($passwordBox)

    $saveInfo = [System.Windows.Forms.Label]::new()
    $saveInfo.Text = 'Адрес и логин сохраняются для следующих запусков. Пароль хранится через Windows DPAPI.'
    $saveInfo.Font = [System.Drawing.Font]::new('Segoe UI', 8)
    $saveInfo.ForeColor = [System.Drawing.Color]::DimGray
    $saveInfo.Location = [System.Drawing.Point]::new(22, 216)
    $saveInfo.Size = [System.Drawing.Size]::new(450, 30)
    $dialog.Controls.Add($saveInfo)

    $cancelButton = [System.Windows.Forms.Button]::new()
    $cancelButton.Text = 'Отмена'
    $cancelButton.Size = [System.Drawing.Size]::new(110, 36)
    $cancelButton.Location = [System.Drawing.Point]::new(168, 258)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.Controls.Add($cancelButton)

    $saveButton = [System.Windows.Forms.Button]::new()
    $saveButton.Text = 'Сохранить и проверить'
    $saveButton.Size = [System.Drawing.Size]::new(185, 36)
    $saveButton.Location = [System.Drawing.Point]::new(290, 258)
    $dialog.Controls.Add($saveButton)
    $dialog.AcceptButton = $saveButton
    $dialog.CancelButton = $cancelButton

    $saveButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($addressBox.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Введите адрес роутера. Пример: http://192.168.1.1:8080/',$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            $addressBox.Focus()
            return
        }
        if ([string]::IsNullOrWhiteSpace($loginBox.Text) -or [string]::IsNullOrWhiteSpace($passwordBox.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Введите логин и пароль.',$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }

        try {
            $newRouterUrl = Normalize-KeeneticBaseUrl -Value $addressBox.Text
            $securePassword = ConvertTo-SecureString $passwordBox.Text -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new($loginBox.Text.Trim(),$securePassword)

            # Сначала проверяем новые данные, ничего не перезаписывая на диске.
            Close-KeeneticSession
            $script:RciSession = New-KeeneticSession -Credential $credential -BaseUrl $newRouterUrl
            $names = @(Get-WireGuardInterfaceNames)

            # Только после успешной проверки сохраняем настройки.
            $credential | Export-Clixml -LiteralPath $CredentialPath
            Set-Content -LiteralPath $RouterUrlPath -Value $newRouterUrl -Encoding UTF8
            $script:RouterBaseUrl = $newRouterUrl

            [System.Windows.Forms.MessageBox]::Show(
                "Доступ проверен.`r`nАдрес: $newRouterUrl`r`nНайдено WireGuard-интерфейсов: $($names.Count).",
                $AppName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            $dialog.Close()
            Refresh-WireGuardInterfaces
        }
        catch {
            Close-KeeneticSession
            [System.Windows.Forms.MessageBox]::Show("Не удалось подключиться к Keenetic:`r`n$($_.Exception.Message)",$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })
    [void]$dialog.ShowDialog($mainForm)
}


# ---------------- STATIC ROUTES MANAGER ----------------
function Convert-Ipv4MaskToPrefix {
    param([Parameter(Mandatory)][string]$Mask)
    $parts = $Mask.Trim().Split('.')
    if ($parts.Count -ne 4) { return -1 }
    $bits = ''
    foreach ($part in $parts) {
        $n = 0
        if (-not [int]::TryParse($part,[ref]$n) -or $n -lt 0 -or $n -gt 255) { return -1 }
        $bits += [Convert]::ToString($n,2).PadLeft(8,'0')
    }
    if ($bits -notmatch '^1*0*$') { return -1 }
    return @($bits.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

function Split-KeeneticRouteComment {
    param([Parameter(Mandatory)][string]$Line)
    $text = $Line.Trim()
    $idx = $text.IndexOf(' !',[StringComparison]::Ordinal)
    if ($idx -ge 0) {
        return [pscustomobject]@{
            Command = $text.Substring(0,$idx).Trim()
            Comment = $text.Substring($idx + 2).Trim()
        }
    }
    return [pscustomobject]@{ Command = $text; Comment = '' }
}

function Normalize-KeeneticRouteCommand {
    param([Parameter(Mandatory)][string]$Line)
    $split = Split-KeeneticRouteComment -Line $Line
    return (($split.Command -replace '\s+',' ').Trim()).ToLowerInvariant()
}

function Get-KeeneticRouteDeleteCommand {
    param([Parameter(Mandatory)][string]$RouteLine)
    $split = Split-KeeneticRouteComment -Line $RouteLine
    $command = ($split.Command -replace '\s+',' ').Trim()
    if ($command -notmatch '^(?i)(ip|ipv6)\s+route\s+') { throw "Не похоже на статический маршрут: $RouteLine" }
    $command = $command -replace '(?i)\s+auto(?=\s|$)',''
    $command = $command -replace '(?i)\s+reject(?=\s|$)',''
    $command = ($command -replace '\s+',' ').Trim()
    return 'no ' + $command
}

function Get-KeeneticRouteIdentity {
    param([Parameter(Mandatory)][string]$Line)
    $split = Split-KeeneticRouteComment -Line $Line
    $command = ($split.Command -replace '\s+',' ').Trim()
    if ($command -match '^(?i)no\s+(?<rest>(?:ip|ipv6)\s+route\s+.+)$') {
        $command = $Matches.rest.Trim()
    }
    if ($command -notmatch '^(?i)(ip|ipv6)\s+route\s+') { return $command.ToLowerInvariant() }
    try {
        $delete = Get-KeeneticRouteDeleteCommand -RouteLine $command
        return (($delete -replace '^no\s+','' -replace '\s+',' ').Trim()).ToLowerInvariant()
    }
    catch { return $command.ToLowerInvariant() }
}

function Convert-RouteLineToRecord {
    param(
        [Parameter(Mandatory)][string]$Line,
        [int]$Index = 0,
        [bool]$Disabled = $false
    )
    $split = Split-KeeneticRouteComment -Line $Line
    $command = ($split.Command -replace '\s+',' ').Trim()
    if ($command -notmatch '^(?<family>ip|ipv6)\s+route\s+(?<rest>.+)$') { return $null }
    $family = $Matches.family.ToLowerInvariant()
    $rest = $Matches.rest.Trim()
    if ($rest -ieq 'disable') { return $null }
    $tokens = @($rest -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -lt 2) { return $null }

    $destination = $tokens[0]
    $cursor = 1
    if ($family -eq 'ip' -and $destination -ne 'default' -and $tokens.Count -gt 2) {
        $prefix = Convert-Ipv4MaskToPrefix -Mask $tokens[1]
        if ($prefix -ge 0) {
            $destination = "{0}/{1}" -f $tokens[0],$prefix
            $cursor = 2
        }
    }

    $auto = $false
    $reject = $false
    $viaParts = New-Object System.Collections.ArrayList
    for ($i=$cursor; $i -lt $tokens.Count; $i++) {
        $token = [string]$tokens[$i]
        if ($token -ieq 'auto') { $auto = $true; continue }
        if ($token -ieq 'reject') { $reject = $true; continue }
        if ($token -match '^\d+$' -and $i -eq ($tokens.Count - 1)) { continue }
        [void]$viaParts.Add($token)
    }
    $via = (@($viaParts) -join ' ')

    $familyText = 'IPv4'
    if ($family -eq 'ipv6') { $familyText = 'IPv6' }

    return [pscustomobject]@{
        Index = $Index
        Family = $familyText
        Destination = $destination
        Via = $via
        Auto = $auto
        Reject = $reject
        Disabled = $Disabled
        Comment = [string]$split.Comment
        RawLine = $Line.Trim()
        Command = $command
        DeleteCommand = Get-KeeneticRouteDeleteCommand -RouteLine $Line
    }
}

function Get-KeeneticStaticRoutesFromText {
    param([Parameter(Mandatory)][string]$ConfigText)
    $records = New-Object System.Collections.ArrayList
    $lastRecord = $null
    $index = 0
    foreach ($raw in ($ConfigText -split '\r?\n')) {
        $line = ([string]$raw).Trim()
        if ($line -match '^(?i)(ip|ipv6)\s+route\s+disable\s*$') {
            if ($null -ne $lastRecord) { $lastRecord.Disabled = $true }
            continue
        }
        if ($line -notmatch '^(?i)(ip|ipv6)\s+route\s+') { continue }
        $record = Convert-RouteLineToRecord -Line $line -Index $index
        if ($null -ne $record) {
            [void]$records.Add($record)
            $lastRecord = $record
            $index++
        }
    }
    return @($records)
}

function Get-KeeneticStaticRoutes {
    $running = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
    if ([string]::IsNullOrWhiteSpace($running) -or $running.Length -lt 200) {
        throw 'Keenetic вернул подозрительно пустой running-config.'
    }
    return @(Get-KeeneticStaticRoutesFromText -ConfigText $running)
}

function Test-Ipv4AddressText {
    param([string]$Text)
    $ip = $null
    return [Net.IPAddress]::TryParse($Text,[ref]$ip) -and $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
}

function Test-Ipv6AddressText {
    param([string]$Text)
    $ip = $null
    return [Net.IPAddress]::TryParse($Text,[ref]$ip) -and $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6
}

function New-KeeneticRouteAddCommand {
    param(
        [Parameter(Mandatory)][ValidateSet('IPv4','IPv6')][string]$Family,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Via,
        [bool]$Auto = $true,
        [bool]$Reject = $false,
        [string]$Comment = ''
    )
    $dest = $Destination.Trim()
    $viaText = $Via.Trim()
    if ([string]::IsNullOrWhiteSpace($dest)) { throw 'Укажите сеть/узел назначения.' }
    if ([string]::IsNullOrWhiteSpace($viaText)) { throw 'Укажите интерфейс или шлюз.' }
    if ($viaText -match '[\r\n!]') { throw 'Некорректный интерфейс/шлюз.' }

    if ($Family -eq 'IPv4') {
        if ($dest -ieq 'default') {
            $destCli = 'default'
        }
        elseif ($dest -match '/') {
            $parsed = Convert-Ipv4CidrToAddressMask -Cidr $dest
            $destCli = "{0} {1}" -f $parsed.Address,$parsed.Mask
        }
        elseif (Test-Ipv4AddressText -Text $dest) {
            $destCli = $dest
        }
        else { throw "Некорректный IPv4/CIDR: $dest" }
        $command = "ip route $destCli $viaText"
        if ($Auto) { $command += ' auto' }
        if ($Reject) { $command += ' reject' }
    }
    else {
        if ($dest -ieq 'default') { $destCli = 'default' }
        elseif ($dest -match '^(?<addr>[^/]+)/(?<prefix>\d{1,3})$') {
            if (-not (Test-Ipv6AddressText -Text $Matches.addr)) { throw "Некорректный IPv6: $($Matches.addr)" }
            $prefix = [int]$Matches.prefix
            if ($prefix -lt 0 -or $prefix -gt 128) { throw "Некорректный IPv6 prefix: $prefix" }
            $destCli = $dest
        }
        elseif (Test-Ipv6AddressText -Text $dest) { $destCli = "$dest/128" }
        else { throw "Некорректный IPv6/CIDR: $dest" }
        $command = "ipv6 route $destCli $viaText"
        if ($Auto) { $command += ' auto' }
        if ($Reject) { $command += ' reject' }
    }
    if (-not [string]::IsNullOrWhiteSpace($Comment)) {
        $cleanComment = ($Comment.Trim() -replace '[\r\n!]',' ')
        if (-not [string]::IsNullOrWhiteSpace($cleanComment)) { $command += " !$cleanComment" }
    }
    return $command
}

function Save-RouteSafetyBackup {
    param(
        [Parameter(Mandatory)][string]$Operation,
        [string[]]$Commands = @()
    )
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $folder = Join-Path $RouteBackupDir $stamp
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $startup = Invoke-KeeneticTextGet -Path 'ci/startup-config.txt'
    $running = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
    if ([string]::IsNullOrWhiteSpace($startup) -or $startup.Length -lt 200) { throw 'Не удалось получить полноценный startup-config перед изменением маршрутов.' }
    if ([string]::IsNullOrWhiteSpace($running) -or $running.Length -lt 200) { throw 'Не удалось получить полноценный running-config перед изменением маршрутов.' }
    [IO.File]::WriteAllText((Join-Path $folder 'startup-config.txt'),$startup,[Text.Encoding]::UTF8)
    [IO.File]::WriteAllText((Join-Path $folder 'running-config-before.txt'),$running,[Text.Encoding]::UTF8)
    [IO.File]::WriteAllLines((Join-Path $folder 'routes-before.txt'),@($running -split '\r?\n' | Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' }),[Text.Encoding]::UTF8)
    [IO.File]::WriteAllLines((Join-Path $folder 'requested-commands.txt'),@($Commands),[Text.Encoding]::UTF8)
    @{ operation=$Operation; router_url=$script:RouterBaseUrl; created=(Get-Date).ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'meta.json') -Encoding UTF8
    return [pscustomobject]@{ Folder=$folder; RunningBefore=$running }
}

function Test-RouteCommandPresent {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RouteLines,
        [Parameter(Mandatory)][string]$RouteCommand
    )
    $needle = Normalize-KeeneticRouteCommand -Line $RouteCommand
    foreach ($line in $RouteLines) {
        if ((Normalize-KeeneticRouteCommand -Line $line) -eq $needle) { return $true }
    }
    return $false
}

function Invoke-KeeneticRouteChangesSafely {
    param(
        [Parameter(Mandatory)][object[]]$Changes,
        [Parameter(Mandatory)][string]$OperationName
    )
    if ($Changes.Count -eq 0) { throw 'Нет изменений для применения.' }
    $commands = @($Changes | ForEach-Object { [string]$_.Command })
    $backup = Save-RouteSafetyBackup -Operation $OperationName -Commands $commands

    # Preflight: не допускаем дубликаты, удаления отсутствующих маршрутов и
    # противоречивые изменения до первой команды на роутере.
    $routeLinesBefore = @(
        $backup.RunningBefore -split '\r?\n' |
            Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' } |
            ForEach-Object { $_.Trim() }
    )
    $seenOperations = @{}
    foreach ($change in $Changes) {
        $expectedKey = Get-KeeneticRouteIdentity -Line ([string]$change.ExpectedLine)
        $opKey = ([string]$change.Action) + '|' + $expectedKey
        if ($seenOperations.ContainsKey($opKey)) {
            throw "В одной операции маршрут повторяется несколько раз: $($change.ExpectedLine)"
        }
        $seenOperations[$opKey] = $true
        $presentBefore = $false
        foreach ($existingLine in $routeLinesBefore) {
            if ((Get-KeeneticRouteIdentity -Line $existingLine) -eq $expectedKey) { $presentBefore = $true; break }
        }
        if ($change.Action -eq 'add' -and $presentBefore) {
            throw "Маршрут уже существует; импорт остановлен до изменений: $($change.ExpectedLine)"
        }
        if ($change.Action -eq 'delete' -and -not $presentBefore) {
            throw "Маршрут для удаления уже отсутствует; операция остановлена до изменений: $($change.ExpectedLine)"
        }
    }

    $applied = New-Object System.Collections.ArrayList
    try {
        foreach ($change in $Changes) {
            Invoke-KeeneticCliCommand -Command ([string]$change.Command) -Description ([string]$change.Description) | Out-Null
            [void]$applied.Add($change)
        }
        $runningAfter = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
        $routeLinesAfter = @($runningAfter -split '\r?\n' | Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' } | ForEach-Object { $_.Trim() })
        foreach ($change in $Changes) {
            if ($change.Action -eq 'add') {
                if (-not (Test-RouteCommandPresent -RouteLines $routeLinesAfter -RouteCommand ([string]$change.ExpectedLine))) {
                    throw "Маршрут не найден после добавления: $($change.ExpectedLine)"
                }
            }
            elseif ($change.Action -eq 'delete') {
                if (Test-RouteCommandPresent -RouteLines $routeLinesAfter -RouteCommand ([string]$change.ExpectedLine)) {
                    throw "Маршрут всё ещё присутствует после удаления: $($change.ExpectedLine)"
                }
            }
        }
        [IO.File]::WriteAllText((Join-Path $backup.Folder 'running-config-after.txt'),$runningAfter,[Text.Encoding]::UTF8)
        Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение маршрутов' | Out-Null
        $script:WireGuardRouteCountCache = @{}
        $script:WireGuardRouteCountCacheAt = @{}
        Write-Log "Routes: операция '$OperationName' успешна, изменений: $($Changes.Count), backup: $($backup.Folder)"
        return [pscustomobject]@{ Count=$Changes.Count; BackupFolder=$backup.Folder }
    }
    catch {
        $originalError = $_.Exception.Message
        $rollbackOk = $true
        $rollbackErrors = New-Object System.Collections.ArrayList
        for ($i=$applied.Count-1; $i -ge 0; $i--) {
            $change = $applied[$i]
            foreach ($inverse in @($change.InverseCommands)) {
                if ([string]::IsNullOrWhiteSpace([string]$inverse)) { continue }
                try { Invoke-KeeneticCliCommand -Command ([string]$inverse) -Description 'rollback маршрута' | Out-Null }
                catch { $rollbackOk = $false; [void]$rollbackErrors.Add($_.Exception.Message) }
            }
        }
        if ($rollbackOk) {
            try {
                Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение rollback маршрутов' | Out-Null
                $script:WireGuardRouteCountCache = @{}
                $script:WireGuardRouteCountCacheAt = @{}
            }
            catch { $rollbackOk = $false; [void]$rollbackErrors.Add($_.Exception.Message) }
        }
        if ($rollbackOk) {
            throw "Операция с маршрутами отменена: $originalError`r`n`r`nИзменения автоматически откатились. Backup: $($backup.Folder)"
        }
        throw "Ошибка маршрутов: $originalError`r`n`r`nАвтооткат выполнен НЕ полностью: $(@($rollbackErrors) -join '; ')`r`nНЕ сохраняйте конфигурацию вручную. Исходный startup-config: $($backup.Folder)\startup-config.txt"
    }
}


function Invoke-KeeneticRouteImportInBatchesSafely {
    param(
        [Parameter(Mandatory)][object[]]$Changes,
        [Parameter(Mandatory)][System.Windows.Forms.Form]$Owner,
        [string]$SourceFileName = ''
    )

    $allChanges = @($Changes)
    if ($allChanges.Count -eq 0) { throw 'Нет маршрутов для импорта.' }

    $batchSize = [int]$RouteImportBatchSize
    if ($batchSize -lt 1) { $batchSize = 950 }
    $commands = @($allChanges | ForEach-Object { [string]$_.Command })
    $backup = Save-RouteSafetyBackup -Operation 'import-batched' -Commands $commands

    # Полный preflight ДО первой команды. Уже существующие ADD-маршруты и
    # повторные ADD-строки внутри самого файла НЕ считаются ошибкой: они
    # спокойно пропускаются, а в конце показывается их количество.
    $routeLinesBefore = @(
        $backup.RunningBefore -split '\r?\n' |
            Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' } |
            ForEach-Object { $_.Trim() }
    )
    $routeIdentityBefore = @{}
    foreach ($existingLine in $routeLinesBefore) {
        $routeIdentityBefore[(Get-KeeneticRouteIdentity -Line $existingLine)] = $true
    }

    $effectiveChanges = New-Object System.Collections.ArrayList
    $seenOperations = @{}
    $duplicateExistingCount = 0
    $duplicateFileCount = 0

    foreach ($change in $allChanges) {
        $expectedKey = Get-KeeneticRouteIdentity -Line ([string]$change.ExpectedLine)
        $action = [string]$change.Action
        $opKey = $action + '|' + $expectedKey
        $presentBefore = $routeIdentityBefore.ContainsKey($expectedKey)

        if ($action -eq 'add') {
            if ($presentBefore) {
                $duplicateExistingCount++
                continue
            }
            if ($seenOperations.ContainsKey($opKey)) {
                $duplicateFileCount++
                continue
            }
            $seenOperations[$opKey] = $true
            [void]$effectiveChanges.Add($change)
            continue
        }

        # Для удаления сохраняем строгую семантику: отсутствующий маршрут —
        # это не «повтор», а потенциально ошибочный BAT, поэтому останавливаемся
        # до первой команды. Повторная строка удаления также считается ошибкой.
        if ($seenOperations.ContainsKey($opKey)) {
            throw "В импортируемом файле операция удаления повторяется несколько раз: $($change.ExpectedLine)"
        }
        $seenOperations[$opKey] = $true
        if ($action -eq 'delete' -and -not $presentBefore) {
            throw "Маршрут для удаления уже отсутствует; импорт остановлен до изменений: $($change.ExpectedLine)"
        }
        [void]$effectiveChanges.Add($change)
    }

    $allChanges = @($effectiveChanges)
    $duplicateCount = $duplicateExistingCount + $duplicateFileCount
    $batchCount = if ($allChanges.Count -gt 0) { [int][Math]::Ceiling($allChanges.Count / [double]$batchSize) } else { 0 }

    # Сохраняем разбиение рядом с safety-backup. В партии попадают только
    # реально применяемые маршруты; уже существующие/повторные строки туда не пишутся.
    $partsDir = Join-Path $backup.Folder 'import-parts'
    New-Item -ItemType Directory -Path $partsDir -Force | Out-Null
    for ($batchIndex = 0; $batchIndex -lt $batchCount; $batchIndex++) {
        $start = $batchIndex * $batchSize
        $count = [Math]::Min($batchSize, $allChanges.Count - $start)
        $part = @($allChanges[$start..($start + $count - 1)])
        $sourceExt = [IO.Path]::GetExtension($SourceFileName).ToLowerInvariant()
        $partExt = if ($sourceExt -eq '.bat' -or $sourceExt -eq '.cmd') { '.bat' } else { '.txt' }
        $partPath = Join-Path $partsDir (('part-{0:D3}-of-{1:D3}' -f ($batchIndex + 1),$batchCount) + $partExt)
        $partLines = New-Object System.Collections.ArrayList
        if ($partExt -eq '.bat') {
            [void]$partLines.Add('@echo off')
            [void]$partLines.Add(('rem Auto-split by Keenetic WG & Routes; source: {0}' -f $SourceFileName))
            [void]$partLines.Add(('rem Batch {0}/{1}; routes: {2}; max batch size: {3}' -f ($batchIndex + 1),$batchCount,$count,$batchSize))
        }
        else {
            [void]$partLines.Add(('# Auto-split by Keenetic WG & Routes; source: {0}' -f $SourceFileName))
            [void]$partLines.Add(('# Batch {0}/{1}; routes: {2}; max batch size: {3}' -f ($batchIndex + 1),$batchCount,$count,$batchSize))
        }
        foreach ($change in $part) {
            $sourceLine = Get-NamedPropertyValue -Object $change -Name 'SourceLine'
            if ([string]::IsNullOrWhiteSpace([string]$sourceLine)) { $sourceLine = [string]$change.Command }
            [void]$partLines.Add([string]$sourceLine)
        }
        [IO.File]::WriteAllLines($partPath,@($partLines),[Text.Encoding]::UTF8)
    }

    if ($allChanges.Count -eq 0) {
        Write-Log "Routes import: изменений нет. Все ADD-маршруты уже существовали/повторялись. Повторов: $duplicateCount (на роутере: $duplicateExistingCount, в файле: $duplicateFileCount)."
        return [pscustomobject]@{
            Count = 0
            DuplicateCount = $duplicateCount
            DuplicateExistingCount = $duplicateExistingCount
            DuplicateFileCount = $duplicateFileCount
            BatchCount = 0
            BatchSize = $batchSize
            BackupFolder = $backup.Folder
            PartsFolder = $partsDir
        }
    }

    $progress = [System.Windows.Forms.Form]::new()
    $progress.Text = 'Импорт маршрутов'
    $progress.ClientSize = [System.Drawing.Size]::new(560,160)
    $progress.FormBorderStyle = 'FixedDialog'
    $progress.MaximizeBox = $false
    $progress.MinimizeBox = $false
    $progress.StartPosition = 'CenterParent'
    if ($null -ne $script:AppIcon) { $progress.Icon=$script:AppIcon; $progress.ShowIcon=$true }
    $progressLabel = [System.Windows.Forms.Label]::new()
    $progressLabel.Location = [System.Drawing.Point]::new(20,20)
    $progressLabel.Size = [System.Drawing.Size]::new(520,48)
    $progress.Controls.Add($progressLabel)
    $progressBar = [System.Windows.Forms.ProgressBar]::new()
    $progressBar.Location = [System.Drawing.Point]::new(20,78)
    $progressBar.Size = [System.Drawing.Size]::new(520,26)
    $progressBar.Minimum = 0
    $progressBar.Maximum = $allChanges.Count
    $progress.Controls.Add($progressBar)
    $progressHint = [System.Windows.Forms.Label]::new()
    $progressHint.Text = "Партии до $batchSize маршрутов. Следующая начинается только после проверки текущей."
    $progressHint.ForeColor = [System.Drawing.Color]::DimGray
    $progressHint.Location = [System.Drawing.Point]::new(20,115)
    $progressHint.Size = [System.Drawing.Size]::new(520,28)
    $progress.Controls.Add($progressHint)

    $applied = New-Object System.Collections.ArrayList
    try {
        $progress.Show($Owner)
        [System.Windows.Forms.Application]::DoEvents()

        for ($batchIndex = 0; $batchIndex -lt $batchCount; $batchIndex++) {
            $start = $batchIndex * $batchSize
            $count = [Math]::Min($batchSize, $allChanges.Count - $start)
            $end = $start + $count - 1
            $batch = @($allChanges[$start..$end])

            for ($localIndex = 0; $localIndex -lt $batch.Count; $localIndex++) {
                $globalNumber = $start + $localIndex + 1
                $progressLabel.Text = "Пакет $($batchIndex + 1)/$batchCount — маршрут $($localIndex + 1)/$($batch.Count)`r`nВсего: $globalNumber/$($allChanges.Count)"
                $progressBar.Value = [Math]::Min($globalNumber - 1,$progressBar.Maximum)
                [System.Windows.Forms.Application]::DoEvents()

                $change = $batch[$localIndex]
                Invoke-KeeneticCliCommand -Command ([string]$change.Command) -Description ("импорт маршрутов, пакет {0}/{1}" -f ($batchIndex + 1),$batchCount) | Out-Null
                [void]$applied.Add($change)
            }

            # Проверяем только что завершённую партию до перехода к следующей.
            $progressLabel.Text = "Пакет $($batchIndex + 1)/$batchCount загружен. Проверяем маршруты..."
            [System.Windows.Forms.Application]::DoEvents()
            $runningAfterBatch = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
            $routeLinesAfterBatch = @($runningAfterBatch -split '\r?\n' | Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' } | ForEach-Object { $_.Trim() })
            $routeNormalizedAfterBatch = @{}
            foreach ($routeLine in $routeLinesAfterBatch) { $routeNormalizedAfterBatch[(Normalize-KeeneticRouteCommand -Line $routeLine)] = $true }
            foreach ($change in $batch) {
                $normalizedExpected = Normalize-KeeneticRouteCommand -Line ([string]$change.ExpectedLine)
                $isPresent = $routeNormalizedAfterBatch.ContainsKey($normalizedExpected)
                if ($change.Action -eq 'add' -and -not $isPresent) {
                    throw "Пакет $($batchIndex + 1)/$($batchCount): маршрут не найден после добавления: $($change.ExpectedLine)"
                }
                elseif ($change.Action -eq 'delete' -and $isPresent) {
                    throw "Пакет $($batchIndex + 1)/$($batchCount): маршрут всё ещё присутствует после удаления: $($change.ExpectedLine)"
                }
            }
            [IO.File]::WriteAllText((Join-Path $backup.Folder ('running-config-after-batch-{0:D3}.txt' -f ($batchIndex + 1))),$runningAfterBatch,[Text.Encoding]::UTF8)
            Write-Log "Routes import: пакет $($batchIndex + 1)/$batchCount OK, маршрутов: $count."
            $progressBar.Value = [Math]::Min($end + 1,$progressBar.Maximum)
            $progressLabel.Text = "Пакет $($batchIndex + 1)/$batchCount — OK ✓`r`nПрименено: $($end + 1)/$($allChanges.Count)"
            [System.Windows.Forms.Application]::DoEvents()
        }

        # Финальная проверка всей операции и единственное сохранение startup-config.
        $runningAfter = Invoke-KeeneticTextGet -Path 'ci/running-config.txt'
        $routeLinesAfter = @($runningAfter -split '\r?\n' | Where-Object { $_ -match '^\s*(?:ip|ipv6)\s+route\b' } | ForEach-Object { $_.Trim() })
        $routeNormalizedAfter = @{}
        foreach ($routeLine in $routeLinesAfter) { $routeNormalizedAfter[(Normalize-KeeneticRouteCommand -Line $routeLine)] = $true }
        foreach ($change in $allChanges) {
            $normalizedExpected = Normalize-KeeneticRouteCommand -Line ([string]$change.ExpectedLine)
            $isPresent = $routeNormalizedAfter.ContainsKey($normalizedExpected)
            if ($change.Action -eq 'add' -and -not $isPresent) {
                throw "Финальная проверка: маршрут не найден: $($change.ExpectedLine)"
            }
            elseif ($change.Action -eq 'delete' -and $isPresent) {
                throw "Финальная проверка: удалённый маршрут снова присутствует: $($change.ExpectedLine)"
            }
        }
        [IO.File]::WriteAllText((Join-Path $backup.Folder 'running-config-after.txt'),$runningAfter,[Text.Encoding]::UTF8)
        Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение пакетного импорта маршрутов' | Out-Null
        $script:WireGuardRouteCountCache = @{}
        $script:WireGuardRouteCountCacheAt = @{}
        Write-Log "Routes import: завершено успешно. Добавлено/применено: $($allChanges.Count), повторов пропущено: $duplicateCount (на роутере: $duplicateExistingCount, в файле: $duplicateFileCount), пакетов: $batchCount, backup: $($backup.Folder)"
        return [pscustomobject]@{
            Count = $allChanges.Count
            DuplicateCount = $duplicateCount
            DuplicateExistingCount = $duplicateExistingCount
            DuplicateFileCount = $duplicateFileCount
            BatchCount = $batchCount
            BatchSize = $batchSize
            BackupFolder = $backup.Folder
            PartsFolder = $partsDir
        }
    }
    catch {
        $originalError = $_.Exception.Message
        $rollbackOk = $true
        $rollbackErrors = New-Object System.Collections.ArrayList
        if ($null -ne $progressLabel) {
            $progressLabel.Text = "Ошибка. Выполняется откат $($applied.Count) применённых изменений..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        for ($i=$applied.Count-1; $i -ge 0; $i--) {
            $change = $applied[$i]
            foreach ($inverse in @($change.InverseCommands)) {
                if ([string]::IsNullOrWhiteSpace([string]$inverse)) { continue }
                try { Invoke-KeeneticCliCommand -Command ([string]$inverse) -Description 'rollback пакетного импорта маршрутов' | Out-Null }
                catch { $rollbackOk=$false; [void]$rollbackErrors.Add($_.Exception.Message) }
            }
            if (($i % 25) -eq 0) { [System.Windows.Forms.Application]::DoEvents() }
        }
        if ($rollbackOk) {
            try {
                Invoke-KeeneticCliCommand -Command 'system configuration save' -Description 'сохранение rollback пакетного импорта' | Out-Null
                $script:WireGuardRouteCountCache = @{}
                $script:WireGuardRouteCountCacheAt = @{}
            }
            catch { $rollbackOk=$false; [void]$rollbackErrors.Add($_.Exception.Message) }
        }
        if ($rollbackOk) {
            throw "Пакетный импорт остановлен: $originalError`r`n`r`nВсе применённые партии автоматически откатились. Backup: $($backup.Folder)"
        }
        throw "Пакетный импорт остановлен: $originalError`r`n`r`nАвтооткат выполнен НЕ полностью: $(@($rollbackErrors) -join '; ')`r`nИсходный startup-config: $($backup.Folder)\startup-config.txt"
    }
    finally {
        if ($null -ne $progress) { $progress.Close(); $progress.Dispose() }
    }
}

function Convert-WindowsRouteLineToChange {
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][AllowEmptyString()][string]$DefaultInterface,
        [bool]$Auto = $true,
        [bool]$Reject = $false,
        [string]$Comment = '',
        [object[]]$CurrentRoutes = @()
    )
    $text = ($Line.Trim() -replace '(?i)\s+(?:1>|2>|>)\s*[^\s]+.*$','').Trim()
    $deleteByDash = $false
    if ($text.StartsWith('-')) { $deleteByDash=$true; $text=$text.Substring(1).Trim() }
    if ($text -notmatch '^(?i)route(?:\.exe)?\s+(?:-p\s+)?(?<action>add|delete|del)\s+(?<dest>\S+)(?:\s+mask\s+(?<mask>\S+))?(?:\s+(?<gateway>\S+))?(?<tail>.*)$') { return $null }
    $action = $Matches.action.ToLowerInvariant()
    if ($deleteByDash) { $action = 'delete' }
    $dest = $Matches.dest
    $mask = [string]$Matches.mask
    $gateway = [string]$Matches.gateway
    if ($gateway -match '^(?i)metric$|^if$') { $gateway='' }
    $via = $gateway
    if ([string]::IsNullOrWhiteSpace($via) -or $via -eq '0.0.0.0') { $via = $DefaultInterface }
    if ([string]::IsNullOrWhiteSpace($via)) { throw "Для строки '$Line' нужен целевой интерфейс." }
    $destination = $dest
    if (-not [string]::IsNullOrWhiteSpace($mask)) {
        $prefix = Convert-Ipv4MaskToPrefix -Mask $mask
        if ($prefix -lt 0) { throw "Некорректная маска '$mask' в строке '$Line'." }
        $destination = "$dest/$prefix"
    }
    $addCommand = New-KeeneticRouteAddCommand -Family IPv4 -Destination $destination -Via $via -Auto:$Auto -Reject:$Reject -Comment $Comment
    $addRecord = Convert-RouteLineToRecord -Line $addCommand
    if ($action -eq 'add') {
        return [pscustomobject]@{
            Action='add'; Command=$addCommand; ExpectedLine=$addCommand; InverseCommands=@($addRecord.DeleteCommand); Description='импорт IPv4 маршрута'
        }
    }
    $candidate = $null
    foreach ($route in $CurrentRoutes) {
        if ((Normalize-KeeneticRouteCommand -Line $route.DeleteCommand) -eq (Normalize-KeeneticRouteCommand -Line $addRecord.DeleteCommand)) { $candidate=$route; break }
    }
    if ($null -eq $candidate) {
        # Попытка более мягкого совпадения по destination/via.
        foreach ($route in $CurrentRoutes) {
            if ($route.Family -eq 'IPv4' -and $route.Destination -eq $addRecord.Destination -and $route.Via -eq $addRecord.Via) { $candidate=$route; break }
        }
    }
    if ($null -eq $candidate) { throw "Не найден точный существующий маршрут для удаления из строки '$Line'." }
    $inverse = New-Object System.Collections.ArrayList
    [void]$inverse.Add($candidate.RawLine)
    if ($candidate.Disabled) { [void]$inverse.Add('ip route disable') }
    return [pscustomobject]@{
        Action='delete'; Command=$candidate.DeleteCommand; ExpectedLine=$candidate.RawLine; InverseCommands=@($inverse); Description='импорт удаления IPv4 маршрута'
    }
}

function Convert-KeeneticRouteImportLineToChange {
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][AllowEmptyString()][string]$DefaultInterface,
        [bool]$Auto = $true,
        [bool]$Reject = $false,
        [string]$Comment = '',
        [object[]]$CurrentRoutes = @()
    )
    $text = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    if ($text -match '^(?i)(@?echo\b|rem\b|::|#|;|pause\b|cls\b|chcp\b|set\b)') { return $null }

    $win = Convert-WindowsRouteLineToChange -Line $text -DefaultInterface $DefaultInterface -Auto:$Auto -Reject:$Reject -Comment $Comment -CurrentRoutes $CurrentRoutes
    if ($null -ne $win) { return $win }

    if ($text -match '^(?i)(?<no>no\s+)?(?<family>ip|ipv6)\s+route\s+') {
        $isDelete = -not [string]::IsNullOrWhiteSpace([string]$Matches.no)
        if ($text -match '^(?i)(ip|ipv6)\s+route\s+disable\s*$') { throw 'Отдельная строка route disable без привязанного маршрута не импортируется.' }
        if (-not $isDelete) {
            $record = Convert-RouteLineToRecord -Line $text
            if ($null -eq $record) { throw "Не удалось разобрать Keenetic route: $text" }
            return [pscustomobject]@{ Action='add'; Command=$text; ExpectedLine=$text; InverseCommands=@($record.DeleteCommand); Description='импорт Keenetic route' }
        }
        $normalizedDelete = Normalize-KeeneticRouteCommand -Line $text
        $candidate = $null
        foreach ($route in $CurrentRoutes) {
            if ((Normalize-KeeneticRouteCommand -Line $route.DeleteCommand) -eq $normalizedDelete) { $candidate=$route; break }
        }
        if ($null -eq $candidate) { throw "Не найден существующий маршрут для '$text'." }
        $inverse = New-Object System.Collections.ArrayList
        [void]$inverse.Add($candidate.RawLine)
        if ($candidate.Disabled) { [void]$inverse.Add("$($candidate.Command.Split(' ')[0]) route disable") }
        return [pscustomobject]@{ Action='delete'; Command=$text; ExpectedLine=$candidate.RawLine; InverseCommands=@($inverse); Description='импорт удаления Keenetic route' }
    }

    # Простой список IP/CIDR: отправляем через выбранный интерфейс.
    if ($text -match '^[0-9a-fA-F:.]+(?:/\d{1,3})?$') {
        $family = if ($text.Contains(':')) { 'IPv6' } else { 'IPv4' }
        if ([string]::IsNullOrWhiteSpace($DefaultInterface)) { throw "Для списка IP/CIDR выберите интерфейс назначения (строка '$text')." }
        $addCommand = New-KeeneticRouteAddCommand -Family $family -Destination $text -Via $DefaultInterface -Auto:$Auto -Reject:$Reject -Comment $Comment
        $record = Convert-RouteLineToRecord -Line $addCommand
        return [pscustomobject]@{ Action='add'; Command=$addCommand; ExpectedLine=$addCommand; InverseCommands=@($record.DeleteCommand); Description='импорт IP/CIDR' }
    }
    throw "Неподдерживаемая строка: $text"
}

function Show-RouteAddDialog {
    param([Parameter(Mandatory)][System.Windows.Forms.Form]$Owner,[string[]]$InterfaceHints=@())
    $dialog = [System.Windows.Forms.Form]::new()
    $dialog.Text = 'Добавить статический маршрут'
    $dialog.ClientSize = [System.Drawing.Size]::new(510,350)
    $dialog.FormBorderStyle='FixedDialog'; $dialog.MaximizeBox=$false; $dialog.MinimizeBox=$false; $dialog.StartPosition='CenterParent'
    $familyLabel=[System.Windows.Forms.Label]::new();$familyLabel.Text='Тип:';$familyLabel.Location=[System.Drawing.Point]::new(22,25);$familyLabel.AutoSize=$true;$dialog.Controls.Add($familyLabel)
    $family=[System.Windows.Forms.ComboBox]::new();$family.DropDownStyle='DropDownList';$family.Items.AddRange(@('IPv4','IPv6'));$family.SelectedIndex=0;$family.Location=[System.Drawing.Point]::new(145,20);$family.Size=[System.Drawing.Size]::new(330,28);$dialog.Controls.Add($family)
    $destLabel=[System.Windows.Forms.Label]::new();$destLabel.Text='Сеть / узел:';$destLabel.Location=[System.Drawing.Point]::new(22,70);$destLabel.AutoSize=$true;$dialog.Controls.Add($destLabel)
    $dest=[System.Windows.Forms.TextBox]::new();$dest.Location=[System.Drawing.Point]::new(145,65);$dest.Size=[System.Drawing.Size]::new(330,27);$dialog.Controls.Add($dest)
    $hint=[System.Windows.Forms.Label]::new();$hint.Text='Пример: 142.250.0.0/16, 8.8.8.8, 2001:db8::/32 или default';$hint.ForeColor=[System.Drawing.Color]::DimGray;$hint.Location=[System.Drawing.Point]::new(145,94);$hint.Size=[System.Drawing.Size]::new(335,32);$dialog.Controls.Add($hint)
    $viaLabel=[System.Windows.Forms.Label]::new();$viaLabel.Text='Интерфейс / шлюз:';$viaLabel.Location=[System.Drawing.Point]::new(22,139);$viaLabel.AutoSize=$true;$dialog.Controls.Add($viaLabel)
    $via=[System.Windows.Forms.ComboBox]::new();$via.DropDownStyle='DropDown';$via.Location=[System.Drawing.Point]::new(145,134);$via.Size=[System.Drawing.Size]::new(330,28);foreach($x in $InterfaceHints){if(-not [string]::IsNullOrWhiteSpace($x)){[void]$via.Items.Add($x)}};$dialog.Controls.Add($via)
    $commentLabel=[System.Windows.Forms.Label]::new();$commentLabel.Text='Описание:';$commentLabel.Location=[System.Drawing.Point]::new(22,183);$commentLabel.AutoSize=$true;$dialog.Controls.Add($commentLabel)
    $comment=[System.Windows.Forms.TextBox]::new();$comment.Location=[System.Drawing.Point]::new(145,178);$comment.Size=[System.Drawing.Size]::new(330,27);$dialog.Controls.Add($comment)
    $auto=[System.Windows.Forms.CheckBox]::new();$auto.Text='Автоматический маршрут (auto)';$auto.Checked=$true;$auto.Location=[System.Drawing.Point]::new(145,219);$auto.Size=[System.Drawing.Size]::new(250,24);$dialog.Controls.Add($auto)
    $reject=[System.Windows.Forms.CheckBox]::new();$reject.Text='Эксклюзивный маршрут (reject)';$reject.Location=[System.Drawing.Point]::new(145,247);$reject.Size=[System.Drawing.Size]::new(250,24);$dialog.Controls.Add($reject)
    $cancel=[System.Windows.Forms.Button]::new();$cancel.Text='Отмена';$cancel.Location=[System.Drawing.Point]::new(250,296);$cancel.Size=[System.Drawing.Size]::new(105,34);$cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel;$dialog.Controls.Add($cancel)
    $ok=[System.Windows.Forms.Button]::new();$ok.Text='Добавить';$ok.Location=[System.Drawing.Point]::new(370,296);$ok.Size=[System.Drawing.Size]::new(105,34);$dialog.Controls.Add($ok);$dialog.CancelButton=$cancel
    $dialog.Tag = $null
    $ok.Add_Click({
        try {
            $cmd=New-KeeneticRouteAddCommand -Family ([string]$family.SelectedItem) -Destination $dest.Text -Via $via.Text -Auto:$auto.Checked -Reject:$reject.Checked -Comment $comment.Text
            $record=Convert-RouteLineToRecord -Line $cmd
            $dialog.Tag = [pscustomobject]@{ Action='add';Command=$cmd;ExpectedLine=$cmd;InverseCommands=@($record.DeleteCommand);Description='добавление статического маршрута' }
            $dialog.DialogResult=[System.Windows.Forms.DialogResult]::OK
            $dialog.Close()
        } catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)|Out-Null }
    })
    if ($dialog.ShowDialog($Owner) -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.Tag }
    return $null
}

function Show-RouteImportOptionsDialog {
    param([Parameter(Mandatory)][System.Windows.Forms.Form]$Owner,[string[]]$InterfaceHints=@(),[string]$SuggestedInterface='')
    $dialog=[System.Windows.Forms.Form]::new();$dialog.Text='Импорт маршрутов';$dialog.ClientSize=[System.Drawing.Size]::new(540,320);$dialog.FormBorderStyle='FixedDialog';$dialog.MaximizeBox=$false;$dialog.MinimizeBox=$false;$dialog.StartPosition='CenterParent'
    $info=[System.Windows.Forms.Label]::new();$info.Text="Поддерживается: .bat/.cmd/.txt, route add/delete, Keenetic ip route/no ip route,`r`nа также простой список IP/CIDR.";$info.Location=[System.Drawing.Point]::new(22,18);$info.Size=[System.Drawing.Size]::new(490,45);$dialog.Controls.Add($info)
    $viaLabel=[System.Windows.Forms.Label]::new();$viaLabel.Text='Интерфейс по умолчанию:';$viaLabel.Location=[System.Drawing.Point]::new(22,83);$viaLabel.AutoSize=$true;$dialog.Controls.Add($viaLabel)
    $via=[System.Windows.Forms.ComboBox]::new();$via.DropDownStyle='DropDown';$via.Location=[System.Drawing.Point]::new(200,78);$via.Size=[System.Drawing.Size]::new(310,28);foreach($x in $InterfaceHints){if(-not [string]::IsNullOrWhiteSpace($x)){[void]$via.Items.Add($x)}};$via.Text=$SuggestedInterface;$dialog.Controls.Add($via)
    $viaHint=[System.Windows.Forms.Label]::new();$viaHint.Text='Для BAT шлюз 0.0.0.0 заменяется этим интерфейсом.';$viaHint.ForeColor=[System.Drawing.Color]::DimGray;$viaHint.Location=[System.Drawing.Point]::new(200,108);$viaHint.Size=[System.Drawing.Size]::new(310,30);$dialog.Controls.Add($viaHint)
    $commentLabel=[System.Windows.Forms.Label]::new();$commentLabel.Text='Описание для импорта:';$commentLabel.Location=[System.Drawing.Point]::new(22,149);$commentLabel.AutoSize=$true;$dialog.Controls.Add($commentLabel)
    $comment=[System.Windows.Forms.TextBox]::new();$comment.Location=[System.Drawing.Point]::new(200,144);$comment.Size=[System.Drawing.Size]::new(310,27);$dialog.Controls.Add($comment)
    $auto=[System.Windows.Forms.CheckBox]::new();$auto.Text='auto';$auto.Checked=$true;$auto.Location=[System.Drawing.Point]::new(200,184);$auto.Size=[System.Drawing.Size]::new(100,24);$dialog.Controls.Add($auto)
    $reject=[System.Windows.Forms.CheckBox]::new();$reject.Text='Эксклюзивный (reject)';$reject.Location=[System.Drawing.Point]::new(305,184);$reject.Size=[System.Drawing.Size]::new(190,24);$dialog.Controls.Add($reject)
    $cancel=[System.Windows.Forms.Button]::new();$cancel.Text='Отмена';$cancel.Location=[System.Drawing.Point]::new(285,255);$cancel.Size=[System.Drawing.Size]::new(105,34);$cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel;$dialog.Controls.Add($cancel)
    $ok=[System.Windows.Forms.Button]::new();$ok.Text='Далее';$ok.Location=[System.Drawing.Point]::new(405,255);$ok.Size=[System.Drawing.Size]::new(105,34);$dialog.Controls.Add($ok);$dialog.CancelButton=$cancel
    $dialog.Tag = $null
    $ok.Add_Click({
        $dialog.Tag = [pscustomobject]@{ Interface=$via.Text.Trim(); Comment=$comment.Text.Trim(); Auto=$auto.Checked; Reject=$reject.Checked }
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    })
    if ($dialog.ShowDialog($Owner) -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.Tag }
    return $null
}

function Show-RouteImportPreviewDialog {
    param([Parameter(Mandatory)][System.Windows.Forms.Form]$Owner,[object[]]$Changes,[object[]]$Errors,[string]$FileName)
    $dialog=[System.Windows.Forms.Form]::new();$dialog.Text='Предпросмотр импорта маршрутов';$dialog.ClientSize=[System.Drawing.Size]::new(820,570);$dialog.StartPosition='CenterParent';$dialog.MinimumSize=[System.Drawing.Size]::new(700,500)
    $previewBatchCount = if ($Changes.Count -gt 0) { [int][Math]::Ceiling($Changes.Count / [double]$RouteImportBatchSize) } else { 0 }
    $summary=[System.Windows.Forms.Label]::new();$summary.Text="Файл: $FileName`r`nГотово: $($Changes.Count)   Ошибок/пропусков: $($Errors.Count)   Пакетов: $previewBatchCount (до $RouteImportBatchSize маршрутов)";$summary.Location=[System.Drawing.Point]::new(18,16);$summary.Size=[System.Drawing.Size]::new(780,45);$dialog.Controls.Add($summary)
    $box=[System.Windows.Forms.TextBox]::new();$box.Multiline=$true;$box.ReadOnly=$true;$box.ScrollBars='Both';$box.WordWrap=$false;$box.Location=[System.Drawing.Point]::new(18,68);$box.Size=[System.Drawing.Size]::new(784,430);$lines=New-Object System.Collections.ArrayList;foreach($c in $Changes){[void]$lines.Add("[$($c.Action.ToUpperInvariant())] $($c.Command)")};if($Errors.Count -gt 0){[void]$lines.Add('');[void]$lines.Add('--- НЕ ИМПОРТИРОВАНО ---');foreach($e in $Errors){[void]$lines.Add("Строка $($e.Line): $($e.Error) | $($e.Text)")}};$box.Text=@($lines)-join "`r`n";$dialog.Controls.Add($box)
    $cancel=[System.Windows.Forms.Button]::new();$cancel.Text='Отмена';$cancel.Location=[System.Drawing.Point]::new(570,515);$cancel.Size=[System.Drawing.Size]::new(105,34);$cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel;$dialog.Controls.Add($cancel)
    $apply=[System.Windows.Forms.Button]::new();$apply.Text='Применить';$apply.Location=[System.Drawing.Point]::new(690,515);$apply.Size=[System.Drawing.Size]::new(112,34);$apply.Enabled=$Changes.Count -gt 0;$dialog.Controls.Add($apply);$dialog.CancelButton=$cancel
    $apply.Add_Click({$dialog.DialogResult=[System.Windows.Forms.DialogResult]::OK;$dialog.Close()})
    return ($dialog.ShowDialog($Owner) -eq [System.Windows.Forms.DialogResult]::OK)
}

function Show-RouteManager {
    if (-not (Test-Path -LiteralPath $CredentialPath)) {
        Show-KeeneticCredentialDialog
        if (-not (Test-Path -LiteralPath $CredentialPath)) { return }
    }

    $dialog = [System.Windows.Forms.Form]::new()
    $dialog.Text = 'Статические маршруты Keenetic'
    $dialog.ClientSize = [System.Drawing.Size]::new(1040, 680)
    $dialog.StartPosition = 'CenterParent'
    $dialog.FormBorderStyle = 'FixedSingle'
    $dialog.MaximizeBox = $false
    $dialog.MinimumSize = [System.Drawing.Size]::new(1056, 719)
    $dialog.MaximumSize = [System.Drawing.Size]::new(1056, 719)
    if ($null -ne $script:AppIcon) {
        $dialog.Icon = $script:AppIcon
        $dialog.ShowIcon = $true
    }

    $title = [System.Windows.Forms.Label]::new()
    $title.Text = 'Статические маршруты'
    $title.Font = [System.Drawing.Font]::new('Segoe UI',15,[System.Drawing.FontStyle]::Bold)
    $title.Location = [System.Drawing.Point]::new(20,16)
    $title.AutoSize = $true
    $dialog.Controls.Add($title)

    $info = [System.Windows.Forms.Label]::new()
    $info.Text = 'Добавление/удаление + массовый импорт BAT/CMD/TXT. Перед изменениями создаётся полный startup/running backup.'
    $info.ForeColor = [System.Drawing.Color]::DimGray
    $info.Location = [System.Drawing.Point]::new(22,48)
    $info.Size = [System.Drawing.Size]::new(850,28)
    $dialog.Controls.Add($info)

    $filterLabel = [System.Windows.Forms.Label]::new()
    $filterLabel.Text = 'Интерфейс:'
    $filterLabel.Location = [System.Drawing.Point]::new(22,88)
    $filterLabel.AutoSize = $true
    $dialog.Controls.Add($filterLabel)

    $filter = [System.Windows.Forms.ComboBox]::new()
    $filter.DropDownStyle = 'DropDownList'
    $filter.Location = [System.Drawing.Point]::new(100,83)
    $filter.Size = [System.Drawing.Size]::new(210,28)
    $dialog.Controls.Add($filter)

    $searchLabel = [System.Windows.Forms.Label]::new()
    $searchLabel.Text = 'Поиск:'
    $searchLabel.Location = [System.Drawing.Point]::new(330,88)
    $searchLabel.AutoSize = $true
    $dialog.Controls.Add($searchLabel)

    $search = [System.Windows.Forms.TextBox]::new()
    $search.Location = [System.Drawing.Point]::new(385,83)
    $search.Size = [System.Drawing.Size]::new(250,27)
    $dialog.Controls.Add($search)

    $refresh = [System.Windows.Forms.Button]::new()
    $refresh.Text = 'Обновить'
    $refresh.Location = [System.Drawing.Point]::new(655,80)
    $refresh.Size = [System.Drawing.Size]::new(105,34)
    $dialog.Controls.Add($refresh)

    $add = [System.Windows.Forms.Button]::new()
    $add.Text = 'Добавить'
    $add.Location = [System.Drawing.Point]::new(770,80)
    $add.Size = [System.Drawing.Size]::new(105,34)
    $dialog.Controls.Add($add)

    $import = [System.Windows.Forms.Button]::new()
    $import.Text = 'Импорт…'
    $import.Location = [System.Drawing.Point]::new(885,80)
    $import.Size = [System.Drawing.Size]::new(125,34)
    $dialog.Controls.Add($import)

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Location = [System.Drawing.Point]::new(20,128)
    $grid.Size = [System.Drawing.Size]::new(990,455)
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.MultiSelect = $true
    $grid.SelectionMode = 'FullRowSelect'
    $grid.AutoGenerateColumns = $false
    $grid.RowHeadersVisible = $false
    $grid.AutoSizeRowsMode = 'None'
    $grid.AllowUserToResizeRows = $false
    $dialog.Controls.Add($grid)

    $columns = @(
        @('State','Вкл.',45),
        @('Family','Тип',50),
        @('Destination','Назначение',160),
        @('Via','Интерфейс / шлюз',175),
        @('AutoText','Auto',45),
        @('RejectText','Экскл.',50),
        @('Comment','Описание',140),
        @('RawLine','Команда Keenetic',300)
    )
    foreach ($columnInfo in $columns) {
        $column = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
        $column.Name = [string]$columnInfo[0]
        $column.DataPropertyName = [string]$columnInfo[0]
        $column.HeaderText = [string]$columnInfo[1]
        $column.Width = [int]$columnInfo[2]
        [void]$grid.Columns.Add($column)
    }

    $status = [System.Windows.Forms.Label]::new()
    $status.Location = [System.Drawing.Point]::new(22,593)
    $status.Size = [System.Drawing.Size]::new(650,34)
    $status.ForeColor = [System.Drawing.Color]::DimGray
    $dialog.Controls.Add($status)

    $delete = [System.Windows.Forms.Button]::new()
    $delete.Text = 'Удалить выбранные'
    $delete.Location = [System.Drawing.Point]::new(20,628)
    $delete.Size = [System.Drawing.Size]::new(170,34)
    $dialog.Controls.Add($delete)

    $export = [System.Windows.Forms.Button]::new()
    $export.Text = 'Экспорт BAT…'
    $export.Location = [System.Drawing.Point]::new(202,628)
    $export.Size = [System.Drawing.Size]::new(145,34)
    $dialog.Controls.Add($export)

    $backups = [System.Windows.Forms.Button]::new()
    $backups.Text = 'Бэкапы маршрутов'
    $backups.Location = [System.Drawing.Point]::new(359,628)
    $backups.Size = [System.Drawing.Size]::new(155,34)
    $dialog.Controls.Add($backups)

    $close = [System.Windows.Forms.Button]::new()
    $close.Text = 'Закрыть'
    $close.Location = [System.Drawing.Point]::new(885,628)
    $close.Size = [System.Drawing.Size]::new(125,34)
    $dialog.Controls.Add($close)

    $script:RouteManagerRoutes = @()

    function Local-ApplyFilter {
        $selectedInterface = [string]$filter.SelectedItem
        $query = $search.Text.Trim()
        $items = @(
            $script:RouteManagerRoutes | Where-Object {
                ($selectedInterface -eq 'Все интерфейсы' -or
                 [string]::IsNullOrWhiteSpace($selectedInterface) -or
                 $_.Via -eq $selectedInterface) -and
                ([string]::IsNullOrWhiteSpace($query) -or
                 $_.RawLine.IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -ge 0)
            }
        )

        # DataGridView плохо биндингует PowerShell PSCustomObject в Windows PowerShell 5.1:
        # строки появляются, но DataPropertyName остаётся пустым. Заполняем ячейки вручную
        # и храним исходный объект маршрута в DataGridViewRow.Tag.
        $grid.SuspendLayout()
        try {
            $grid.DataSource = $null
            $grid.Rows.Clear()
            foreach ($route in $items) {
                $stateText = 'Да'
                if ($route.Disabled) { $stateText = 'Нет' }
                $autoText = ''
                if ($route.Auto) { $autoText = '✓' }
                $rejectText = ''
                if ($route.Reject) { $rejectText = '✓' }

                $rowIndex = $grid.Rows.Add(
                    $stateText,
                    [string]$route.Family,
                    [string]$route.Destination,
                    [string]$route.Via,
                    $autoText,
                    $rejectText,
                    [string]$route.Comment,
                    [string]$route.RawLine
                )
                $grid.Rows[$rowIndex].Tag = $route
            }
            $grid.ClearSelection()
        }
        finally {
            $grid.ResumeLayout()
        }
        $status.Text = "Показано: $($items.Count) из $($script:RouteManagerRoutes.Count)"
    }

    function Local-RefreshGrid {
        try {
            $status.Text = 'Читаем running-config…'
            $dialog.Refresh()
            $script:Busy = $true
            $script:RouteManagerRoutes = @(Get-KeeneticStaticRoutes)
            $currentFilter = [string]$filter.SelectedItem
            $filter.Items.Clear()
            [void]$filter.Items.Add('Все интерфейсы')
            $vias = @($script:RouteManagerRoutes | ForEach-Object { $_.Via } | Where-Object { $_ } | Sort-Object -Unique)
            foreach ($viaName in $vias) { [void]$filter.Items.Add($viaName) }

            if (-not [string]::IsNullOrWhiteSpace($currentFilter) -and $filter.Items.Contains($currentFilter)) {
                $filter.SelectedItem = $currentFilter
            }
            else {
                $suggested = [string]$wireGuardInterfaceCombo.SelectedItem
                if (-not [string]::IsNullOrWhiteSpace($suggested) -and $filter.Items.Contains($suggested)) {
                    $filter.SelectedItem = $suggested
                }
                else { $filter.SelectedIndex = 0 }
            }
            Local-ApplyFilter
        }
        catch {
            $status.Text = "Ошибка: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                $status.Text,$AppName,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
        finally { $script:Busy = $false }
    }

    $refresh.Add_Click({ Local-RefreshGrid })
    $filter.Add_SelectedIndexChanged({ Local-ApplyFilter })
    $search.Add_TextChanged({ Local-ApplyFilter })

    $add.Add_Click({
        try {
            $hints = @(
                @($script:RouteManagerRoutes | ForEach-Object { $_.Via } | Where-Object { $_ }) +
                @(Get-WireGuardInterfaceNames) | Sort-Object -Unique
            )
            $change = Show-RouteAddDialog -Owner $dialog -InterfaceHints $hints
            if ($null -eq $change) { return }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Добавить маршрут?`r`n`r`n$($change.Command)",
                $AppName,
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            $script:Busy = $true
            try {
                $result = Invoke-KeeneticRouteChangesSafely -Changes @($change) -OperationName 'add'
                [System.Windows.Forms.MessageBox]::Show(
                    "Маршрут добавлен.`r`nBackup: $($result.BackupFolder)",
                    $AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            }
            finally { $script:Busy = $false }
            Local-RefreshGrid
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })

    $delete.Add_Click({
        try {
            if ($grid.SelectedRows.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show('Выберите один или несколько маршрутов.',$AppName) | Out-Null
                return
            }
            $changes = New-Object System.Collections.ArrayList
            foreach ($row in $grid.SelectedRows) {
                $route = $row.Tag
                if ($null -eq $route) { continue }
                $inverse = New-Object System.Collections.ArrayList
                [void]$inverse.Add($route.RawLine)
                if ($route.Disabled) {
                    $familyCommand = 'ip'
                    if ($route.Family -eq 'IPv6') { $familyCommand = 'ipv6' }
                    [void]$inverse.Add("$familyCommand route disable")
                }
                [void]$changes.Add([pscustomobject]@{
                    Action = 'delete'
                    Command = $route.DeleteCommand
                    ExpectedLine = $route.RawLine
                    InverseCommands = @($inverse)
                    Description = 'удаление статического маршрута'
                })
            }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Удалить выбранные маршруты: $($changes.Count)?`r`nПеред удалением будет сохранён полный startup/running backup.",
                $AppName,[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            $script:Busy = $true
            try {
                $result = Invoke-KeeneticRouteChangesSafely -Changes @($changes) -OperationName 'delete-selected'
                [System.Windows.Forms.MessageBox]::Show(
                    "Удалено: $($result.Count).`r`nBackup: $($result.BackupFolder)",
                    $AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            }
            finally { $script:Busy = $false }
            Local-RefreshGrid
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })

    $import.Add_Click({
        try {
            $fileDialog = [System.Windows.Forms.OpenFileDialog]::new()
            $fileDialog.Title = 'Выберите BAT/CMD/TXT со списком маршрутов'
            $fileDialog.Filter = 'Маршруты (*.bat;*.cmd;*.txt;*.list)|*.bat;*.cmd;*.txt;*.list|Все файлы (*.*)|*.*'
            if ($fileDialog.ShowDialog($dialog) -ne [System.Windows.Forms.DialogResult]::OK) { return }

            $hints = @(
                @($script:RouteManagerRoutes | ForEach-Object { $_.Via } | Where-Object { $_ }) +
                @(Get-WireGuardInterfaceNames) | Sort-Object -Unique
            )
            $suggested = [string]$filter.SelectedItem
            if ($suggested -eq 'Все интерфейсы') { $suggested = [string]$wireGuardInterfaceCombo.SelectedItem }
            $options = Show-RouteImportOptionsDialog -Owner $dialog -InterfaceHints $hints -SuggestedInterface $suggested
            if ($null -eq $options) { return }

            $changes = New-Object System.Collections.ArrayList
            $errors = New-Object System.Collections.ArrayList
            $lineNumber = 0
            foreach ($line in [IO.File]::ReadAllLines($fileDialog.FileName)) {
                $lineNumber++
                try {
                    $change = Convert-KeeneticRouteImportLineToChange -Line $line -DefaultInterface $options.Interface -Auto:$options.Auto -Reject:$options.Reject -Comment $options.Comment -CurrentRoutes $script:RouteManagerRoutes
                    if ($null -ne $change) {
                        $change | Add-Member -NotePropertyName SourceLine -NotePropertyValue $line -Force
                        [void]$changes.Add($change)
                    }
                }
                catch {
                    [void]$errors.Add([pscustomobject]@{ Line=$lineNumber; Text=$line; Error=$_.Exception.Message })
                }
            }

            $applyImport = Show-RouteImportPreviewDialog -Owner $dialog -Changes @($changes) -Errors @($errors) -FileName ([IO.Path]::GetFileName($fileDialog.FileName))
            if (-not $applyImport) { return }
            $script:Busy = $true
            try {
                $result = Invoke-KeeneticRouteImportInBatchesSafely -Changes @($changes) -Owner $dialog -SourceFileName ([IO.Path]::GetFileName($fileDialog.FileName))
                [System.Windows.Forms.MessageBox]::Show(
                    "Импорт завершён.`r`nДобавлено: $($result.Count).`r`nПовторных маршрутов: $($result.DuplicateCount).`r`nПакетов: $($result.BatchCount) по максимум $($result.BatchSize).`r`nBackup: $($result.BackupFolder)",
                    $AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            }
            finally { $script:Busy = $false }
            Local-RefreshGrid
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })

    $export.Add_Click({
        try {
            $items = New-Object System.Collections.ArrayList
            if ($grid.SelectedRows.Count -gt 0) {
                foreach ($row in $grid.SelectedRows) { if ($null -ne $row.Tag) { [void]$items.Add($row.Tag) } }
            }
            else {
                foreach ($row in $grid.Rows) {
                    if ($null -ne $row.Tag) { [void]$items.Add($row.Tag) }
                }
            }
            if ($items.Count -eq 0) { return }

            $saveDialog = [System.Windows.Forms.SaveFileDialog]::new()
            $saveDialog.Title = 'Экспорт маршрутов в BAT'
            $saveDialog.Filter = 'BAT (*.bat)|*.bat|Text (*.txt)|*.txt'
            $saveDialog.FileName = 'keenetic-routes.bat'
            if ($saveDialog.ShowDialog($dialog) -ne [System.Windows.Forms.DialogResult]::OK) { return }

            $output = New-Object System.Collections.ArrayList
            [void]$output.Add('@echo off')
            [void]$output.Add('rem Exported by Keenetic WG & Routes')
            foreach ($route in $items) {
                if ($route.Family -ne 'IPv4') {
                    [void]$output.Add("rem IPv6: $($route.RawLine)")
                    continue
                }
                if (-not [string]::IsNullOrWhiteSpace($route.Comment)) { [void]$output.Add("rem $($route.Comment)") }
                $destination = $route.Destination
                $mask = '255.255.255.255'
                $ip = $destination
                if ($destination -match '^(?<ip>[^/]+)/(?<prefix>\d+)$') {
                    $ip = $Matches.ip
                    $prefix = [int]$Matches.prefix
                    $bits = ('1' * $prefix).PadRight(32,'0')
                    $octets = @()
                    for ($i=0; $i -lt 32; $i+=8) { $octets += [Convert]::ToInt32($bits.Substring($i,8),2) }
                    $mask = $octets -join '.'
                }
                elseif ($destination -eq 'default') {
                    $ip = '0.0.0.0'
                    $mask = '0.0.0.0'
                }
                [void]$output.Add("route add $ip mask $mask 0.0.0.0")
            }
            [IO.File]::WriteAllLines($saveDialog.FileName,@($output),[Text.Encoding]::ASCII)
            [System.Windows.Forms.MessageBox]::Show("Экспортировано: $($items.Count)",$AppName) | Out-Null
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,$AppName) | Out-Null
        }
    })

    $backups.Add_Click({
        if (-not (Test-Path -LiteralPath $RouteBackupDir)) { New-Item -ItemType Directory -Path $RouteBackupDir -Force | Out-Null }
        Start-Process explorer.exe -ArgumentList ('"{0}"' -f $RouteBackupDir)
    })
    $close.Add_Click({ $dialog.Close() })

    Local-RefreshGrid
    [void]$dialog.ShowDialog($mainForm)
    $script:RouteManagerRoutes = @()
}


# ---------------- MAIN WINDOW ----------------
$mutex = [Threading.Mutex]::new($false,'Local\KeeneticWGUpdater_v1')
if (-not $mutex.WaitOne(0)) {
    [System.Windows.Forms.MessageBox]::Show('Keenetic WG Updater уже запущен.',$AppName,[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    exit 0
}

$mainForm = [System.Windows.Forms.Form]::new()
$mainForm.Text = $AppName
$mainForm.ClientSize = [System.Drawing.Size]::new(640, 520)
$mainForm.MinimumSize = [System.Drawing.Size]::new(656, 559)
$mainForm.MaximumSize = [System.Drawing.Size]::new(656, 559)
$mainForm.StartPosition = 'CenterScreen'
$mainForm.FormBorderStyle = 'FixedSingle'
$mainForm.MaximizeBox = $false

$script:AppIcon = $null
$appIconPath = Join-Path (Split-Path -Parent $PSCommandPath) 'Keenetic-WG-Updater.ico'
if (Test-Path -LiteralPath $appIconPath) {
    try {
        $script:AppIcon = [System.Drawing.Icon]::new($appIconPath)
        $mainForm.ShowIcon = $true
        $mainForm.Icon = $script:AppIcon
    } catch {}
}

$wireGuardTab = [System.Windows.Forms.Panel]::new()
$wireGuardTab.Location = [System.Drawing.Point]::new(14, 14)
$wireGuardTab.Size = [System.Drawing.Size]::new(612, 450)
$wireGuardTab.BorderStyle = 'FixedSingle'
$mainForm.Controls.Add($wireGuardTab)

$wireGuardTitleLabel = [System.Windows.Forms.Label]::new()
$wireGuardTitleLabel.Text = 'Keenetic WireGuard / AmneziaWG Updater'
$wireGuardTitleLabel.Font = [System.Drawing.Font]::new('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
$wireGuardTitleLabel.AutoSize = $true
$wireGuardTitleLabel.Location = [System.Drawing.Point]::new(24, 16)
$wireGuardTab.Controls.Add($wireGuardTitleLabel)

$wireGuardDescriptionLabel = [System.Windows.Forms.Label]::new()
$wireGuardDescriptionLabel.Text = 'Safe update: startup/running backup + маршруты + DPAPI rollback. Интерфейс не удаляется.'
$wireGuardDescriptionLabel.Font = [System.Drawing.Font]::new('Segoe UI', 8.2)
$wireGuardDescriptionLabel.ForeColor = [System.Drawing.Color]::DimGray
$wireGuardDescriptionLabel.Size = [System.Drawing.Size]::new(524, 34)
$wireGuardDescriptionLabel.Location = [System.Drawing.Point]::new(27, 50)
$wireGuardTab.Controls.Add($wireGuardDescriptionLabel)

$wireGuardInterfaceLabel = [System.Windows.Forms.Label]::new()
$wireGuardInterfaceLabel.Text = 'Интерфейс:'
$wireGuardInterfaceLabel.AutoSize = $true
$wireGuardInterfaceLabel.Location = [System.Drawing.Point]::new(28, 92)
$wireGuardTab.Controls.Add($wireGuardInterfaceLabel)

$wireGuardInterfaceCombo = [System.Windows.Forms.ComboBox]::new()
$wireGuardInterfaceCombo.DropDownStyle = 'DropDownList'
$wireGuardInterfaceCombo.Location = [System.Drawing.Point]::new(112, 86)
$wireGuardInterfaceCombo.Size = [System.Drawing.Size]::new(160, 30)
$wireGuardTab.Controls.Add($wireGuardInterfaceCombo)

$wireGuardRefreshButton = [System.Windows.Forms.Button]::new()
$wireGuardRefreshButton.Text = 'Обновить список'
$wireGuardRefreshButton.Size = [System.Drawing.Size]::new(128, 34)
$wireGuardRefreshButton.Location = [System.Drawing.Point]::new(284, 83)
$wireGuardTab.Controls.Add($wireGuardRefreshButton)

$wireGuardBrowseButton = [System.Windows.Forms.Button]::new()
$wireGuardBrowseButton.Text = 'Выбрать .conf…'
$wireGuardBrowseButton.Size = [System.Drawing.Size]::new(128, 34)
$wireGuardBrowseButton.Location = [System.Drawing.Point]::new(424, 83)
$wireGuardTab.Controls.Add($wireGuardBrowseButton)


$wireGuardConfigPathBox = [System.Windows.Forms.TextBox]::new()
$wireGuardConfigPathBox.ReadOnly = $true
$wireGuardConfigPathBox.Location = [System.Drawing.Point]::new(28, 126)
$wireGuardConfigPathBox.Size = [System.Drawing.Size]::new(524, 27)
$wireGuardConfigPathBox.Text = 'Файл не выбран'
$wireGuardTab.Controls.Add($wireGuardConfigPathBox)

$wireGuardPreviewBox = [System.Windows.Forms.TextBox]::new()
$wireGuardPreviewBox.Multiline = $true
$wireGuardPreviewBox.ReadOnly = $true
$wireGuardPreviewBox.ScrollBars = 'Vertical'
$wireGuardPreviewBox.Location = [System.Drawing.Point]::new(28, 161)
$wireGuardPreviewBox.Size = [System.Drawing.Size]::new(524, 100)
$wireGuardPreviewBox.Text = "Перетащите .conf сюда или нажмите «Выбрать .conf…».`r`nПеред первым обновлением сохраните ТЕКУЩИЙ рабочий .conf как rollback-базу."
$wireGuardTab.Controls.Add($wireGuardPreviewBox)

$wireGuardBaselineStateLabel = [System.Windows.Forms.Label]::new()
$wireGuardBaselineStateLabel.Font = [System.Drawing.Font]::new('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
$wireGuardBaselineStateLabel.ForeColor = [System.Drawing.Color]::DarkOrange
$wireGuardBaselineStateLabel.Size = [System.Drawing.Size]::new(220, 22)
$wireGuardBaselineStateLabel.Location = [System.Drawing.Point]::new(28, 268)
$wireGuardBaselineStateLabel.Text = 'Rollback: НЕ задан'
$wireGuardTab.Controls.Add($wireGuardBaselineStateLabel)

# Main actions: one aligned row, equal button sizes.
$wireGuardBaselineButton = [System.Windows.Forms.Button]::new()
$wireGuardBaselineButton.Text = 'Сделать rollback-базой'
$wireGuardBaselineButton.Size = [System.Drawing.Size]::new(168, 36)
$wireGuardBaselineButton.Location = [System.Drawing.Point]::new(28, 289)
$wireGuardBaselineButton.Enabled = $false
$wireGuardTab.Controls.Add($wireGuardBaselineButton)

$wireGuardApplyButton = [System.Windows.Forms.Button]::new()
$wireGuardApplyButton.Text = 'Безопасно обновить'
$wireGuardApplyButton.Size = [System.Drawing.Size]::new(168, 36)
$wireGuardApplyButton.Location = [System.Drawing.Point]::new(206, 289)
$wireGuardApplyButton.Enabled = $false
$wireGuardTab.Controls.Add($wireGuardApplyButton)

$wireGuardRollbackButton = [System.Windows.Forms.Button]::new()
$wireGuardRollbackButton.Text = 'Откатить обновление'
$wireGuardRollbackButton.Size = [System.Drawing.Size]::new(168, 36)
$wireGuardRollbackButton.Location = [System.Drawing.Point]::new(384, 289)
$wireGuardRollbackButton.Enabled = $false
$wireGuardTab.Controls.Add($wireGuardRollbackButton)

# Service actions: second aligned row, same widths/heights.
$credentialButton = [System.Windows.Forms.Button]::new()
$credentialButton.Text = 'Доступ Keenetic…'
$credentialButton.Size = [System.Drawing.Size]::new(168, 34)
$credentialButton.Location = [System.Drawing.Point]::new(28, 333)
$wireGuardTab.Controls.Add($credentialButton)

$wireGuardBackupButton = [System.Windows.Forms.Button]::new()
$wireGuardBackupButton.Text = 'Safety-бэкапы'
$wireGuardBackupButton.Size = [System.Drawing.Size]::new(168, 34)
$wireGuardBackupButton.Location = [System.Drawing.Point]::new(206, 333)
$wireGuardTab.Controls.Add($wireGuardBackupButton)

$wireGuardRestoreButton = [System.Windows.Forms.Button]::new()
$wireGuardRestoreButton.Text = 'Startup-config…'
$wireGuardRestoreButton.Size = [System.Drawing.Size]::new(168, 34)
$wireGuardRestoreButton.Location = [System.Drawing.Point]::new(384, 333)
$wireGuardTab.Controls.Add($wireGuardRestoreButton)

$wireGuardStatusLabel = [System.Windows.Forms.Label]::new()
$wireGuardStatusLabel.Font = [System.Drawing.Font]::new('Segoe UI', 8.2)
$wireGuardStatusLabel.ForeColor = [System.Drawing.Color]::DimGray
$wireGuardStatusLabel.Size = [System.Drawing.Size]::new(524, 66)
$wireGuardStatusLabel.Location = [System.Drawing.Point]::new(28, 374)
$wireGuardStatusLabel.Text = 'Получаем состояние Keenetic…'
$wireGuardTab.Controls.Add($wireGuardStatusLabel)

$logButton = [System.Windows.Forms.Button]::new()
$logButton.Text = 'Лог'
$logButton.Size = [System.Drawing.Size]::new(170, 34)
$logButton.Location = [System.Drawing.Point]::new(14, 476)
$mainForm.Controls.Add($logButton)

$routeManagerButton = [System.Windows.Forms.Button]::new()
$routeManagerButton.Text = 'Маршруты…'
$routeManagerButton.Size = [System.Drawing.Size]::new(170, 34)
$routeManagerButton.Location = [System.Drawing.Point]::new(235, 476)
$mainForm.Controls.Add($routeManagerButton)

$closeButton = [System.Windows.Forms.Button]::new()
$closeButton.Text = 'Закрыть'
$closeButton.Size = [System.Drawing.Size]::new(170, 34)
$closeButton.Location = [System.Drawing.Point]::new(456, 476)
$mainForm.Controls.Add($closeButton)

foreach ($dropTarget in @($wireGuardTab,$wireGuardConfigPathBox,$wireGuardPreviewBox)) {
    $dropTarget.AllowDrop = $true
    $dropTarget.Add_DragEnter({ param($sender,$eventArgs) Handle-WireGuardDragEnter -Sender $sender -EventArgs $eventArgs })
    $dropTarget.Add_DragDrop({ param($sender,$eventArgs) Handle-WireGuardDragDrop -Sender $sender -EventArgs $eventArgs })
}

$wireGuardRefreshButton.Add_Click({ Refresh-WireGuardInterfaces })
$wireGuardBrowseButton.Add_Click({ Select-WireGuardConfigFile })
$wireGuardBaselineButton.Add_Click({ Save-LoadedWireGuardAsBaseline })
$wireGuardApplyButton.Add_Click({ Start-WireGuardConfigUpdate })
$wireGuardRollbackButton.Add_Click({ Start-WireGuardLastUpdateRollback })
$wireGuardRestoreButton.Add_Click({ Select-AndRestoreStartupBackup })
$wireGuardInterfaceCombo.Add_SelectedIndexChanged({ Update-WireGuardUiState; Update-WireGuardRuntimeStatusLabel })
$credentialButton.Add_Click({ Show-KeeneticCredentialDialog })
$wireGuardBackupButton.Add_Click({
    if (-not (Test-Path -LiteralPath $WireGuardBackupDir)) { New-Item -ItemType Directory -Path $WireGuardBackupDir -Force | Out-Null }
    Start-Process explorer.exe -ArgumentList ('"{0}"' -f $WireGuardBackupDir)
})
$routeManagerButton.Add_Click({ Show-RouteManager; try { Update-WireGuardRuntimeStatusLabel } catch {} })
$logButton.Add_Click({
    if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType File -Path $LogPath -Force | Out-Null }
    Start-Process notepad.exe -ArgumentList ('"{0}"' -f $LogPath)
})
$closeButton.Add_Click({ $mainForm.Close() })

$statusTimer = [System.Windows.Forms.Timer]::new()
$statusTimer.Interval = 15000
$statusTimer.Add_Tick({
    if (-not $script:Busy -and $wireGuardInterfaceCombo.Items.Count -gt 0) {
        try { Update-WireGuardRuntimeStatusLabel } catch {}
    }
})

Write-Log 'Keenetic WG & Routes v1.3.4 запущен.'

if (-not (Test-Path -LiteralPath $CredentialPath)) {
    $wireGuardStatusLabel.Text = 'Нажмите «Доступ Keenetic…» и сохраните адрес роутера, логин и пароль.'
} else {
    $wireGuardStatusLabel.Text = 'Окно готово. Подключаемся к Keenetic…'
}

# Важно: никаких сетевых запросов к Keenetic до показа главного окна.
# Иначе runtime-ошибка/таймаут на первичном опросе выглядит как «программа не запускается».
$mainForm.Add_Shown({
    if (Test-Path -LiteralPath $CredentialPath) {
        try {
            Refresh-WireGuardInterfaces
        }
        catch {
            Close-KeeneticSession
            $message = $_.Exception.Message
            Write-Log "Startup refresh error: $message"
            $wireGuardStatusLabel.Text = "Keenetic пока недоступен: $message"
        }
    }
    $statusTimer.Start()
})

try {
    [System.Windows.Forms.Application]::Run($mainForm)
}
finally {
    $statusTimer.Stop()
    $statusTimer.Dispose()
    Close-KeeneticSession
    if ($null -ne $script:AppIcon) { try { $script:AppIcon.Dispose() } catch {} }
    try { $mutex.ReleaseMutex() | Out-Null } catch {}
    $mutex.Dispose()
}
