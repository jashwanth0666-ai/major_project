param([switch]$Rotate)

$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$appData = if ($env:APPDATA) { $env:APPDATA } else { [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData) }
if ([string]::IsNullOrWhiteSpace($appData)) { throw 'The current user application-data folder is unavailable.' }
$directory = Join-Path $appData 'AIWatchDog\auth'
$defaultTokenPath = Join-Path $directory 'api-tokens.json'
$tokenPath = if ($env:AI_WATCHDOG_TOKEN_FILE) { $env:AI_WATCHDOG_TOKEN_FILE } else { $defaultTokenPath }
$isDefaultPath = [IO.Path]::GetFullPath($tokenPath) -eq [IO.Path]::GetFullPath($defaultTokenPath)
$tokenPath = [IO.Path]::GetFullPath($tokenPath)
$directory = Split-Path -Parent $tokenPath
New-Item -ItemType Directory -Path $directory -Force | Out-Null

# Restrict only the dedicated default directory. A custom token path may share a
# parent with unrelated files, so its parent ACL is left untouched.
if ($isDefaultPath) {
    & icacls.exe $directory /inheritance:r /grant:r "$identity`:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the AI WatchDog credential directory.' }
}

$tokens = $null
if ((Test-Path -LiteralPath $tokenPath) -and -not $Rotate) {
    try { $tokens = Get-Content -LiteralPath $tokenPath -Raw | ConvertFrom-Json } catch { throw 'The existing credential file is invalid. Rotate it deliberately with -Rotate.' }
    foreach ($name in @('desktop', 'extension', 'springToMl')) {
        $value = [string]$tokens.$name
        if ($value.Length -lt 64 -or $value -notmatch '^[a-f0-9]+$') { throw "The existing credential file is missing a valid $name token. Rotate it deliberately with -Rotate." }
    }
} else {
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $newTokens = @{}
        foreach ($name in @('desktop', 'extension', 'springToMl')) {
            $bytes = New-Object byte[] 32
            $generator.GetBytes($bytes)
            $newTokens[$name] = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        }
    } finally { $generator.Dispose() }
    $temporaryPath = "$tokenPath.tmp"
    $json = $newTokens | ConvertTo-Json
    [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $tokenPath -Force
}

& icacls.exe $tokenPath /inheritance:r /grant:r "$identity`:F" 'SYSTEM:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the AI WatchDog credential file.' }
Write-Output "AI WatchDog local credentials are ready: $tokenPath"
Write-Output 'For the browser extension, enter only the extension token in its Options page.'
