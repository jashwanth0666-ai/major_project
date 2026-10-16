$ErrorActionPreference = 'Stop'
$queue = [System.Collections.Concurrent.BlockingCollection[object]]::new(512)
$dropCounter = [hashtable]::Synchronized(@{ Value = [long]0; Gate = [object]::new() })
$shared = @{ Queue = $queue; DropCounter = $dropCounter }
$watchers = [System.Collections.Generic.List[object]]::new()
$subscriptions = [System.Collections.Generic.List[object]]::new()

function Write-JsonLine($value) {
    [Console]::Out.WriteLine(($value | ConvertTo-Json -Compress -Depth 4))
    [Console]::Out.Flush()
}

$windowsTelemetryEnabled = $env:AIWD_WINDOWS_ENABLED -eq 'true'
$scriptMonitoringEnabled = $env:AIWD_SCRIPT_ENABLED -eq 'true'
$processMonitoringEnabled = $env:AIWD_PROCESS_ENABLED -eq 'true'
$configs = [System.Collections.Generic.List[object]]::new()
$securityEventIds = [System.Collections.Generic.List[int]]::new()
if ($windowsTelemetryEnabled) {
    $configs.Add(@{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Provider = 'Defender Operational'; Ids = @(1116, 1117, 1118, 5007) })
    foreach ($id in @(1102, 4697, 4698, 4719)) { $securityEventIds.Add($id) }
}
if ($processMonitoringEnabled) {
    foreach ($id in @(4688, 4689)) { $securityEventIds.Add($id) }
}
if ($securityEventIds.Count -gt 0) {
    $configs.Add(@{ LogName = 'Security'; Provider = 'Windows Security'; Ids = @($securityEventIds.ToArray()) })
}
if ($scriptMonitoringEnabled) {
    $configs.Add(@{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Provider = 'PowerShell Operational'; Ids = @(4104) })
}

foreach ($config in $configs) {
    try {
        $log = Get-WinEvent -ListLog $config.LogName -ErrorAction Stop
        if (-not $log.IsEnabled) {
            Write-JsonLine @{ kind = 'provider'; provider = $config.Provider; state = 'DISABLED'; errorCategory = 'LOG_DISABLED'; message = 'Windows event log is disabled.' }
            continue
        }
        $conditions = @($config.Ids | ForEach-Object { "EventID=$($_)" }) -join ' or '
        $xpath = "*[System[($conditions)]]"
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $config.LogName,
            [System.Diagnostics.Eventing.Reader.PathType]::LogName,
            $xpath)
        $watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($query, $null, $false)
        $provider = $config.Provider
        $subscription = Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten `
            -SourceIdentifier ("AIWatchDog-" + ($provider -replace '[^A-Za-z0-9]', '')) `
            -MessageData @{ Queue = $queue; Provider = $provider; LogName = $config.LogName; DropCounter = $dropCounter } `
            -Action {
                $sharedState = $Event.MessageData
                $eventArgs = $Event.SourceEventArgs
                if ($eventArgs.EventException) {
                    $item = @{ kind = 'provider-error'; provider = $sharedState.Provider; errorCategory = 'EVENT_DELIVERY_ERROR' }
                } elseif ($eventArgs.EventRecord) {
                    $record = $eventArgs.EventRecord
                    $timestamp = if ($record.TimeCreated) { $record.TimeCreated.ToUniversalTime().ToString('o') } else { [DateTime]::UtcNow.ToString('o') }
                    $item = @{
                        kind = 'event'
                        logName = $sharedState.LogName
                        providerName = [string]$record.ProviderName
                        eventId = [int]$record.Id
                        recordId = [long]$record.RecordId
                        timestampUtc = $timestamp
                    }
                    if ($record.Id -in @(4104, 4688, 4689)) {
                        $fields = @{}
                        try {
                            $eventXml = [xml]$record.ToXml()
                            foreach ($data in $eventXml.SelectNodes("//*[local-name()='Data']")) {
                                if ($data.Name) { $fields[[string]$data.Name] = [string]$data.InnerText }
                            }
                            if ($record.Id -eq 4104) {
                                $content = $fields['ScriptBlockText']
                                if ($content -and $content.Length -le 32768) {
                                    $item.transientContent = $content
                                    $item.processId = [long]$record.ProcessId
                                    $item.scriptBlockId = $fields['ScriptBlockId']
                                    try { $item.scriptMessageNumber = [int]$fields['MessageNumber'] } catch { $item.scriptMessageNumber = 1 }
                                    try { $item.scriptMessageTotal = [int]$fields['MessageTotal'] } catch { $item.scriptMessageTotal = 1 }
                                }
                            } else {
                                $name = if ($fields['NewProcessName']) { $fields['NewProcessName'] } else { $fields['ProcessName'] }
                                $pidText = if ($fields['NewProcessId']) { $fields['NewProcessId'] } else { $fields['ProcessId'] }
                                $parentText = if ($fields['CreatorProcessId']) { $fields['CreatorProcessId'] } else { $fields['ProcessId'] }
                                $parentName = if ($fields['ParentProcessName']) { $fields['ParentProcessName'] } else { $fields['CreatorProcessName'] }
                                $pidValue = $null
                                $parentValue = $null
                                try { if ($pidText) { $pidValue = [Convert]::ToInt64(([string]$pidText).Replace('0x',''), 16) } } catch { }
                                try { if ($parentText) { $parentValue = [Convert]::ToInt64(([string]$parentText).Replace('0x',''), 16) } } catch { }
                                $item.processName = $name
                                $item.processId = $pidValue
                                $item.parentProcessName = $parentName
                                $item.parentProcessId = $parentValue
                                if ($record.Id -eq 4688 -and $fields['CommandLine'] -and $fields['CommandLine'].Length -le 4096) {
                                    $item.transientContent = [string]$fields['CommandLine']
                                }
                            }
                        } catch {
                            # Core event metadata remains available; payload analysis is skipped on parse errors.
                        }
                    }
                    $record.Dispose()
                } else { return }
                if (-not $sharedState.Queue.TryAdd($item)) {
                    [System.Threading.Monitor]::Enter($sharedState.DropCounter.Gate)
                    try { $sharedState.DropCounter.Value = [long]$sharedState.DropCounter.Value + 1 }
                    finally { [System.Threading.Monitor]::Exit($sharedState.DropCounter.Gate) }
                }
            }
        $watcher.Enabled = $true
        $watchers.Add($watcher)
        $subscriptions.Add($subscription)
        Write-JsonLine @{ kind = 'provider'; provider = $config.Provider; state = 'SUBSCRIBED'; message = 'Filtered Windows Event Log subscription is active; audit policy was not changed.' }
    } catch {
        $category = if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception -is [System.Security.SecurityException]) { 'ACCESS_DENIED' } else { 'LOG_OR_SUBSCRIPTION_UNAVAILABLE' }
        Write-JsonLine @{ kind = 'provider'; provider = $config.Provider; state = 'UNAVAILABLE'; errorCategory = $category; message = 'Windows Event Log is unavailable to this process or its provider could not be subscribed.' }
    }
}

$defenderService = $null
if ($windowsTelemetryEnabled) { try {
    $defenderService = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    $serviceState = if ($null -eq $defenderService) { 'NOT_INSTALLED' } elseif ($defenderService.Status -eq 'Running') { 'RUNNING' } else { 'STOPPED' }
    Write-JsonLine @{ kind = 'provider'; provider = 'Defender Antivirus service'; state = $serviceState; message = 'Service state only; this does not report scan or protection efficacy.' }
} catch {
    Write-JsonLine @{ kind = 'provider'; provider = 'Defender Antivirus service'; state = 'UNAVAILABLE'; errorCategory = 'SERVICE_STATUS_UNAVAILABLE'; message = 'Defender Antivirus service state could not be read.' }
} } else {
    Write-JsonLine @{ kind = 'provider'; provider = 'Defender Operational'; state = 'DISABLED'; message = 'Defender event monitoring is disabled.' }
    Write-JsonLine @{ kind = 'provider'; provider = 'Windows Security'; state = if ($processMonitoringEnabled) { 'STARTING' } else { 'DISABLED' }; message = 'Windows Security events are collected only for enabled modules.' }
    Write-JsonLine @{ kind = 'provider'; provider = 'Defender Antivirus service'; state = 'DISABLED'; message = 'Defender service status is not requested while Defender telemetry is disabled.' }
}
if (-not $scriptMonitoringEnabled) {
    Write-JsonLine @{ kind = 'provider'; provider = 'PowerShell Operational'; state = 'DISABLED'; message = 'PowerShell script monitoring is disabled.' }
}

$lastHealth = [DateTime]::UtcNow
while ($true) {
    $item = $null
    if ($queue.TryTake([ref]$item, 1000)) {
        Write-JsonLine $item
        $item = $null
        while ($queue.TryTake([ref]$item, 0)) {
            Write-JsonLine $item
            $item = $null
        }
    }
    if (([DateTime]::UtcNow - $lastHealth).TotalSeconds -ge 5) {
        [System.Threading.Monitor]::Enter($dropCounter.Gate)
        try { $dropped = [long]$dropCounter.Value }
        finally { [System.Threading.Monitor]::Exit($dropCounter.Gate) }
        Write-JsonLine @{ kind = 'collector'; state = 'RUNNING'; droppedEvents = $dropped }
        $lastHealth = [DateTime]::UtcNow
    }
}
