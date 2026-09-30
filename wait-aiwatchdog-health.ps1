param(
    [Parameter(Mandatory = $true)] [string] $Uri,
    [Parameter(Mandatory = $true)] [int] $TimeoutSeconds,
    [switch] $RequireMl
)

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
do {
    try {
        $health = Invoke-RestMethod -Uri $Uri -TimeoutSec 3
        $isHealthy = $health.status -eq 'OK'
        if ($RequireMl) {
            $isHealthy = $isHealthy -and $health.spring_boot -eq 'UP' -and $health.ml_service -eq 'UP'
        }
        if ($isHealthy) {
            Write-Output ($health | ConvertTo-Json -Compress)
            exit 0
        }
    } catch {
        # Retry while the service starts; the caller reports the final timeout.
    }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

Write-Error "Health check failed for $Uri after $TimeoutSeconds seconds."
exit 1
