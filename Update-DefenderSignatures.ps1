#Requires -Version 5.1
<#
.SYNOPSIS
    Forces a Microsoft Defender signature update and verifies the result.

.DESCRIPTION
    Written for N-able N-sight RMM as an Automated Task with the frequency method
    "On Check Failure", triggered by the Antivirus Update Check.

    Intended for the common false-positive pattern: a device is off over the
    weekend, boots Monday morning, the Daily Safety Check runs before Defender
    has pulled current signatures, and the AV Update Check fails.

    Runs as SYSTEM under the Advanced Monitoring Agent. No user context needed.

.PARAMETER MaxAgeDays
    Signature age (in days) that counts as current. Default 1.

.PARAMETER WaitSeconds
    Pause after the update before re-reading Defender status. Default 20.

.PARAMETER Harden
    Also applies SignatureUpdateInterval / SignatureUpdateCatchupInterval so the
    device is less likely to fall behind again. Ignored where GPO or Intune
    manages these settings.

.EXAMPLE
    .\Update-DefenderSignatures.ps1

    Runs with defaults: signatures older than 1 day are treated as stale, and
    the script waits 20 seconds after triggering an update before checking again.

.EXAMPLE
    .\Update-DefenderSignatures.ps1 -MaxAgeDays 2 -WaitSeconds 30 -Harden

    Allows definitions up to 2 days old, waits 30 seconds after the update, and
    tightens the device's own signature update schedule going forward.

.NOTES
    Exit codes (non-zero marks the task as failed in N-sight):
      0    - definitions confirmed current
      1001 - Defender not present, not the active AV, or service unavailable
      1002 - update ran but definitions are still stale
      1003 - every update method failed (likely network, WSUS or proxy)
      1004 - definitions current but real-time protection is off
      1005 - unexpected/unhandled error - see the log output for details
#>

[CmdletBinding()]
param(
    [ValidateRange(0, 30)]
    [int]$MaxAgeDays = 1,

    [ValidateRange(0, 300)]
    [int]$WaitSeconds = 20,

    [switch]$Harden
)

$ErrorActionPreference = 'Stop'

# Keeping the codes in one place means the mapping in .NOTES never drifts
# from what the script actually returns.
$ExitCodes = @{
    Success               = 0
    DefenderUnavailable   = 1001
    StillStale            = 1002
    AllUpdatesFailed      = 1003
    RealTimeProtectionOff = 1004
    UnexpectedError       = 1005
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message)
}

function Get-MpCmdRunPath {
    # The active Defender platform lives under ProgramData, not Program Files.
    # Platform folders are named after their version (e.g. 4.18.24030.7), so
    # sort on the parsed version rather than LastWriteTime, which can be
    # touched by things other than a genuine platform update.
    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path $platformRoot) {
        $newest = Get-ChildItem $platformRoot -Directory -ErrorAction SilentlyContinue |
                  Sort-Object -Property {
                      $ver = $_.Name -replace '-\d+$', ''
                      try { [version]$ver } catch { [version]'0.0' }
                  } -Descending |
                  Select-Object -First 1
        if ($newest) {
            $candidate = Join-Path $newest.FullName 'MpCmdRun.exe'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    $fallback = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}

# The whole body runs inside one try/catch so a genuinely unexpected error
# still logs something useful and returns a non-zero exit code instead of
# dying silently. The deliberate `exit N` calls below are unaffected by this -
# `exit` ends the process immediately and is never routed through a catch.
try {

    # --- Pre-flight -----------------------------------------------------------

    try {
        $before = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-Log "Get-MpComputerStatus failed: $($_.Exception.Message)"
        Write-Log "This device is probably running a third-party AV, or WinDefend is disabled."
        exit $ExitCodes.DefenderUnavailable
    }

    Write-Log ("Defender service enabled : {0}" -f $before.AMServiceEnabled)
    Write-Log ("Real-time protection     : {0}" -f $before.RealTimeProtectionEnabled)
    Write-Log ("Signature version        : {0}" -f $before.AntivirusSignatureVersion)
    Write-Log ("Signature last updated   : {0}" -f $before.AntivirusSignatureLastUpdated)
    Write-Log ("Signature age (days)     : {0}" -f $before.AntivirusSignatureAge)

    if (-not $before.AMServiceEnabled) {
        Write-Log "AM service not enabled - attempting to start WinDefend."
        try {
            Start-Service WinDefend -ErrorAction Stop
            Start-Sleep -Seconds 10
        }
        catch {
            Write-Log "Could not start WinDefend: $($_.Exception.Message)"
        }

        # Re-check rather than assume the start worked - no point trying an
        # update against a service that still isn't running.
        $recheck = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if (-not $recheck -or -not $recheck.AMServiceEnabled) {
            Write-Log "WinDefend is still not running. Nothing more this script can do."
            exit $ExitCodes.DefenderUnavailable
        }
        $before = $recheck
    }

    if ($Harden) {
        try {
            # Check every 8 hours; catch up if a scheduled update was missed for 1 day.
            Set-MpPreference -SignatureUpdateInterval 8 -SignatureUpdateCatchupInterval 1 -ErrorAction Stop
            Write-Log "Applied SignatureUpdateInterval=8h, SignatureUpdateCatchupInterval=1d."
        }
        catch {
            Write-Log "Could not apply update preferences (likely GPO/Intune managed): $($_.Exception.Message)"
        }
    }

    # --- Update -----------------------------------------------------------------

    $updated  = $false
    $attempts = @(
        @{ Name = 'Update-MpSignature (MicrosoftUpdateServer)';
           Action = { Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop } },
        @{ Name = 'Update-MpSignature (MMPC)';
           Action = { Update-MpSignature -UpdateSource MMPC -ErrorAction Stop } }
    )

    foreach ($attempt in $attempts) {
        try {
            Write-Log ("Trying {0}..." -f $attempt.Name)
            & $attempt.Action
            Write-Log ("{0} completed." -f $attempt.Name)
            $updated = $true
            break
        }
        catch {
            Write-Log ("{0} failed: {1}" -f $attempt.Name, $_.Exception.Message)
        }
    }

    if (-not $updated) {
        $mpCmdRun = Get-MpCmdRunPath
        if ($mpCmdRun) {
            Write-Log ("Falling back to {0} -SignatureUpdate" -f $mpCmdRun)
            & $mpCmdRun -SignatureUpdate 2>&1 | ForEach-Object { Write-Log $_ }
            if ($LASTEXITCODE -eq 0) {
                $updated = $true
            }
            else {
                Write-Log ("MpCmdRun.exe exited with code {0}." -f $LASTEXITCODE)
            }
        }
        else {
            Write-Log "MpCmdRun.exe could not be located."
        }
    }

    if (-not $updated) {
        Write-Log "All signature update methods failed."
        Write-Log "Check internet access, proxy configuration, and whether WSUS approves definition updates."
        exit $ExitCodes.AllUpdatesFailed
    }

    # --- Verify -------------------------------------------------------------------

    Start-Sleep -Seconds $WaitSeconds

    try {
        $after = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-Log "Could not re-read Defender status after update: $($_.Exception.Message)"
        exit $ExitCodes.StillStale
    }

    $versionChanged = $after.AntivirusSignatureVersion -ne $before.AntivirusSignatureVersion

    Write-Log ("New signature version    : {0} (changed: {1})" -f $after.AntivirusSignatureVersion, $versionChanged)
    Write-Log ("New last updated         : {0}" -f $after.AntivirusSignatureLastUpdated)
    Write-Log ("New signature age (days) : {0}" -f $after.AntivirusSignatureAge)

    if ($after.AntivirusSignatureAge -le $MaxAgeDays) {
        if (-not $after.RealTimeProtectionEnabled) {
            Write-Log "Definitions are current, but real-time protection is OFF. Raising for review."
            exit $ExitCodes.RealTimeProtectionOff
        }
        Write-Log ("SUCCESS - definitions are {0} day(s) old (threshold {1})." -f $after.AntivirusSignatureAge, $MaxAgeDays)
        exit $ExitCodes.Success
    }

    Write-Log ("STILL STALE - {0} day(s) old after update. Manual investigation required." -f $after.AntivirusSignatureAge)
    exit $ExitCodes.StillStale
}
catch {
    Write-Log "UNEXPECTED ERROR: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace }
    exit $ExitCodes.UnexpectedError
}
