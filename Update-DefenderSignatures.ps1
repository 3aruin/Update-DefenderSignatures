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

    Order of operations: confirm elevation, read Defender status, confirm
    Defender is the active AV rather than passive behind a third-party product,
    start the AM service if it is stopped, optionally tighten the update
    schedule, then try three update methods in order until one succeeds, then
    poll status until the definitions are current or the wait ceiling expires.

    All output goes to stdout on a single stream. The Advanced Monitoring Agent
    reliably captures stdout and nothing else, so there is no verbose stream and
    no warning stream to enable - a diagnostic that only appears when someone
    remembers to pass a switch is a diagnostic that is not there at 8am.

.PARAMETER MaxAgeDays
    Signature age (in days) that counts as current. Default 1.

.PARAMETER WaitSeconds
    Ceiling for the post-update verification loop. Status is polled every 5
    seconds and the script stops as soon as definitions are current, so a
    healthy device finishes well inside this. Default 20.

.PARAMETER UpdateTimeoutSeconds
    Per-attempt ceiling for each update method. Update-MpSignature has no
    timeout of its own and can block for minutes against a broken WSUS; without
    a ceiling the agent's own task timeout kills the run and the log is lost.
    Worst case is three attempts at this value plus -WaitSeconds, so keep that
    total below the agent's task timeout. Default 120.

.PARAMETER Harden
    Also applies SignatureUpdateInterval (8h) and SignatureUpdateCatchupInterval
    (1d) so the device is less likely to fall behind again, then reads the
    values back and logs the effective figures. Where GPO or Intune manages
    these settings the write still succeeds and policy wins at read time, so the
    read-back is the only honest report of what Defender will actually use.

.EXAMPLE
    .\Update-DefenderSignatures.ps1

    Runs with defaults: signatures older than 1 day are treated as stale, each
    update method is given 120 seconds, and status is polled for up to 20
    seconds afterwards.

.EXAMPLE
    .\Update-DefenderSignatures.ps1 -MaxAgeDays 2 -WaitSeconds 30 -Harden

    Allows definitions up to 2 days old, polls for up to 30 seconds after the
    update, and tightens the device's own signature update schedule going
    forward.

.EXAMPLE
    .\Update-DefenderSignatures.ps1 -UpdateTimeoutSeconds 45

    Bounds each update method at 45 seconds instead of 120, for an agent
    configured with a task timeout tighter than the default worst case.

.NOTES
    Exit codes (non-zero marks the task as failed in N-sight):
      0    - definitions confirmed current and real-time protection is on, or
             Defender is passive behind a third-party AV and there is nothing
             for this script to remediate
      1001 - Defender not present, the service could not be started, or the
             script is not running elevated
      1002 - new definitions applied but they are still older than -MaxAgeDays
      1003 - every update method failed or timed out - check internet access,
             proxy configuration, and WSUS approval of definition updates
      1004 - definitions are current, but real-time protection is off
      1005 - unexpected/unhandled error - see the log output for details
      1006 - Defender status could not be re-read after an update that reported
             success - investigate Defender/WMI health, not definition delivery
      1007 - definitions are stale and real-time protection is off - the highest
             priority of the failure codes
      1008 - an update method reported success but the signature version never
             moved - the update source is not offering current definitions

    Version 1.2.0. See CHANGELOG.md for what changed and ARCHITECTURE.md for the
    control flow diagram and the full exit code contract.
#>

[CmdletBinding()]
param(
    [ValidateRange(0, 30)]
    [int]$MaxAgeDays = 1,

    [ValidateRange(0, 300)]
    [int]$WaitSeconds = 20,

    [ValidateRange(30, 600)]
    [int]$UpdateTimeoutSeconds = 120,

    [switch]$Harden
)

$ErrorActionPreference = 'Stop'

# Keeping the codes in one place means the mapping in .NOTES never drifts
# from what the script actually returns. Every terminal path below uses a
# named key; there are no numeric exit literals anywhere else in this file.
$ExitCodes = @{
    Success               = 0

    # Deliberately 0, and deliberately a separate key. A device where a
    # third-party AV owns Defender is healthy, so failing the task on it
    # raises a ticket nobody can action: the device is working as designed
    # and no change to it would ever clear the alert. The key exists so the
    # exit site still reads as its own outcome rather than as "success",
    # and so this decision is visible here rather than buried in the branch.
    NotActiveAntivirus    = 0

    DefenderUnavailable   = 1001
    StillStale            = 1002
    AllUpdatesFailed      = 1003
    RealTimeProtectionOff = 1004
    UnexpectedError       = 1005
    StatusReadFailed      = 1006
    StaleAndUnprotected   = 1007
    UpdateAppliedNothing  = 1008
}

# Poll cadence for both wait loops. A script constant rather than a parameter:
# Get-MpComputerStatus is a WMI call, and 5 seconds catches most updates on the
# first or second poll while keeping the log short enough to read.
$PollIntervalSeconds = 5

# Ceiling for WinDefend reaching 'Running' after Start-Service. Not a parameter
# because a service that has not started in 30 seconds is not going to.
$ServiceStartTimeoutSeconds = 30

# Write-Log writes to the success stream, which is also a function's return
# path. Helpers that both log and produce a result therefore hand the result
# back through a [ref] parameter instead of returning it, so their log lines
# reach stdout as they happen rather than being swallowed by the caller's
# assignment.

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message
    )

    # MpCmdRun.exe emits blank lines. A mandatory [string] implicitly rejects
    # '', and the resulting binding exception would surface through the outer
    # catch as 1005 - the fallback update path dying through its own logging.
    if ($null -eq $Message) { $Message = '' }

    # The date matters: RMM logs are read days later, often from another time
    # zone, and a bare HH:mm:ss is not enough to place an event.
    Write-Output ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}

function Test-IsElevated {
    # SYSTEM's token is a member of BUILTIN\Administrators, so this is true
    # under the agent as well as in an elevated console. Without it, both
    # Update-MpSignature attempts fail on access denied and the run reports
    # 1003 - sending the technician to inspect a proxy and a WSUS that are fine.
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Invoke-JobWithTimeout {
    <#
        Runs a scriptblock in a background job with a hard ceiling, and hands
        back whatever the scriptblock produced through -ResultRef. A $null
        result means "no usable answer": the job could not be started, it did
        not finish in time, or it returned nothing. Callers treat all three as
        a failed attempt.

        The job is stopped and removed in a finally so it is disposed on every
        path out - timeout, success, failure, and job-infrastructure failure -
        and nothing accumulates in the runspace across three attempts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [ref]$ResultRef,

        [object[]]$ArgumentList = @()
    )

    $ResultRef.Value = $null
    $job = $null

    try {
        try {
            $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
        catch {
            # Start-Job is a dependency with its own failure mode - constrained
            # language mode, a broken component. Name it, because the run will
            # otherwise report 1003 and read like a network problem.
            Write-Log ("{0}: background job could not be started: {1}" -f $Description, $_.Exception.Message)
            Write-Log "This is a job infrastructure failure on the endpoint, not a definition delivery failure."
            return
        }

        $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue
        if ($null -eq $finished) {
            Write-Log ("{0}: no response within {1}s - abandoning this method." -f $Description, $TimeoutSeconds)
            # Stop-Job in the finally terminates the child process. Any
            # definition download Defender started on its own carries on; that
            # is Defender's business, not this script's.
            return
        }

        $received = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
        $ResultRef.Value = $received |
                           Where-Object { $null -ne $_ } |
                           Select-Object -Last 1
    }
    finally {
        if ($null -ne $job) {
            Stop-Job   -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Wait-ForServiceRunning {
    <#
        Polls a service for 'Running' up to a ceiling, replacing a fixed sleep
        that was either a waste of the agent's time or not long enough.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [ref]$IsRunningRef,

        [int]$IntervalSeconds = 2
    )

    $IsRunningRef.Value = $false
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $poll     = 0

    while ($true) {
        $poll++
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue

        if ($null -eq $service) {
            Write-Log ("Service poll {0}: {1} not found." -f $poll, $Name)
        }
        else {
            Write-Log ("Service poll {0}: {1} is {2}." -f $poll, $Name, $service.Status)
            if ($service.Status -eq 'Running') {
                $IsRunningRef.Value = $true
                return
            }
        }

        # Clamp the sleep to what is left so the ceiling is real rather than
        # the ceiling plus one whole interval.
        $remaining = ($deadline - (Get-Date)).TotalSeconds
        if ($remaining -le 0) { return }
        $sleep = [int][math]::Ceiling([math]::Min($IntervalSeconds, $remaining))
        if ($sleep -lt 1) { $sleep = 1 }
        Start-Sleep -Seconds $sleep
    }
}

function Wait-ForSignatureRefresh {
    <#
        Polls Defender status until the signature age is within the threshold
        or the ceiling expires, and hands back the last status object it
        managed to read - $null if it never read one at all.

        This replaces a fixed Start-Sleep for the whole wait window: a device
        that updates in two seconds should not hold the agent's task open for
        twenty.
    #>
    param(
        [Parameter(Mandatory)]
        [int]$MaxAgeDays,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [ref]$StatusRef,

        [int]$IntervalSeconds = 5
    )

    $StatusRef.Value = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $poll     = 0

    while ($true) {
        $poll++
        $current = $null
        try {
            $current = Get-MpComputerStatus -ErrorAction Stop
        }
        catch {
            Write-Log ("Status poll {0}: Get-MpComputerStatus failed: {1}" -f $poll, $_.Exception.Message)
        }

        if ($null -ne $current) {
            # Keep the last reading that actually worked, so a single failed
            # poll at the end of the window does not lose an earlier answer.
            $StatusRef.Value = $current
            $age = $current.AntivirusSignatureAge

            if ($null -eq $age) {
                Write-Log ("Status poll {0}: signature age not reported." -f $poll)
            }
            else {
                Write-Log ("Status poll {0}: signature age {1} day(s), version {2}." -f $poll, $age, $current.AntivirusSignatureVersion)
                if ($age -le $MaxAgeDays) {
                    Write-Log ("Signature age is within the {0} day threshold - no need to keep polling." -f $MaxAgeDays)
                    return
                }
            }
        }

        # Clamp the sleep to the time remaining so -WaitSeconds is a real
        # ceiling rather than a lower bound.
        $remaining = ($deadline - (Get-Date)).TotalSeconds
        if ($remaining -le 0) { return }
        $sleep = [int][math]::Ceiling([math]::Min($IntervalSeconds, $remaining))
        if ($sleep -lt 1) { $sleep = 1 }
        Start-Sleep -Seconds $sleep
    }
}

# Each update method runs in its own runspace, so these scriptblocks cannot see
# anything above. They catch their own failures and return a structured result
# rather than letting Receive-Job decide how an error should surface.

$UpdateSignatureScript = {
    param($UpdateSource)

    try {
        Update-MpSignature -UpdateSource $UpdateSource -ErrorAction Stop
        [pscustomobject]@{ Succeeded = $true;  Message = '' }
    }
    catch {
        [pscustomobject]@{ Succeeded = $false; Message = $_.Exception.Message }
    }
}

$MpCmdRunScript = {
    param($ExePath)

    # 'Stop' turns redirected stderr from a native command into a terminating
    # NativeCommandError in Windows PowerShell 5.1, which would report 1005
    # where 1003 is the truth. The job relaxes the preference for itself only;
    # the script-level preference is never weakened.
    $ErrorActionPreference = 'Continue'

    # A stale $LASTEXITCODE from an earlier command makes a failed launch look
    # like a successful update. Remove it rather than assigning 0, which would
    # create a script-scope shadow the engine never updates.
    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue

    $lines = & $ExePath -SignatureUpdate 2>&1 | ForEach-Object { $_.ToString() }

    # If the variable is still absent the process never ran, so there is no
    # exit code to trust. The caller treats that as a failed attempt.
    $exitCode = $null
    if (Test-Path Variable:\LASTEXITCODE) { $exitCode = $LASTEXITCODE }

    [pscustomobject]@{ Lines = @($lines); ExitCode = $exitCode }
}

# The whole body runs inside one try/catch so a genuinely unexpected error
# still logs something useful and returns a non-zero exit code instead of
# dying silently. The deliberate `exit N` calls below are unaffected by this -
# `exit` ends the process immediately and is never routed through a catch.
try {

    # --- Startup --------------------------------------------------------------

    # [TimeZoneInfo]::Local rather than Get-TimeZone: command discovery failures
    # are terminating regardless of -ErrorAction, so a missing cmdlet here would
    # have produced 1005 before the script had logged anything at all.
    Write-Log "Update-DefenderSignatures 1.2.0 starting."
    Write-Log ("Parameters               : MaxAgeDays={0}, WaitSeconds={1}, UpdateTimeoutSeconds={2}, Harden={3}" -f $MaxAgeDays, $WaitSeconds, $UpdateTimeoutSeconds, [bool]$Harden)
    Write-Log ("Local time zone          : {0}" -f [System.TimeZoneInfo]::Local.Id)

    # --- Pre-flight -----------------------------------------------------------

    if (-not (Test-IsElevated)) {
        Write-Log "Not running elevated. Every update method below would fail on access denied."
        Write-Log "Check the N-sight task configuration: this must run as SYSTEM under the Advanced Monitoring Agent."
        exit $ExitCodes.DefenderUnavailable
    }
    Write-Log "Elevation                : confirmed (administrator or SYSTEM)."

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

    # Passive-mode Defender is the false positive this whole script exists to
    # suppress: on a device owned by a third-party AV, Get-MpComputerStatus
    # succeeds, AMServiceEnabled is $true and RealTimeProtectionEnabled is
    # correctly $false, so reading only those two produces a confident 1004 on
    # a perfectly healthy machine - across the whole estate at once.
    #
    # Read through PSObject.Properties so an absent property is distinguishable
    # from a passive one. AMRunningMode does not exist before platform
    # 4.18.2011; failing closed on an old-but-healthy platform would be worse
    # than the false positive it prevents, so absence is inconclusive and the
    # run continues.
    $runningModeProperty = $before.PSObject.Properties['AMRunningMode']
    if ($null -eq $runningModeProperty -or $null -eq $runningModeProperty.Value) {
        Write-Log "Running mode             : not reported (Defender platform older than 4.18.2011)."
        Write-Log "Passive-mode detection is inconclusive on this platform. Continuing."
    }
    else {
        $runningMode = $runningModeProperty.Value
        Write-Log ("Running mode             : {0}" -f $runningMode)
        if ($runningMode -ne 'Normal') {
            Write-Log ("Defender is not the active antivirus on this device (running mode '{0}')." -f $runningMode)
            Write-Log "This is a healthy machine owned by another AV product. Defender's own definitions and real-time protection are expected to look stale and off here, so there is nothing to remediate and nothing to raise."
            Write-Log "Exiting 0 so the task does not fail. Point the Antivirus Update Check at the third-party product, or exclude this device from it, to stop the check firing in the first place."
            exit $ExitCodes.NotActiveAntivirus
        }
    }

    if (-not $before.AMServiceEnabled) {
        Write-Log "AM service not enabled - attempting to start WinDefend."
        try {
            Start-Service -Name 'WinDefend' -ErrorAction Stop
        }
        catch {
            # Tamper Protection returns a generic access denial that reads like
            # any other permissions error, and it is the usual cause. Naming it
            # saves twenty minutes of checking ACLs that are fine.
            Write-Log "Could not start WinDefend: $($_.Exception.Message)"
            Write-Log "Tamper Protection is the usual cause: it blocks service control even for SYSTEM, and cannot be turned off from a script."
        }

        Write-Log ("Polling WinDefend for 'Running' for up to {0}s..." -f $ServiceStartTimeoutSeconds)
        $serviceRunning = $false
        Wait-ForServiceRunning -Name 'WinDefend' -TimeoutSeconds $ServiceStartTimeoutSeconds -IsRunningRef ([ref]$serviceRunning)
        if (-not $serviceRunning) {
            Write-Log ("WinDefend did not reach 'Running' within {0}s." -f $ServiceStartTimeoutSeconds)
        }

        # Re-read rather than assume the start took. The poll result is logged
        # separately from the AM service state so the log distinguishes "the
        # service never started" from "the service started but Defender still
        # reports its AM service as disabled"; Defender's own view of the AM
        # service is what decides, since that is what the update methods need.
        $recheck = $null
        try {
            $recheck = Get-MpComputerStatus -ErrorAction Stop
        }
        catch {
            Write-Log "Could not re-read Defender status after the service start attempt: $($_.Exception.Message)"
        }

        if ($null -eq $recheck) {
            Write-Log "Defender status is unreadable. Nothing more this script can do."
            exit $ExitCodes.DefenderUnavailable
        }
        if (-not $recheck.AMServiceEnabled) {
            Write-Log "WinDefend is still not providing an enabled AM service. Nothing more this script can do."
            exit $ExitCodes.DefenderUnavailable
        }

        Write-Log "AM service is now enabled."
        $before = $recheck
    }

    # --- Harden (optional, and the only thing this script writes) -------------

    if ($Harden) {
        # Check every 8 hours; catch up if a scheduled update was missed for 1 day.
        $requestedInterval = 8
        $requestedCatchup  = 1

        try {
            Set-MpPreference -SignatureUpdateInterval $requestedInterval -SignatureUpdateCatchupInterval $requestedCatchup -ErrorAction Stop
            Write-Log ("Requested SignatureUpdateInterval={0}h, SignatureUpdateCatchupInterval={1}d." -f $requestedInterval, $requestedCatchup)
        }
        catch {
            Write-Log "Could not apply update preferences: $($_.Exception.Message)"
        }

        # Set-MpPreference succeeds on policy-managed devices and policy wins at
        # read time rather than the write being rejected, so reporting the write
        # as a success is misleading. The read-back is the only honest report of
        # what Defender will actually use.
        try {
            $preference = Get-MpPreference -ErrorAction Stop
            Write-Log ("Effective SignatureUpdateInterval        : {0}" -f $preference.SignatureUpdateInterval)
            Write-Log ("Effective SignatureUpdateCatchupInterval : {0}" -f $preference.SignatureUpdateCatchupInterval)
            if ($preference.SignatureUpdateInterval -ne $requestedInterval -or
                $preference.SignatureUpdateCatchupInterval -ne $requestedCatchup) {
                Write-Log "Effective values differ from those requested: GPO or Intune manages these settings and the local write is inert. Fix this in policy, not here."
            }
        }
        catch {
            Write-Log "Could not read Defender preferences back: $($_.Exception.Message)"
        }
    }

    # --- Update ---------------------------------------------------------------

    # Order is deliberate. MicrosoftUpdateServer respects local infrastructure
    # first; MMPC routes around a WSUS that has not approved this week's
    # definitions; MpCmdRun.exe bypasses the PowerShell module and the WMI layer
    # entirely, so it is a genuinely different failure surface rather than a
    # third try at the same thing.
    $updated = $false

    foreach ($updateSource in @('MicrosoftUpdateServer', 'MMPC')) {
        $description = "Update-MpSignature -UpdateSource $updateSource"
        Write-Log ("Trying {0} (ceiling {1}s)..." -f $description, $UpdateTimeoutSeconds)

        $attemptResult = $null
        Invoke-JobWithTimeout -Description $description `
                              -ScriptBlock $UpdateSignatureScript `
                              -ArgumentList @($updateSource) `
                              -TimeoutSeconds $UpdateTimeoutSeconds `
                              -ResultRef ([ref]$attemptResult)

        if ($null -eq $attemptResult) {
            Write-Log ("{0} produced no result." -f $description)
            continue
        }
        if ($attemptResult.Succeeded) {
            Write-Log ("{0} completed." -f $description)
            $updated = $true
            break
        }
        Write-Log ("{0} failed: {1}" -f $description, $attemptResult.Message)
    }

    if (-not $updated) {
        $mpCmdRun = Get-MpCmdRunPath
        if ($null -eq $mpCmdRun) {
            Write-Log "MpCmdRun.exe could not be located; no fallback available."
        }
        else {
            $description = "$mpCmdRun -SignatureUpdate"
            Write-Log ("Falling back to {0} (ceiling {1}s)..." -f $description, $UpdateTimeoutSeconds)

            $mpCmdRunResult = $null
            Invoke-JobWithTimeout -Description $description `
                                  -ScriptBlock $MpCmdRunScript `
                                  -ArgumentList @($mpCmdRun) `
                                  -TimeoutSeconds $UpdateTimeoutSeconds `
                                  -ResultRef ([ref]$mpCmdRunResult)

            if ($null -eq $mpCmdRunResult) {
                Write-Log ("{0} produced no result." -f $description)
            }
            else {
                foreach ($line in @($mpCmdRunResult.Lines)) { Write-Log $line }

                if ($null -eq $mpCmdRunResult.ExitCode) {
                    Write-Log "MpCmdRun.exe set no exit code, so the process never ran. Treating this as a failed update."
                }
                elseif ($mpCmdRunResult.ExitCode -eq 0) {
                    Write-Log "MpCmdRun.exe -SignatureUpdate completed."
                    $updated = $true
                }
                else {
                    Write-Log ("MpCmdRun.exe exited with code {0}." -f $mpCmdRunResult.ExitCode)
                }
            }
        }
    }

    if (-not $updated) {
        Write-Log "All signature update methods failed."
        Write-Log "Check internet access, proxy configuration, and whether WSUS approves definition updates."
        exit $ExitCodes.AllUpdatesFailed
    }

    # --- Verify ---------------------------------------------------------------

    Write-Log ("Polling Defender status every {0}s for up to {1}s..." -f $PollIntervalSeconds, $WaitSeconds)
    $after = $null
    Wait-ForSignatureRefresh -MaxAgeDays $MaxAgeDays `
                             -TimeoutSeconds $WaitSeconds `
                             -IntervalSeconds $PollIntervalSeconds `
                             -StatusRef ([ref]$after)

    # An unreadable status after an update that reported success is a Defender
    # or WMI health problem, not a definition delivery problem, and it deserves
    # a different ticket than "still stale". A $null age is the same situation:
    # $null -le 1 is $true in PowerShell, so without this guard a status object
    # missing the property would be reported as a successful update.
    if ($null -eq $after -or $null -eq $after.AntivirusSignatureAge) {
        Write-Log "Defender status could not be read after the update reported success."
        Write-Log "Investigate Defender/WMI health on this device - run Get-MpComputerStatus by hand. This is not a definitions problem."
        exit $ExitCodes.StatusReadFailed
    }

    $versionChanged = $after.AntivirusSignatureVersion -ne $before.AntivirusSignatureVersion

    # Captured once and evaluated on every terminal path below. Reading it only
    # on the success path lost the more serious finding on a device that was
    # both stale and unprotected.
    $realTimeProtectionOn = [bool]$after.RealTimeProtectionEnabled

    Write-Log ("New signature version    : {0} (changed: {1})" -f $after.AntivirusSignatureVersion, $versionChanged)
    Write-Log ("New last updated         : {0}" -f $after.AntivirusSignatureLastUpdated)
    Write-Log ("New signature age (days) : {0}" -f $after.AntivirusSignatureAge)
    Write-Log ("Real-time protection     : {0}" -f $realTimeProtectionOn)

    if ($after.AntivirusSignatureAge -le $MaxAgeDays) {
        if (-not $realTimeProtectionOn) {
            Write-Log "Definitions are current, but real-time protection is OFF. Raising for review."
            exit $ExitCodes.RealTimeProtectionOff
        }
        if (-not $versionChanged) {
            Write-Log "Definitions were already current and the version did not move - the original check failure was a timing artefact."
        }
        Write-Log ("SUCCESS - definitions are {0} day(s) old (threshold {1})." -f $after.AntivirusSignatureAge, $MaxAgeDays)
        exit $ExitCodes.Success
    }

    # Stale is bad; stale and unprotected is worse, so it is evaluated ahead of
    # the version-change split and the more serious finding wins the exit code.
    if (-not $realTimeProtectionOn) {
        Write-Log ("STALE AND UNPROTECTED - definitions are {0} day(s) old and real-time protection is OFF." -f $after.AntivirusSignatureAge)
        Write-Log "Treat as the highest priority of the failure codes. Check real-time protection first, definitions second."
        exit $ExitCodes.StaleAndUnprotected
    }

    if ($versionChanged) {
        Write-Log ("STILL STALE - new definitions applied but they are {0} day(s) old (threshold {1})." -f $after.AntivirusSignatureAge, $MaxAgeDays)
        Write-Log "Compare the before/after version lines, then check the device clock and the update source's own definition age."
        exit $ExitCodes.StillStale
    }

    Write-Log ("UPDATE APPLIED NOTHING - an update method reported success but the signature version never moved, and definitions are {0} day(s) old." -f $after.AntivirusSignatureAge)
    Write-Log "This is a source problem, not an endpoint problem. Check what the configured update source is actually offering."
    exit $ExitCodes.UpdateAppliedNothing
}
catch {
    Write-Log "UNEXPECTED ERROR: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-Log $_.ScriptStackTrace }
    exit $ExitCodes.UnexpectedError
}
