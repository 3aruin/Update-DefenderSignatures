# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [1.1.0] - 2026-09-01

Hardening pass following an audit of the 1.0.0 release. Several of the fixes
below are for bugs that turned a working device into a ticket, which is the
opposite of what this script is for.

### Fixed
- `Write-Log` accepted `[Parameter(Mandatory)][string]$Message`, which
  implicitly rejects an empty string. `MpCmdRun.exe` emits blank lines, so
  piping its output into the logger threw a binding exception that the outer
  `try/catch` converted to `1005` — the last-resort update path died through
  its own logging. The parameter now carries `AllowEmptyString`/`AllowNull`.
- `2>&1` on `MpCmdRun.exe` under `$ErrorActionPreference = 'Stop'` turned
  redirected stderr into a terminating `NativeCommandError` in Windows
  PowerShell 5.1, again producing `1005` where `1003` was the truth. The
  native call now runs inside a job that sets `Continue` for itself only; the
  script-level preference is never weakened.
- `$LASTEXITCODE` was not cleared before invoking `MpCmdRun.exe`, so a stale
  `0` from an earlier command made a failed launch look like a successful
  update. It is now removed before the call and its absence afterwards is
  treated as failure.
- Passive-mode Defender was undetectable. On a device running a third-party
  AV, `Get-MpComputerStatus` succeeds, `AMServiceEnabled` is `$true` and
  `RealTimeProtectionEnabled` is correctly `$false` — so the script reported
  `1004` and raised a ticket for a healthy machine, at estate scale, which is
  the exact false positive it exists to suppress. `AMRunningMode` is now
  checked before anything else; anything other than `Normal` exits `1001`.
  The property is absent before platform 4.18.2011 and that absence is logged
  and allowed rather than treated as passive.
- No elevation check. Without administrator rights both `Update-MpSignature`
  attempts failed on access denied and the script reported `1003`, sending
  the technician to inspect a proxy and a WSUS that were both fine. Elevation
  is now the first thing tested, and exits `1001` naming the likely cause.
- Real-time protection was only evaluated on the success path, so a device
  that was both stale and unprotected reported `1002` and quietly lost the
  more serious of the two findings. It is now evaluated on every path.
- `$versionChanged` was computed, logged, and never used. It now distinguishes
  "new definitions arrived but are still too old" from "the update source
  reported success and delivered nothing" — different tickets, different
  first move.

### Added
- `1006`, `1007` and `1008` (see README). `1002` previously covered both
  still-stale definitions and a failed post-update status read, which are
  unrelated problems that were arriving as the same ticket.
- `-UpdateTimeoutSeconds` (default 120). `Update-MpSignature` has no timeout
  of its own and can block for minutes against a broken WSUS; if the agent's
  task timeout fired first the run was killed with no log at all, leaving a
  failed task and no explanation. Each update method now runs in a background
  job that is disposed on every path out, including timeout.
- Polling of the `WinDefend` service after `Start-Service`, replacing a fixed
  ten-second sleep that was either a waste of time or not long enough.
- Tamper Protection is now named in the log when the service fails to start.
  It returns a generic access denial that reads like any other permissions
  error, and it is the usual cause.
- Read-back of `Get-MpPreference` after `-Harden`, so a policy-managed device
  shows the effective values rather than a misleading success message.
- A startup line logging the parameters in use and the local time zone.

### Changed
- The fixed `Start-Sleep -Seconds $WaitSeconds` after an update is now a poll
  every five seconds with `-WaitSeconds` as the ceiling, so a healthy device
  finishes in a couple of seconds instead of holding the agent's task open
  for the full window.
- `Write-Log` timestamps include the date. RMM logs are read days later and
  often from another time zone; `HH:mm:ss` alone was not enough to place an
  event.
- CI now fails on PSScriptAnalyzer **warnings** as well as errors, and
  annotates findings inline on pull requests. This is a deliberate tightening:
  a build that previously passed with warnings will now fail. Suppress genuine
  false positives inline with a justification rather than relaxing the gate.
- `psscriptanalyzer.yml` moved to `.github/workflows/`. GitHub Actions only
  runs workflows from that path, so the lint job had never executed on any
  push or pull request — every finding in this release shipped through a green
  repository with no CI behind it.
- Added `permissions: contents: read` to the workflow.
- README: corrected the `-Verbose` example, which did nothing — the script has
  `[CmdletBinding()]` but never calls `Write-Verbose`, and deliberately keeps
  all output on one stream. Corrected the claim that `-Harden` is skipped where
  GPO or Intune manages the setting; `Set-MpPreference` succeeds there and
  policy wins at read time, so the `catch` almost never fires.

### Added (repository)
- `ARCHITECTURE.md` — control flow, failure modes, exit code contract, and
  testing notes, aimed at whoever is debugging this at 8am.
- `LICENSE` — MIT, which the README had linked to since 1.0.0 without the
  file being present.

### Unchanged
- Update strategy and fallback order: `Update-MpSignature`
  (MicrosoftUpdateServer -> MMPC) then `MpCmdRun.exe -SignatureUpdate`.
- Meanings and numbers of exit codes `0` and `1001`-`1005`. They are a public
  contract that tickets and runbooks reference.
- Intended N-sight deployment: Automated Task, run as SYSTEM, frequency
  method "On Check Failure" on the Antivirus Update Check.

## [1.0.0] - 2026-08-17

Initial public release, cleaned up from the original internal draft.

### Added
- Top-level `try/catch` around the whole script so an unhandled error still
  logs a message and returns a non-zero exit code (`1005`) instead of dying
  silently — `exit` statements for the expected paths still short-circuit
  the process normally and are unaffected by this.
- Re-check of `WinDefend` service status after attempting to start it, before
  trying an update. Previously the script would try to update anyway and
  eventually fail with a "check network/proxy/WSUS" message that didn't match
  the actual problem.
- Parameter validation (`-MaxAgeDays`, `-WaitSeconds`) via `ValidateRange`.
- Logging of `MpCmdRun.exe`'s exit code on failure.

### Changed
- Exit codes centralized into a single `$ExitCodes` hashtable so the mapping
  in the comment-based help can't silently drift from what the script
  actually returns.
- `Get-MpCmdRunPath` now picks the newest Defender platform folder by parsed
  version number instead of filesystem `LastWriteTime`, which can be touched
  by things unrelated to an actual platform update.

### Unchanged
- Overall update strategy and fallback order: `Update-MpSignature`
  (MicrosoftUpdateServer → MMPC) then `MpCmdRun.exe -SignatureUpdate`.
- Intended N-sight deployment: Automated Task, run as SYSTEM, frequency
  method "On Check Failure" on the Antivirus Update Check.
