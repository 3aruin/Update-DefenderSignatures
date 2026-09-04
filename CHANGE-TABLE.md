# Change table — audit findings to fixes

Line numbers refer to the shipped `Update-DefenderSignatures.ps1` (561 lines).

## P1 — production-breaking

| # | Finding | What changed | Where |
|---|---------|--------------|-------|
| 1 | `Write-Log` rejects empty strings | `$Message` now carries `[AllowNull()]` and `[AllowEmptyString()]`, with a `$null` guard in the body. Blank `MpCmdRun.exe` lines log as blank lines instead of throwing a binding exception into the outer catch. | `Update-DefenderSignatures.ps1:109-126` |
| 2 | `2>&1` under `$ErrorActionPreference = 'Stop'` | The native call moved into a job scriptblock that sets `$ErrorActionPreference = 'Continue'` for itself only. The script-level preference is never modified, and the parent process never sees the redirected stream. | `Update-DefenderSignatures.ps1:441-460` (preference at `:445`) |
| 3 | `$LASTEXITCODE` not reset | `Remove-Variable -Name LASTEXITCODE -Scope Global` immediately before the call; afterwards `Test-Path Variable:\LASTEXITCODE` decides whether a code was actually produced, and its absence is treated as failure. Deliberately *not* `$LASTEXITCODE = 0`, which would create a script-scope shadow that the engine never updates. | `Update-DefenderSignatures.ps1:447-457`, consumed at `:466-482` |
| 4 | Passive-mode Defender undetectable | `AMRunningMode` read via `PSObject.Properties` so an absent property is distinguishable from a passive one. Anything other than `Normal` exits `1001` before any update is attempted; absence is logged as inconclusive and allowed to continue. | `Update-DefenderSignatures.ps1:324-347` |
| 5 | No elevation check | `Test-IsElevated` (WindowsPrincipal / BUILTIN\Administrators, which SYSTEM's token satisfies) runs as the first pre-flight step and exits `1001` naming the N-sight task configuration as the likely cause. | `Update-DefenderSignatures.ps1:127-134`, called at `:300-307` |

## P2 — reliability and logic

| # | Finding | What changed | Where |
|---|---------|--------------|-------|
| 6 | Fixed sleep replaced with polling | `Wait-ForSignatureRefresh` polls every 5s with `-WaitSeconds` as the ceiling, logs each poll, and breaks as soon as age is within threshold. Sleep is clamped to the remaining time so the ceiling is real. | `:238-283`, called at `:502` |
| 7 | `$versionChanged` never acted on | Now selects between `1002` (new definitions, still too old) and `1008` (source reported success, version never moved). On the success path an unchanged version is logged as "the original check failure was a timing artefact". | `:514`, `:528-530`, `:545-551` |
| 8 | `1002` overloaded | Post-update status read failure now exits `1006`, with a log line pointing at Defender/WMI health rather than definition delivery. A `$null` `AntivirusSignatureAge` takes the same path. | `:505-511` |
| 9 | RTP only checked on success path | RTP is captured once and evaluated on every terminal path. Stale + RTP off exits `1007`, which is ordered ahead of the version-change checks so the more serious finding wins. | `:517`, `:526-542` |
| 10 | `Update-MpSignature` unbounded | `Invoke-JobWithTimeout` wraps all three methods. The job is stopped and removed in a `finally`, so it is disposed on the timeout path, the success path, the failure path, and the job-infrastructure-failed path. | `:158-214`, used at `:413` and `:462` |
| 11 | Fixed 10s sleep after `Start-Service` | `Wait-ForServiceRunning` polls for `Running` up to 30s, then the AM service state is re-read before continuing. | `:218-236`, called at `:358` |
| 12 | Tamper Protection unnamed | `catch` retained, log line now names Tamper Protection as the usual cause and notes it blocks service control even for SYSTEM. | `:353-356` |
| 13 | Timestamps lack the date | `Write-Log` format is now `yyyy-MM-dd HH:mm:ss`, and a startup line records the local time zone ID. | `:124`, `:296` |

## P3 — documentation drift

| # | Finding | What changed | Where |
|---|---------|--------------|-------|
| 14 | `-Verbose` example does nothing | **Chose to correct the README**, not to add `Write-Verbose`. The agent reliably captures stdout only; a diagnostic that appears only when someone passes a switch is not a diagnostic that helps at 8am. `[CmdletBinding()]` stays for common-parameter support. | `README.md` "Local testing"; rationale also in `ARCHITECTURE.md` "Execution model" |
| 15 | `-Harden` "skipped automatically" claim | Reworded: the write succeeds, policy wins at read time. The script now reads values back with `Get-MpPreference` and logs the effective figures, plus an explicit line when they differ from what was requested. | `README.md` parameters table; script `:376-390`; help block `.PARAMETER Harden` |
| 16 | `1001` documented as covering "not the active AV" | The code can now actually detect it (finding 4), so the documented meaning is accurate. Wording aligned across `.NOTES`, README and ARCHITECTURE. | `.NOTES` (script `:58-70`), `README.md`, `ARCHITECTURE.md` |
| 17 | `1002`'s documented meaning didn't cover the status-read path | Split out to `1006`; `1002` is now documented narrowly as "new definitions applied but still older than `-MaxAgeDays`". | `.NOTES` (script `:58-70`), `README.md`, `ARCHITECTURE.md` |

## Repo and CI

| # | Finding | What changed | Where |
|---|---------|--------------|-------|
| 18 | Workflow at repo root | Moved to `.github/workflows/psscriptanalyzer.yml`. The project files were surfaced to me flattened, so if it already lived at that path in the repo, this is a no-op — but the path filter in the file pointed there while the file itself did not, which is the signature of a workflow that has never run. | `.github/workflows/psscriptanalyzer.yml` |
| 19 | No `permissions` block | Added `permissions: contents: read`. | workflow, top level |
| 20 | Warnings never gated the build | **Behaviour change, per your instruction:** warnings now fail the build alongside errors, and every finding is emitted as a GitHub annotation. A build that previously passed with warnings will now fail. The shipped script was written to be clean at `-Severity Warning,Error` without suppressions. | workflow `run:` step |
| 21 | README links a missing `LICENSE` | Added MIT `LICENSE`. **The copyright line reads "Update-DefenderSignatures contributors" — replace with the actual holder before publishing.** | `LICENSE` |

## Keeping the three sources in sync

The `$ExitCodes` hashtable is the single source of truth. Every terminal path
uses a named key rather than a literal, so the numbers cannot drift. Around
that:

1. `$ExitCodes` (script `:91-101`) defines code and name.
2. `.NOTES` (script `:58-70`) lists the same nine codes in numeric order, one
   line each.
3. `README.md` "Exit codes" repeats them with the operator-facing phrasing.
4. `ARCHITECTURE.md` "Exit code contract" adds likely cause, first diagnostic
   step, and recoverability.

I generated the `.NOTES` block from the hashtable last, after the control flow
was final, then propagated the same wording outward to README and ARCHITECTURE
so all three read consistently. Verified: 13 `exit` statements resolving to nine
distinct codes (`1001` is reached from five pre-flight paths), nine keys in the
hashtable, and nine rows in each of the three tables — same numbers, same
meanings. If a code is ever added, all four places need touching —
worth a line in a PR checklist.

## Assumptions made

- **Polling interval: 5s**, per your answer, as a script constant rather than a
  parameter. `Get-MpComputerStatus` is a WMI call; 5s catches most updates on
  the first or second poll and keeps the log short. Documented in
  `ARCHITECTURE.md`.
- **Update timeout: 120s per attempt**, exposed as `-UpdateTimeoutSeconds`
  (range 30–600) rather than hard-coded, since "the goal is success" and the
  right ceiling depends on the estate's link quality. Worst case is
  `3 x 120 + WaitSeconds`, a little over six minutes. **This must stay below
  your agent's task timeout** — please check that value; if it is under six
  minutes, lower the default.
- **New codes `1006`–`1008`** rather than reusing `1002`/`1004`, per the "codes
  above 1005" constraint. Runbooks referencing `1002` for a status-read failure
  will need updating, but that case was almost certainly being misdiagnosed
  anyway.
- **`AMRunningMode` absent is treated as "cannot tell", not as passive.**
  Failing closed on an old-but-healthy platform is worse than the false
  positive it would prevent.
- **`MpCmdRun.exe` also runs in a bounded job**, though the audit only asked for
  `Update-MpSignature`. It can hang for the same reasons, and it made the
  stderr and `$LASTEXITCODE` fixes cleaner to express.

## Things the audit missed

1. **`Get-MpComputerStatus` failing on the `AMServiceEnabled` re-check path.**
   The 1.0.0 re-check used `-ErrorAction SilentlyContinue` and then evaluated
   `-not $recheck.AMServiceEnabled`, which is `$true` when `$recheck` is
   `$null` — so it happened to work, but only by accident. Now an explicit
   `$null` check, and the service-poll result is evaluated separately from the
   AM service state so the log distinguishes "service never started" from
   "service started but AM is still disabled". (`:358-371`)
2. **`AntivirusSignatureAge` could be `$null`.** `$null -le 1` evaluates to
   `$true` in PowerShell, so a status object missing that property would have
   been reported as a successful update. Now guarded on the `1006` path.
   (`:505`)
3. **`Get-TimeZone` is not safe behind `-ErrorAction`.** Command-discovery
   failures are terminating regardless of `-ErrorAction`, so a missing cmdlet
   in the startup log line could have produced `1005`. Uses
   `[System.TimeZoneInfo]::Local` instead. (`:293-296`)
4. **`Start-Job` is a new dependency with its own failure mode.** If the job
   infrastructure cannot start, all three methods fail and the run reports
   `1003`, which is arguably the wrong code. The log names the job failure
   explicitly. Recorded under "Known limitations" in `ARCHITECTURE.md` rather
   than fixed, because the in-process alternative reintroduces the unbounded
   hang.
5. **`Wait-Job -Timeout` kills the job but not necessarily the download.**
   `Stop-Job` terminates the child process; any in-flight definition download
   Defender started on its own remains Defender's business. Harmless, but worth
   knowing before someone reads a `1003` log next to a definition file that
   later appears.

## Better handled outside this script

- **Passive-mode devices should not be running this check at all.** Exiting
  `1001` is the correct behaviour, but the real fix is an N-sight exclusion or
  a check that targets the installed AV product. Every `1001`-passive result is
  a monitoring configuration defect, not a device defect.
- **Proxy authentication for SYSTEM** belongs in WinHTTP machine-account
  configuration, not in the script.
- **Execution policy** belongs in the Automation Manager object or a
  code-signing certificate. A script that bypasses its own execution policy has
  defeated a control.
- **Staggering definition traffic** across an estate belongs in the RMM
  schedule.
- **`-Harden` on policy-managed devices** belongs in GPO or Intune. The switch
  can only report the discrepancy, never win it.
