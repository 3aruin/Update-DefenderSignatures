# Update-DefenderSignatures

A PowerShell remediation script for **N-able N-sight RMM** that forces a
Microsoft Defender signature update and confirms it actually landed.

## Why this exists

The classic false positive: a workstation is off over the weekend, boots
Monday morning, and N-sight's Daily Safety Check runs its Antivirus Update
Check before Defender has had a chance to pull current signatures. The check
fails, a ticket gets raised, and there's nothing actually wrong.

This script is meant to run automatically in response to that failure. It
re-triggers a signature update through a few different methods, waits, and
re-checks. If definitions are current afterward, the underlying alert clears on
its next check run. If they're still stale, it exits with a code that tells you
why.

For the debugging view — control flow diagram, failure modes, and what to do
about each exit code — see [ARCHITECTURE.md](ARCHITECTURE.md).

## How it works

1. Confirms it is running elevated. Without administrator or SYSTEM rights
   every update method fails on access denied, and the resulting error points
   at the wrong thing entirely.
2. Reads current Defender status (`Get-MpComputerStatus`).
3. Checks `AMRunningMode`. If Defender is passive because a third-party AV owns
   the device, that's a healthy machine and the script stops there rather than
   reporting a problem. Older Defender platforms don't expose this property;
   the script logs that it couldn't tell and continues.
4. Starts the `WinDefend` service if it isn't running, polling for it to come
   up, and re-checks before continuing — no point trying to force an update
   against a service that never started.
5. Optionally (`-Harden`) tightens the device's own update schedule, then reads
   the values back so you can see whether policy overrode them.
6. Tries, in order, each inside a background job with a timeout:
   - `Update-MpSignature -UpdateSource MicrosoftUpdateServer`
   - `Update-MpSignature -UpdateSource MMPC`
   - `MpCmdRun.exe -SignatureUpdate` (located under
     `%ProgramData%\Microsoft\Windows Defender\Platform`, picking the
     highest-versioned platform folder present)
7. Polls Defender status every 5 seconds up to `-WaitSeconds`, stopping as soon
   as definitions are current, and compares signature age, signature version
   and real-time protection state to pick an exit code.

## Deploying in N-sight

1. Add the script under **Automated Tasks**.
2. Set it to run **as SYSTEM** via the Advanced Monitoring Agent (no user
   context needed).
3. Set the frequency method to **On Check Failure**, triggered by the
   **Antivirus Update Check**.
4. Leave parameters at their defaults, or override as needed (see below).

Check the agent's task timeout against the script's worst case: three update
attempts at `-UpdateTimeoutSeconds` each, plus `-WaitSeconds`. At the defaults
that is a little over six minutes. Lower `-UpdateTimeoutSeconds` if your agent
is configured tighter.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-MaxAgeDays` | int | `1` | Signature age, in days, that counts as current. |
| `-WaitSeconds` | int | `20` | Ceiling for the post-update verification loop. Status is polled every 5 seconds and the script returns as soon as definitions are current. |
| `-UpdateTimeoutSeconds` | int | `120` | Per-attempt ceiling for each update method. Bounds the run so a hung update can't be killed mid-flight by the agent's own timeout. |
| `-Harden` | switch | off | Also sets `SignatureUpdateInterval` (8h) and `SignatureUpdateCatchupInterval` (1d), then logs the effective values. Where GPO or Intune manages these, the write still succeeds but policy wins when Defender reads it — the log shows the difference. |

## Exit codes

N-sight marks the task failed on any non-zero exit code. Codes `0` and
`1001`–`1005` mean what they meant in 1.0.0; `1006`–`1008` are new in 1.1.0 and
split cases that were previously reported as `1002` or `1004`.

| Code | Meaning |
|------|---------|
| `0` | Definitions confirmed current and real-time protection is on. |
| `1001` | Defender not present, not the active AV (passive mode), the service couldn't be started, or the script isn't running elevated. |
| `1002` | New definitions applied but they're still older than `-MaxAgeDays`. |
| `1003` | Every update method failed or timed out — check internet access, proxy config, and WSUS approval of definition updates. |
| `1004` | Definitions are current, but real-time protection is off. |
| `1005` | Unexpected/unhandled error — check the log output for details. |
| `1006` | Defender status couldn't be re-read after an update that reported success. Investigate Defender/WMI health, not definition delivery. |
| `1007` | Definitions are stale **and** real-time protection is off. Highest priority of the failure codes. |
| `1008` | An update method reported success but the signature version never moved — the update source isn't offering current definitions. |

## Local testing

Run interactively (as administrator) to see the log output without needing
N-sight:

```powershell
.\Update-DefenderSignatures.ps1 -MaxAgeDays 2 -WaitSeconds 15
$LASTEXITCODE
```

There's no `-Verbose` output to enable. Everything the script has to say goes
to stdout on a single stream, because that's the only stream the Advanced
Monitoring Agent reliably captures — a diagnostic that only appears when
someone remembers to pass a switch is a diagnostic that isn't there at 8am.

If you get `... is not digitally signed. You cannot run this script...`,
that's PowerShell's execution policy blocking unsigned scripts, not a problem
with the script itself. Check which scope is enforcing it:

```powershell
Get-ExecutionPolicy -List
```

If `MachinePolicy` or `UserPolicy` shows a restrictive value, that's coming
from Group Policy and can't be overridden locally. Otherwise, bypass it for
a single run without changing anything system-wide:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Update-DefenderSignatures.ps1
```

### Execution policy in production

Scripts run by N-sight's Advanced Monitoring Agent are subject to the same
local execution policy as an interactive session — the agent doesn't bypass
it. N-able ships a **Set PowerShell Execution Policy** Automation Manager
object for exactly this reason. Two ways to handle it:

- Add that object ahead of this script in an Automation Manager policy to
  set `RemoteSigned` or `Bypass` on target endpoints, or
- Sign this script with a code-signing certificate, which is the only thing
  that satisfies `AllSigned` and works regardless of a given endpoint's
  policy. Recommended if you're deploying across machines whose execution
  policy you don't fully control.

## Requirements

- Windows with Microsoft Defender as the active antivirus.
- PowerShell 5.1+ (ships with Windows 10/11 and Server 2016+). No PowerShell 7
  syntax is used, and no external modules are required.
- Run with local administrator / SYSTEM privileges.

## Contributing

CI runs PSScriptAnalyzer on every push and pull request that touches a `.ps1`
file, and **fails the build on warnings as well as errors**. If a finding is a
false positive, add an inline `SuppressMessageAttribute` with a justification
rather than loosening the gate.

## License

[MIT](LICENSE)
