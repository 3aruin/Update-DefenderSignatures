# Architecture

Written for the engineer who has just opened a queue of failed checks and needs
to know what this script did and why. Start at the [exit code
contract](#exit-code-contract) — it is the section that resolves most tickets.

## Problem statement and blast radius

**What it solves.** N-sight's Antivirus Update Check compares Defender's
signature age against a threshold. A device that was powered off over the
weekend boots Monday, the Daily Safety Check runs before Defender has pulled
current definitions, and the check fails. Nothing is wrong with the device.
This script re-triggers the update, waits for it to land, and reports what it
found.

**Where it runs.** Every managed Windows endpoint with Defender as the active
AV, as an Automated Task, as SYSTEM, under the Advanced Monitoring Agent. It is
triggered by check failure rather than on a schedule, so on a healthy estate it
runs rarely — and on a bad Monday it runs on hundreds of devices within the
same hour.

**Blast radius if it misbehaves.**

- It writes nothing outside Defender's own preferences, and only with
  `-Harden`. Without that switch the script is read-only apart from asking
  Defender to update itself.
- The failure mode that scales badly is a wrong exit code, not a wrong action:
  a false non-zero on hundreds of devices is a ticket storm. Finding 4 in the
  1.0.0 audit was exactly this — passive-mode Defender reported `1004` on every
  device running a third-party AV.
- Each run can trigger a definition download. On an estate behind a single
  WSUS or a metered link, a synchronised Monday morning means a synchronised
  burst of definition traffic. The script does not stagger itself; if that
  matters, stagger it in the RMM.
- The script never reboots, never disables anything, and never touches Tamper
  Protection.

## Execution model

1. The Antivirus Update Check fails on a device.
2. N-sight fires the Automated Task attached to that check with the frequency
   method **On Check Failure**.
3. The agent runs the script as **SYSTEM**. There is no user context, no
   desktop, and no way to prompt — hence no `Read-Host` anywhere in the script.
4. All output goes to **stdout as one stream**. `Write-Verbose` is deliberately
   not used: the agent captures stdout, and a second stream that might be
   dropped is worse than no second stream.
5. The **process exit code** becomes the task result. Zero is a pass; anything
   else marks the task failed and raises a ticket carrying the log.
6. A passing run does not itself clear the alert. The underlying **Antivirus
   Update Check** clears on its next execution, once it sees current
   definitions. So `0` here means "the next check should pass", not "the ticket
   is closed".

Execution policy applies to the agent exactly as it does to an interactive
session — see the README for the two supported ways to handle that.

## Control flow

```mermaid
flowchart TD
    START(["Automated Task starts as SYSTEM"]) --> ELEV{"Running elevated?"}
    ELEV -- "no" --> X1001A(["1001 not elevated"])
    ELEV -- "yes" --> STATUS{"Get-MpComputerStatus succeeds?"}
    STATUS -- "no" --> X1001B(["1001 Defender unavailable"])
    STATUS -- "yes" --> MODE{"AMRunningMode Normal or absent?"}
    MODE -- "no" --> X1001C(["1001 not the active AV"])
    MODE -- "yes" --> SVC{"AMServiceEnabled?"}
    SVC -- "no" --> STARTSVC["Start WinDefend, poll to 30s"]
    STARTSVC --> SVC2{"Running and AM service enabled?"}
    SVC2 -- "no" --> X1001D(["1001 service will not start"])
    SVC2 -- "yes" --> HARD{"-Harden specified?"}
    SVC -- "yes" --> HARD
    HARD -- "yes" --> SETPREF["Set-MpPreference, then read back"]
    SETPREF --> UPD1["Attempt 1 MicrosoftUpdateServer, bounded job"]
    HARD -- "no" --> UPD1
    UPD1 --> OK1{"Succeeded?"}
    OK1 -- "no" --> UPD2["Attempt 2 MMPC, bounded job"]
    UPD2 --> OK2{"Succeeded?"}
    OK2 -- "no" --> MPC["Fallback MpCmdRun.exe, bounded job"]
    MPC --> OK3{"Exit code 0?"}
    OK3 -- "no" --> X1003(["1003 all update methods failed"])
    OK3 -- "yes" --> POLL["Poll status every 5s up to WaitSeconds"]
    OK1 -- "yes" --> POLL
    OK2 -- "yes" --> POLL
    POLL --> READ{"Status readable and age reported?"}
    READ -- "no" --> X1006(["1006 status read failed"])
    READ -- "yes" --> CUR{"Age within MaxAgeDays?"}
    CUR -- "yes" --> RTP1{"Real-time protection on?"}
    RTP1 -- "yes" --> X0(["0 definitions current"])
    RTP1 -- "no" --> X1004(["1004 current but RTP off"])
    CUR -- "no" --> RTP2{"Real-time protection on?"}
    RTP2 -- "no" --> X1007(["1007 stale and RTP off"])
    RTP2 -- "yes" --> VER{"Signature version changed?"}
    VER -- "yes" --> X1002(["1002 still stale after update"])
    VER -- "no" --> X1008(["1008 update applied nothing"])
    ANY["Unhandled error at any point"] -.-> X1005(["1005 unexpected error"])
```

In prose:

**Pre-flight.** Elevation first, because without it every downstream failure
lies about its cause. Then `Get-MpComputerStatus`, which fails outright if the
Defender module or WMI provider is not there. Then `AMRunningMode`, which is
the only reliable way to tell "Defender is the AV and it is behind" from
"Defender is dormant because another product owns this device". The property
does not exist before platform 4.18.2011, and its absence is logged and treated
as inconclusive rather than as passive — refusing to run on old platforms would
be worse than the false positive it prevents. If the AM service is off, the
script starts `WinDefend` and polls for `Running`, then re-reads status rather
than assuming the start took.

**Harden.** Optional, and the only thing the script writes. `Set-MpPreference`
is applied and then read back with `Get-MpPreference`, because policy-managed
values are silently overridden at read time rather than rejected at write time.

**Update.** Three methods in order, each in its own background job with a
`-UpdateTimeoutSeconds` ceiling. The first success ends the phase.

**Verify.** Polls `Get-MpComputerStatus` every 5 seconds up to `-WaitSeconds`
and stops as soon as the age is within threshold. Real-time protection and
signature-version movement are then evaluated together to pick the exit code.

## Exit code contract

Codes `0` and `1001`–`1005` keep the meanings they had in 1.0.0. `1006`–`1008`
are new in 1.1.0 and split cases that used to be reported as `1002` or `1004`.

| Code | Meaning | Likely cause | First diagnostic step | Auto-recoverable |
|------|---------|--------------|-----------------------|------------------|
| `0` | Definitions current, real-time protection on. | Device was simply behind; the update landed. | None. Confirm the next AV Update Check passes. | Yes — already recovered |
| `1001` | Defender not present, not the active AV, service unavailable, or the script is not elevated. | Third-party AV in passive/SxS mode; Defender disabled by policy; Tamper Protection blocking service start; task not configured to run as SYSTEM. | Read the log's `Running mode` line, then the elevation line. If mode is not `Normal`, this is a monitoring config problem, not a device problem. | No — needs a config change |
| `1002` | New definitions applied but still older than `-MaxAgeDays`. | Update source only offers older definitions; endpoint clock skew; `-MaxAgeDays 0` on a device that just updated to yesterday's build. | Compare the before/after version lines, then check the device clock and the source's own definition age. | Sometimes — a later run may pass |
| `1003` | Every update method failed or timed out. | No egress, proxy requiring authentication SYSTEM cannot supply, WSUS not approving definition updates. | `netsh winhttp show proxy` on the device, then check WSUS approvals for Definition Updates. | No |
| `1004` | Definitions current, real-time protection off. | RTP disabled by policy, by a user with rights, or left off after troubleshooting. | `Get-MpPreference \| Select-Object DisableRealtimeMonitoring` and check for a managing policy. | No |
| `1005` | Unexpected/unhandled error. | A genuine defect or an environment nobody anticipated. | Read the stack trace in the log. Any `1005` is a bug report. | No |
| `1006` | Defender status could not be re-read after a successful update. | WMI provider unhealthy, `WinDefend` stopped mid-run, repository corruption. | `Get-MpComputerStatus` by hand; if it fails, this is a Defender health issue, not a definitions issue. | No |
| `1007` | Definitions stale **and** real-time protection off. | Defender degraded on both axes; often a half-removed third-party AV. | Treat as the highest priority of the failure codes. Check RTP first, definitions second. | No |
| `1008` | Update method reported success but the signature version never moved. | WSUS approving nothing, an internal definition share serving stale content, or a source that returns success with no payload. | Check what the configured source is actually offering — this is a source problem, not an endpoint problem. | No |

## Failure modes and design rationale

**No network.** Both `Update-MpSignature` attempts fail fast, `MpCmdRun.exe`
returns non-zero, and the run reports `1003` with a message naming egress,
proxy and WSUS. The script does not try to diagnose connectivity itself — no
test endpoints, no pings — because a remediation script that probes the network
becomes a network monitoring tool that nobody asked for and that trips
egress alerts at scale.

**Proxy requiring authentication.** SYSTEM has no user credentials to present.
This surfaces as `1003`. This is not fixable in the script; the WinHTTP proxy
configuration for the machine account is the right place.

**WSUS not approving definition updates.** `MicrosoftUpdateServer` succeeds at
the transport level and delivers nothing, or fails. That is why `MMPC` is tried
next — it goes straight to Microsoft and routes around the approval problem —
and why `1008` exists: an update that "succeeded" without moving the version
number is a source problem, and it deserves a different ticket than a device
that genuinely cannot reach anything.

**Tamper Protection.** Blocks `Start-Service WinDefend` even for SYSTEM, and
returns a generic access denial that reads like any other permissions error.
The script keeps the `try/catch` and names Tamper Protection in the log line so
the technician does not spend twenty minutes checking ACLs. It does not attempt
to disable it: that is by design impossible from script, and rightly so.

**Third-party AV in passive mode.** `Get-MpComputerStatus` succeeds,
`AMServiceEnabled` is `$true`, `RealTimeProtectionEnabled` is correctly
`$false`. Reading only those two properties produces a confident `1004` on a
perfectly healthy machine. `AMRunningMode` is checked before anything else
touches Defender, and anything other than `Normal` exits `1001` with a log line
that points at the monitoring configuration rather than the device.

**Defender disabled by policy.** Either `Get-MpComputerStatus` fails, or the
service refuses to start and stays disabled. Both paths exit `1001` within the
30-second service poll rather than proceeding to an update that cannot work.

**Agent task timeout.** The reason every update method runs in a job. An
unbounded `Update-MpSignature` against a dead WSUS can block for minutes; if
the agent's timeout fires first, the process is killed and the log is lost —
leaving a failed task with no explanation, which is the one outcome that
guarantees a wasted hour. Worst case the script now spends
`3 x UpdateTimeoutSeconds` (six minutes at the default) plus `-WaitSeconds`
before exiting cleanly with `1003`. **Keep that total below the agent's task
timeout**; lower `-UpdateTimeoutSeconds` if your agent is configured tighter.

**Non-elevated execution.** Checked first, exits `1001`. Previously this
produced `1003` and sent the technician to inspect a proxy and a WSUS that were
both fine.

## Why the update methods are ordered as they are

| Order | Method | Talks to | Why here |
|-------|--------|----------|----------|
| 1 | `Update-MpSignature -UpdateSource MicrosoftUpdateServer` | The device's configured Windows Update target — WSUS if one is set, Microsoft Update otherwise. Honours WinHTTP proxy config. | Respects local infrastructure first. On a correctly configured estate this is the only method that runs, and definitions come from the server the device is supposed to use. |
| 2 | `Update-MpSignature -UpdateSource MMPC` | Microsoft's definition endpoint directly over HTTPS. | Routes around WSUS entirely. This is the one that saves the Monday morning when WSUS has not approved this week's definitions. It still needs egress and proxy to work. |
| 3 | `MpCmdRun.exe -SignatureUpdate` | Defender's own configured fallback order, in-process to the AM engine. | Bypasses the PowerShell module and the WMI layer, so it can still work when those are unhealthy — a genuinely different failure surface, not just a third try at the same thing. Located under `%ProgramData%\Microsoft\Windows Defender\Platform`, picking the highest **parsed version** folder, since that directory accumulates old platform versions and `LastWriteTime` gets touched by unrelated activity. |

## State and idempotency

**Mutates:** only `SignatureUpdateInterval` and `SignatureUpdateCatchupInterval`,
and only with `-Harden`. Both are set to fixed values, so re-running converges
rather than drifting.

**Reads:** `Get-MpComputerStatus`, `Get-MpPreference`, `Get-Service WinDefend`,
and the Defender platform directory listing.

**Side effects:** asks Defender to update its own definitions, and starts
`WinDefend` if it is stopped. Both are operations Defender performs on its own
schedule anyway.

**Repeated runs are safe.** No files are written, no registry keys are set
directly, no state is carried between runs, and nothing accumulates. Two
concurrent runs on the same device would both call into the same Defender
update mechanism, which serialises internally; the second simply reports that
definitions are current. Background jobs are removed in a `finally` block on
every path, including timeout, so nothing is left behind in the runspace.

## Known limitations

- **`AMRunningMode` on old platforms.** Absent before platform 4.18.2011.
  Passive-mode detection silently does not work there. Logged as inconclusive
  and allowed to continue, on the grounds that failing closed on an old but
  healthy platform is worse than the false positive.
- **`Start-Job` dependency.** If the job infrastructure cannot start (heavily
  constrained language mode, a broken WinRM-adjacent component), every update
  attempt fails with a job error and the run reports `1003`. The log line names
  the job failure specifically, but the exit code is arguably misleading. Not
  fixed, because an in-process fallback would reintroduce the unbounded-hang
  problem that the jobs exist to solve.
- **`AntivirusSignatureAge` is whole days.** A threshold of `0` is effectively
  "updated today", and clock skew on the endpoint shifts it. There is no
  sub-day granularity available from this property.
- **Definition traffic is not staggered.** By design; belongs in the RMM
  schedule, not in the script.
- **Execution policy is not handled by the script.** Deliberately. A script
  that bypasses its own execution policy is a script that has defeated a
  control. Handle it with the Automation Manager object or code signing, both
  documented in the README.
- **`-Harden` cannot beat policy.** It writes the local preference and reports
  the effective value; where GPO or Intune manages the setting, the local value
  is inert. The fix belongs in policy.
- **`1005` should be unreachable.** Every known failure surface is handled. Any
  occurrence is a defect, not an environment quirk.

## Testing notes

On a lab VM with a snapshot to roll back to:

| Path | How to provoke it |
|------|-------------------|
| `0` | Set the clock back a few days, or run with `-MaxAgeDays 30` on any healthy device. |
| `1001` not elevated | Run from a non-elevated PowerShell session as a standard user. |
| `1001` passive AV | Install any third-party AV that registers with Security Center; confirm with `(Get-MpComputerStatus).AMRunningMode`. |
| `1001` service down | With Tamper Protection **off**: `sc.exe config WinDefend start= disabled`, then `sc.exe stop WinDefend`, then reboot. |
| `1002` | Run with `-MaxAgeDays 0` on a device whose definitions are a day old and whose source has nothing newer. |
| `1003` | Add an outbound firewall rule blocking `MpCmdRun.exe` and `svchost`, or point the device at a nonexistent WSUS via the `WUServer` policy. |
| `1003` via timeout | Block the WSUS host with a **DROP** rule rather than a reject — connections then hang instead of failing fast, which is what exercises the job timeout. Use a low `-UpdateTimeoutSeconds` to keep the test short. |
| `1004` | With Tamper Protection off: `Set-MpPreference -DisableRealtimeMonitoring $true`. |
| `1006` | Stop `WinDefend` immediately after the update phase begins, so the verification polls have nothing to read. Narrow window; expect a few attempts. |
| `1007` | Combine the `1004` and `1002` setups on the same VM. |
| `1008` | Point the device at a WSUS that approves no definition updates while its own definitions are stale. |

**Cannot be safely or realistically simulated:**

- **Tamper Protection blocking service start.** Turning it on is easy; getting
  a deterministic test out of it is not, and it cannot be scripted off
  afterwards — the toggle is interactive or Intune-managed by design. Verify
  the log wording by inspection instead.
- **A proxy that requires authentication.** Needs a real authenticating proxy
  in the lab path; a mock will not reproduce SYSTEM's credential problem
  faithfully.
- **EDR Block Mode.** Requires a licensed Defender for Endpoint tenant.
- **`1005`.** There is no supported way to force it, which is the point.
- **Production WSUS approval states.** Do not test approval changes against a
  production WSUS to exercise `1008`.
