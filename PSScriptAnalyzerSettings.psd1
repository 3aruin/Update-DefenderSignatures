# Picked up automatically by Invoke-ScriptAnalyzer when it runs against this
# directory, including the CI job in .github/workflows/psscriptanalyzer.yml.
#
# This narrows one rule to the PowerShell version the script actually targets.
# It does not relax the gate: no rule is excluded, no severity is filtered, and
# warnings still fail the build.
@{
    Rules = @{
        PSAvoidOverwritingBuiltInCmdlets = @{
            # Write-Log collides with a function that PSDesiredStateConfiguration
            # exported in PowerShell Core 6.1 and nothing else - not Windows
            # PowerShell 5.1, and not PowerShell 7. The rule defaults to a
            # profile matching whatever PowerShell is running the analyzer, so a
            # pwsh-based CI runner checks this script against a version it does
            # not target and never runs on. Update-DefenderSignatures.ps1
            # declares #Requires -Version 5.1, so check it against that.
            PowerShellVersion = @('desktop-5.1.14393.206-windows')
        }
    }
}
