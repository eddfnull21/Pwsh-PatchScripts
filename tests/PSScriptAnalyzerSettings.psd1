# PSScriptAnalyzer settings for the -morph scripts (used by tests\Morphs.Tests.ps1).
# Every exclusion below was reviewed against the morphs on 2026-10-11; re-review if a rule starts
# mattering for new code. All other rules (including AvoidAssignmentToAutomaticVariable, which
# found real shadowing that was fixed) stay on and must report nothing.
@{
    ExcludeRules = @(
        # By design: the paste model returns only the exit code, so all output goes to the host.
        'PSAvoidUsingWriteHost'

        # Style only. Function names are kept verbatim from the merged sources.
        'PSUseSingularNouns'
        'PSAvoidUsingPositionalParameters'
        'PSUseOutputTypeCorrectly'

        # Reviewed, false positives: nested helpers (DotNet Remove-*, UserRemoval Remove-UPFolder,
        # Chrome Set-RelaunchNotificationPolicy) are called only behind the caller's ShouldProcess,
        # or call $PSCmdlet.ShouldProcess of the enclosing function; New-* functions only build objects.
        'PSUseShouldProcessForStateChangingFunctions'

        # Reviewed, false positives: Adobe's mode switches select a parameter set; DotNet's
        # CliTimeoutSeconds is read by a nested function.
        'PSReviewUnusedParameter'

        # Reviewed, false positive: Winget's Start-Job passes values through param() + -ArgumentList.
        'PSUseUsingScopeModifierInNewRunspaces'

        # Reviewed: every empty catch is a best-effort probe, log write or cleanup step, none in a
        # destructive path. Note: Microsoft3DViewer's detection treats a throwing Get-AppxPackage
        # as "not present".
        'PSAvoidUsingEmptyCatchBlock'
    )
}
