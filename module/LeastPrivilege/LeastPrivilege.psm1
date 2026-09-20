<#
    Reasoning about access, separated from asking Azure about it.

    Nothing here calls Azure. The scripts gather role definitions, role
    assignments and observed results; these functions decide what those facts
    mean. That split is why the judgements can be tested exhaustively without
    a subscription, and why a rule change is cheap to verify.
#>

# Actions that let a principal change who can do what. Holding any of these
# without a constraint means the principal can grant itself anything, so a
# "limited" role carrying one of them is not limited at all.
#
# These are concrete actions, never patterns. A wildcard like */write is
# something a role *grants*, not something it can be asked about: testing for
# it would flag Contributor, whose NotActions correctly block the real
# authorization actions but cannot block a pattern string. A role holding *
# is still caught, because * matches every concrete action below.
$script:EscalationActions = @(
    'Microsoft.Authorization/roleAssignments/write'
    'Microsoft.Authorization/roleDefinitions/write'
    'Microsoft.Authorization/denyAssignments/write'
    'Microsoft.Authorization/elevateAccess/action'
)

# Actions that expose a secret value. Separated from escalation because the
# blast radius differs: one takes over the subscription, the other takes the
# data and leaves.
#
# Note what is absent: Microsoft.KeyVault/vaults/secrets/read is a management
# plane action that lists secret *names*, and Reader holds it legitimately.
# The action that returns a secret *value* is getSecret. Conflating the two
# makes every Reader a finding and buries the real ones.
$script:SecretActions = @(
    'Microsoft.KeyVault/vaults/secrets/getSecret/action'
    'Microsoft.Storage/storageAccounts/listKeys/action'
    'Microsoft.Web/sites/config/list/action'
    'Microsoft.DocumentDB/databaseAccounts/listKeys/action'
)

function Test-ActionMatch {
    <#
        .SYNOPSIS
            Whether an RBAC action pattern covers a specific action.
        .DESCRIPTION
            RBAC wildcards are not regular expressions and not globs. A single
            * matches any characters including slashes, so */write covers
            Microsoft.Authorization/roleAssignments/write. Treating these as
            literals is how an over-broad role passes review.
        .EXAMPLE
            Test-ActionMatch -Pattern '*/read' -Action 'Microsoft.Storage/storageAccounts/read'
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Pattern,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Action
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $false }
    if ($Pattern -eq '*') { return $true }

    $escaped = [regex]::Escape($Pattern).Replace('\*', '.*')
    return $Action -match "^$escaped$"
}

function Get-EffectiveAction {
    <#
        .SYNOPSIS
            Resolves a role definition to the actions it actually grants.
        .DESCRIPTION
            NotActions subtract from Actions. A role that grants * and then
            subtracts the escalation actions is genuinely constrained; one
            that grants * and subtracts nothing is Owner by another name.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$RoleDefinition
    )

    $actions    = @($RoleDefinition.Actions)
    $notActions = @($RoleDefinition.NotActions)

    [pscustomobject]@{
        Name       = $RoleDefinition.Name
        Actions    = $actions
        NotActions = $notActions
    }
}

function Test-GrantsAction {
    <#
        .SYNOPSIS
            Whether a role definition grants a specific action after NotActions.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][pscustomobject]$RoleDefinition,
        [Parameter(Mandatory)][string]$Action
    )

    $granted = $false
    foreach ($pattern in @($RoleDefinition.Actions)) {
        if (Test-ActionMatch -Pattern $pattern -Action $Action) { $granted = $true; break }
    }
    if (-not $granted) { return $false }

    foreach ($pattern in @($RoleDefinition.NotActions)) {
        if (Test-ActionMatch -Pattern $pattern -Action $Action) { return $false }
    }
    return $true
}

function Find-EscalationPath {
    <#
        .SYNOPSIS
            Finds assignments that let a principal grant itself more access.
        .DESCRIPTION
            An assignment carrying roleAssignments/write is a path to Owner
            unless an ABAC condition narrows which roles may be assigned. The
            condition is what makes "can delegate" different from "can become
            administrator", so its absence is the finding.
        .PARAMETER Assignment
            Objects with PrincipalId, PrincipalName, RoleName, Scope,
            Condition, and the resolved RoleDefinition.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Assignment
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($a in $Assignment) {
        $definition = $a.RoleDefinition
        if (-not $definition) { continue }

        foreach ($action in $script:EscalationActions) {
            if (-not (Test-GrantsAction -RoleDefinition $definition -Action $action)) { continue }

            $constrained = -not [string]::IsNullOrWhiteSpace($a.Condition)
            $findings.Add([pscustomobject]@{
                    Severity      = if ($constrained) { 'Info' } else { 'Critical' }
                    PrincipalId   = $a.PrincipalId
                    PrincipalName = $a.PrincipalName
                    RoleName      = $a.RoleName
                    Scope         = $a.Scope
                    Action        = $action
                    Constrained   = $constrained
                    Detail        = if ($constrained) {
                        "Can assign roles, limited by an ABAC condition."
                    }
                    else {
                        "Can assign any role at this scope, so can grant itself Owner."
                    }
                })
            break
        }
    }

    [pscustomobject]@{
        Findings = $findings.ToArray()
        Critical = @($findings | Where-Object Severity -eq 'Critical').Count
    }
}

function Compare-RoleAssignment {
    <#
        .SYNOPSIS
            Compares live assignments against what source declares.
        .DESCRIPTION
            Anything live and undeclared was granted outside code, which is
            the change nobody reviewed. Anything declared and missing means
            the deployment did not take effect, which is quieter and just as
            wrong.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Declared,
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Actual
    )

    function Get-Key {
        param($Item)
        # Scope casing varies between the portal and the API, so it is
        # normalised rather than compared literally.
        '{0}|{1}|{2}' -f $Item.PrincipalId, $Item.RoleName, $Item.Scope.ToLowerInvariant()
    }

    $declaredKeys = @{}
    foreach ($d in $Declared) { $declaredKeys[(Get-Key $d)] = $d }

    $actualKeys = @{}
    foreach ($a in $Actual) { $actualKeys[(Get-Key $a)] = $a }

    $unexpected = foreach ($key in $actualKeys.Keys) {
        if (-not $declaredKeys.ContainsKey($key)) { $actualKeys[$key] }
    }
    $missing = foreach ($key in $declaredKeys.Keys) {
        if (-not $actualKeys.ContainsKey($key)) { $declaredKeys[$key] }
    }

    [pscustomobject]@{
        Unexpected = @($unexpected)
        Missing    = @($missing)
        InSync     = (@($unexpected).Count -eq 0 -and @($missing).Count -eq 0)
    }
}

function Test-AccessExpectation {
    <#
        .SYNOPSIS
            Compares what a principal was observed to do against what it should.
        .DESCRIPTION
            Both directions are failures and they are not the same failure. An
            action that was expected to be denied and succeeded is a hole. One
            expected to be allowed and failed is a broken deployment, which
            tends to get "fixed" by widening the role.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Expected,
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Observed
    )

    $observedByKey = @{}
    foreach ($o in $Observed) { $observedByKey['{0}|{1}' -f $o.Principal, $o.Action] = $o }

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($e in $Expected) {
        $key = '{0}|{1}' -f $e.Principal, $e.Action
        $o = $observedByKey[$key]

        if (-not $o) {
            $results.Add([pscustomobject]@{
                    Principal = $e.Principal; Action = $e.Action
                    Expected = $e.Allowed; Observed = $null
                    Verdict = 'NotTested'
                })
            continue
        }

        $verdict = if ($o.Allowed -eq $e.Allowed) { 'AsExpected' }
        elseif ($o.Allowed) { 'UnexpectedlyAllowed' }
        else { 'UnexpectedlyDenied' }

        $results.Add([pscustomobject]@{
                Principal = $e.Principal; Action = $e.Action
                Expected = $e.Allowed; Observed = $o.Allowed
                Verdict = $verdict
            })
    }

    [pscustomobject]@{
        Results             = $results.ToArray()
        AsExpected          = @($results | Where-Object Verdict -eq 'AsExpected').Count
        UnexpectedlyAllowed = @($results | Where-Object Verdict -eq 'UnexpectedlyAllowed').Count
        UnexpectedlyDenied  = @($results | Where-Object Verdict -eq 'UnexpectedlyDenied').Count
        NotTested           = @($results | Where-Object Verdict -eq 'NotTested').Count
        Passed              = (@($results | Where-Object { $_.Verdict -ne 'AsExpected' }).Count -eq 0)
    }
}

function Find-SecretReader {
    <#
        .SYNOPSIS
            Flags assignments that can read secrets or keys.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$Assignment
    )

    $findings = foreach ($a in $Assignment) {
        if (-not $a.RoleDefinition) { continue }
        foreach ($action in $script:SecretActions) {
            if (Test-GrantsAction -RoleDefinition $a.RoleDefinition -Action $action) {
                [pscustomobject]@{
                    PrincipalName = $a.PrincipalName
                    RoleName      = $a.RoleName
                    Scope         = $a.Scope
                    Action        = $action
                }
                break
            }
        }
    }

    [pscustomobject]@{ Findings = @($findings); Count = @($findings).Count }
}

Export-ModuleMember -Function Test-ActionMatch, Get-EffectiveAction, Test-GrantsAction,
Find-EscalationPath, Compare-RoleAssignment, Test-AccessExpectation, Find-SecretReader
