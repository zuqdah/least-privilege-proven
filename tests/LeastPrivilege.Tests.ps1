<#
    Tests for the judgements, not for Azure.

    Every case is a decision about whether access is safe. None of them need a
    subscription, which is why the rules can be changed and re-verified in a
    second rather than a deployment.
#>

BeforeAll {
    $module = Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'module') -ChildPath 'LeastPrivilege'
    Import-Module (Join-Path -Path $module -ChildPath 'LeastPrivilege.psm1') -Force

    function New-Role {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'Test fixture, not a cmdlet.')]
        param([string]$Name = 'Test Role', [string[]]$Actions = @(), [string[]]$NotActions = @())
        [pscustomobject]@{ Name = $Name; Actions = $Actions; NotActions = $NotActions }
    }

    function New-Assignment {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
            Justification = 'Test fixture, not a cmdlet.')]
        param(
            [string]$PrincipalName = 'sp-test',
            [string]$RoleName = 'Test Role',
            [string]$Scope = '/subscriptions/000/resourceGroups/rg',
            [string]$Condition = '',
            [pscustomobject]$RoleDefinition
        )
        [pscustomobject]@{
            PrincipalId    = "id-$PrincipalName"
            PrincipalName  = $PrincipalName
            RoleName       = $RoleName
            Scope          = $Scope
            Condition      = $Condition
            RoleDefinition = $RoleDefinition
        }
    }
}

Describe 'Test-ActionMatch' {
    It 'matches an exact action' {
        Test-ActionMatch -Pattern 'Microsoft.Storage/storageAccounts/read' -Action 'Microsoft.Storage/storageAccounts/read' | Should -BeTrue
    }

    It 'does not match a different action' {
        Test-ActionMatch -Pattern 'Microsoft.Storage/storageAccounts/read' -Action 'Microsoft.Storage/storageAccounts/write' | Should -BeFalse
    }

    It 'treats a bare star as everything' {
        Test-ActionMatch -Pattern '*' -Action 'Microsoft.Authorization/roleAssignments/write' | Should -BeTrue
    }

    It 'lets a star cross slashes, because RBAC wildcards do' {
        # This is the case that makes */write dangerous and is the one people
        # get wrong by reasoning about it like a shell glob.
        Test-ActionMatch -Pattern '*/write' -Action 'Microsoft.Authorization/roleAssignments/write' | Should -BeTrue
    }

    It 'matches a provider-scoped wildcard' {
        Test-ActionMatch -Pattern 'Microsoft.Storage/*' -Action 'Microsoft.Storage/storageAccounts/listKeys/action' | Should -BeTrue
    }

    It 'does not match across providers' {
        Test-ActionMatch -Pattern 'Microsoft.Storage/*' -Action 'Microsoft.Compute/virtualMachines/read' | Should -BeFalse
    }

    It 'treats dots as literals rather than regex wildcards' {
        Test-ActionMatch -Pattern 'Microsoft.Storage/read' -Action 'MicrosoftXStorage/read' | Should -BeFalse
    }

    It 'returns false for an empty pattern' {
        Test-ActionMatch -Pattern '' -Action 'Microsoft.Storage/read' | Should -BeFalse
    }
}

Describe 'Test-GrantsAction' {
    It 'grants an action listed directly' {
        $role = New-Role -Actions @('Microsoft.Storage/storageAccounts/read')
        Test-GrantsAction -RoleDefinition $role -Action 'Microsoft.Storage/storageAccounts/read' | Should -BeTrue
    }

    It 'honours NotActions subtracting from a wildcard' {
        # This is what separates a genuinely constrained role from Owner with
        # extra steps.
        $role = New-Role -Actions @('*') -NotActions @('Microsoft.Authorization/roleAssignments/write')
        Test-GrantsAction -RoleDefinition $role -Action 'Microsoft.Authorization/roleAssignments/write' | Should -BeFalse
        Test-GrantsAction -RoleDefinition $role -Action 'Microsoft.Storage/storageAccounts/read' | Should -BeTrue
    }

    It 'honours a wildcard NotAction' {
        $role = New-Role -Actions @('*') -NotActions @('Microsoft.Authorization/*')
        Test-GrantsAction -RoleDefinition $role -Action 'Microsoft.Authorization/roleDefinitions/write' | Should -BeFalse
    }

    It 'grants nothing when Actions is empty' {
        Test-GrantsAction -RoleDefinition (New-Role) -Action 'Microsoft.Storage/read' | Should -BeFalse
    }
}

Describe 'Find-EscalationPath' {
    It 'flags an unconstrained role assignment writer as critical' {
        $role = New-Role -Name 'Bad Admin' -Actions @('Microsoft.Authorization/roleAssignments/write')
        $result = Find-EscalationPath -Assignment @(New-Assignment -RoleDefinition $role)
        $result.Critical | Should -Be 1
        $result.Findings[0].Detail | Should -Match 'grant itself Owner'
    }

    It 'flags Owner, which grants everything' {
        $role = New-Role -Name 'Owner' -Actions @('*')
        (Find-EscalationPath -Assignment @(New-Assignment -RoleName 'Owner' -RoleDefinition $role)).Critical | Should -Be 1
    }

    It 'does not flag Contributor, which cannot assign roles' {
        # Contributor is * minus the authorization actions. Flagging it would
        # bury the real findings in noise.
        $role = New-Role -Name 'Contributor' -Actions @('*') -NotActions @(
            'Microsoft.Authorization/*/Delete'
            'Microsoft.Authorization/*/Write'
            'Microsoft.Authorization/elevateAccess/Action'
        )
        (Find-EscalationPath -Assignment @(New-Assignment -RoleName 'Contributor' -RoleDefinition $role)).Critical | Should -Be 0
    }

    It 'downgrades a constrained assignment to informational' {
        # An ABAC condition limiting which roles may be assigned is the
        # difference between delegation and self-promotion.
        $role = New-Role -Actions @('Microsoft.Authorization/roleAssignments/write')
        $assignment = New-Assignment -RoleDefinition $role -Condition "@Request[...] ForAnyOfAnyValues:GuidEquals{...}"
        $result = Find-EscalationPath -Assignment @($assignment)
        $result.Critical | Should -Be 0
        $result.Findings[0].Severity | Should -Be 'Info'
    }

    It 'flags a reader as nothing at all' {
        $role = New-Role -Name 'Reader' -Actions @('*/read')
        (Find-EscalationPath -Assignment @(New-Assignment -RoleName 'Reader' -RoleDefinition $role)).Critical | Should -Be 0
    }

    It 'handles an empty assignment list' {
        (Find-EscalationPath -Assignment @()).Critical | Should -Be 0
    }
}

Describe 'Compare-RoleAssignment' {
    BeforeAll {
        $script:Declared = @(
            [pscustomobject]@{ PrincipalId = 'p1'; RoleName = 'Reader'; Scope = '/subscriptions/000/resourceGroups/rg' }
        )
    }

    It 'reports in sync when they match' {
        $result = Compare-RoleAssignment -Declared $script:Declared -Actual $script:Declared
        $result.InSync | Should -BeTrue
    }

    It 'catches an assignment granted outside code' {
        # The portal grant nobody reviewed.
        $actual = $script:Declared + [pscustomobject]@{ PrincipalId = 'p2'; RoleName = 'Owner'; Scope = '/subscriptions/000/resourceGroups/rg' }
        $result = Compare-RoleAssignment -Declared $script:Declared -Actual $actual
        $result.InSync | Should -BeFalse
        $result.Unexpected.Count | Should -Be 1
        $result.Unexpected[0].RoleName | Should -Be 'Owner'
    }

    It 'catches a declared assignment that never landed' {
        $result = Compare-RoleAssignment -Declared $script:Declared -Actual @()
        $result.Missing.Count | Should -Be 1
        $result.InSync | Should -BeFalse
    }

    It 'ignores scope casing, which differs between the portal and the API' {
        $actual = @([pscustomobject]@{ PrincipalId = 'p1'; RoleName = 'Reader'; Scope = '/SUBSCRIPTIONS/000/RESOURCEGROUPS/RG' })
        (Compare-RoleAssignment -Declared $script:Declared -Actual $actual).InSync | Should -BeTrue
    }

    It 'treats the same role at a different scope as a separate assignment' {
        $actual = @([pscustomobject]@{ PrincipalId = 'p1'; RoleName = 'Reader'; Scope = '/subscriptions/000' })
        $result = Compare-RoleAssignment -Declared $script:Declared -Actual $actual
        $result.InSync | Should -BeFalse
    }
}

Describe 'Test-AccessExpectation' {
    It 'passes when every observation matches' {
        $expected = @([pscustomobject]@{ Principal = 'reader'; Action = 'write'; Allowed = $false })
        $observed = @([pscustomobject]@{ Principal = 'reader'; Action = 'write'; Allowed = $false })
        $result = Test-AccessExpectation -Expected $expected -Observed $observed
        $result.Passed | Should -BeTrue
        $result.AsExpected | Should -Be 1
    }

    It 'fails loudly when something denied was actually allowed' {
        # The hole.
        $expected = @([pscustomobject]@{ Principal = 'reader'; Action = 'delete'; Allowed = $false })
        $observed = @([pscustomobject]@{ Principal = 'reader'; Action = 'delete'; Allowed = $true })
        $result = Test-AccessExpectation -Expected $expected -Observed $observed
        $result.Passed | Should -BeFalse
        $result.UnexpectedlyAllowed | Should -Be 1
    }

    It 'also fails when something needed was denied' {
        # The broken deployment, which gets "fixed" by widening the role.
        $expected = @([pscustomobject]@{ Principal = 'operator'; Action = 'restart'; Allowed = $true })
        $observed = @([pscustomobject]@{ Principal = 'operator'; Action = 'restart'; Allowed = $false })
        $result = Test-AccessExpectation -Expected $expected -Observed $observed
        $result.Passed | Should -BeFalse
        $result.UnexpectedlyDenied | Should -Be 1
    }

    It 'does not let an untested expectation count as a pass' {
        $expected = @([pscustomobject]@{ Principal = 'reader'; Action = 'write'; Allowed = $false })
        $result = Test-AccessExpectation -Expected $expected -Observed @()
        $result.NotTested | Should -Be 1
        $result.Passed | Should -BeFalse
    }
}

Describe 'Find-SecretReader' {
    It 'flags a role that can list storage keys' {
        $role = New-Role -Actions @('Microsoft.Storage/storageAccounts/listKeys/action')
        (Find-SecretReader -Assignment @(New-Assignment -RoleDefinition $role)).Count | Should -Be 1
    }

    It 'flags a wildcard role that sweeps up secret reads' {
        $role = New-Role -Name 'Owner' -Actions @('*')
        (Find-SecretReader -Assignment @(New-Assignment -RoleDefinition $role)).Count | Should -Be 1
    }

    It 'does not flag a reader that cannot list keys' {
        # listKeys is an action, not a read, so */read does not cover it.
        $role = New-Role -Name 'Reader' -Actions @('*/read')
        (Find-SecretReader -Assignment @(New-Assignment -RoleDefinition $role)).Count | Should -Be 0
    }
}
