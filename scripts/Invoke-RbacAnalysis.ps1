<#
    .SYNOPSIS
        Reads the live access at a scope and says what is wrong with it.

    .DESCRIPTION
        Three questions, asked of what Azure currently holds rather than of
        what source control intended:

          Is anything assigned that source control did not declare? That is
          the portal grant nobody reviewed.

          Can anything here grant itself more? An assignment carrying
          roleAssignments/write without an ABAC condition is a path to Owner,
          whatever the role is called.

          Can anything here read a secret value? Different blast radius from
          escalation, and worth separating.

        Gathering is here; the judgements live in the module and are tested
        without a subscription.
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Operator-facing analysis report; the output is the product.')]
param(
    [Parameter(Mandatory)][string]$Scope,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$DeclaredAssignments,
    [string]$OutFile,
    [switch]$FailOnDrift
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path -Path (Join-Path -Path $root -ChildPath 'module') -ChildPath 'LeastPrivilege/LeastPrivilege.psm1') -Force

Write-Host "Reading role assignments at $Scope"

# Listed by resource group rather than by --scope: az 2.90 rejects an
# resource-group scope on this command with MissingSubscription, while the
# -g form returns exactly the assignments made at that group.
#
# Inherited assignments are excluded by default here. Including them would
# report the subscription owner as drift on every run, which is how a drift
# report gets ignored.
$live = az role assignment list --resource-group $ResourceGroup --only-show-errors |
    ConvertFrom-Json

$definitionCache = @{}
function Resolve-Definition {
    param([string]$Name)
    if ($definitionCache.ContainsKey($Name)) { return $definitionCache[$Name] }

    # Custom roles are only visible at their assignable scope, so try there
    # first and fall back to the built-in catalogue.
    $raw = az role definition list --name $Name --scope $Scope --only-show-errors 2>$null | ConvertFrom-Json
    if (-not $raw) { $raw = az role definition list --name $Name --only-show-errors | ConvertFrom-Json }

    $definition = if ($raw) {
        [pscustomobject]@{
            Name       = $raw[0].roleName
            Actions    = @($raw[0].permissions.actions)
            NotActions = @($raw[0].permissions.notActions)
        }
    }
    else { $null }

    $definitionCache[$Name] = $definition
    $definition
}

$assignments = foreach ($a in $live) {
    [pscustomobject]@{
        PrincipalId    = $a.principalId
        PrincipalName  = if ($a.principalName) { $a.principalName } else { $a.principalId }
        RoleName       = $a.roleDefinitionName
        Scope          = $a.scope
        Condition      = $a.condition
        RoleDefinition = Resolve-Definition -Name $a.roleDefinitionName
    }
}
$assignments = @($assignments)

Write-Host "  $($assignments.Count) assignment(s) made at this scope"
Write-Host ""

# --- drift -----------------------------------------------------------------
$declared = @($DeclaredAssignments | ConvertFrom-Json)
$drift = Compare-RoleAssignment -Declared $declared -Actual $assignments

Write-Host "Drift"
if ($drift.InSync) {
    Write-Host "  live access matches source control"
}
else {
    foreach ($u in $drift.Unexpected) {
        Write-Host "  GRANTED OUTSIDE CODE  $($u.PrincipalName) has $($u.RoleName)"
    }
    foreach ($m in $drift.Missing) {
        Write-Host "  DECLARED BUT ABSENT   $($m.PrincipalId) should have $($m.RoleName)"
    }
}
Write-Host ""

# --- escalation ------------------------------------------------------------
$escalation = Find-EscalationPath -Assignment $assignments

Write-Host "Privilege escalation"
if ($escalation.Findings.Count -eq 0) {
    Write-Host "  nothing at this scope can change who can do what"
}
else {
    $escalation.Findings |
        Sort-Object @{ Expression = { if ($_.Severity -eq 'Critical') { 0 } else { 1 } } } |
        Format-Table -AutoSize Severity, PrincipalName, RoleName, Detail |
        Out-String -Width 150 | Write-Host
}

# --- secret access ---------------------------------------------------------
$secrets = Find-SecretReader -Assignment $assignments

Write-Host "Secret access"
if ($secrets.Count -eq 0) {
    Write-Host "  nothing at this scope can read a secret value"
}
else {
    $secrets.Findings | Format-Table -AutoSize PrincipalName, RoleName, Action |
        Out-String -Width 120 | Write-Host
}

$report = [pscustomobject]@{
    GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    Scope        = $Scope
    Assignments  = $assignments.Count
    Drift        = [pscustomobject]@{
        InSync     = $drift.InSync
        Unexpected = $drift.Unexpected
        Missing    = $drift.Missing
    }
    Escalation   = [pscustomobject]@{
        Critical = $escalation.Critical
        Findings = $escalation.Findings
    }
    SecretAccess = [pscustomobject]@{
        Count    = $secrets.Count
        Findings = $secrets.Findings
    }
}

if ($OutFile) {
    $dir = Split-Path $OutFile -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host ""
Write-Host ("Drift: {0}   Critical escalation paths: {1}   Secret readers: {2}" -f `
    $(if ($drift.InSync) { 'none' } else { "$($drift.Unexpected.Count) unexpected, $($drift.Missing.Count) missing" }),
    $escalation.Critical, $secrets.Count)

# An escalation path is always a failure. Drift is a failure only when the
# caller asks, because a drift report is also useful as information during an
# investigation.
if ($escalation.Critical -gt 0) {
    throw "$($escalation.Critical) assignment(s) at this scope can grant themselves more access."
}
if ($FailOnDrift -and -not $drift.InSync) {
    throw "Live access does not match source control: $($drift.Unexpected.Count) unexpected, $($drift.Missing.Count) missing."
}

$report
