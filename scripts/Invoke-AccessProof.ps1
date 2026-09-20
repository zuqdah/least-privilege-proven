<#
    .SYNOPSIS
        Signs in as each identity under test and attempts what it should not
        be able to do.

    .DESCRIPTION
        Reading role assignments tells you what Azure was asked to allow.
        This tells you what it actually allows, which is not always the same
        thing and is never the same thing after somebody edits a role in the
        portal.

        Each subject gets a short-lived secret, minted here and deleted in the
        finally block. Nothing is stored: no GitHub secret, no Terraform
        state, no file on disk that outlives the run. The deploy identity can
        do this because bootstrap made it an owner of those three
        applications, rather than giving it rights over the whole directory.

    .PARAMETER MatrixPath
        The expected access policy. This file is the claim; the run is the
        evidence.
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Operator-facing proof report; the output is the product.')]
param(
    [Parameter(Mandatory)][string]$MatrixPath,
    [Parameter(Mandatory)][string]$SubjectClientIds,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path -Path (Join-Path -Path $root -ChildPath 'module') -ChildPath 'LeastPrivilege/LeastPrivilege.psm1') -Force

$matrix    = [System.IO.File]::ReadAllText($MatrixPath) | ConvertFrom-Json
$clientIds = $SubjectClientIds | ConvertFrom-Json
$rgScope   = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"

function Invoke-Probe {
    <#
        Runs one probe as the currently signed-in identity and reports only
        whether it was permitted. The output is deliberately discarded: this
        asks "were you allowed?", not "what did you get?".
    #>
    param(
        [Parameter(Mandatory)][string]$Probe,
        [Parameter(Mandatory)][string]$ConfigDir,
        [Parameter(Mandatory)][string]$PrincipalObjectId,
        # Passed rather than captured from the enclosing scope: a function
        # that reaches outward for its inputs breaks quietly when it moves.
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$Scope
    )

    $env:AZURE_CONFIG_DIR = $ConfigDir
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')

    $command = switch ($Probe) {
        'rg-read' { @('group', 'show', '--name', $ResourceGroupName) }
        'storage-read' { @('storage', 'account', 'show', '--name', $StorageAccountName, '--resource-group', $ResourceGroupName) }
        'storage-listkeys' { @('storage', 'account', 'keys', 'list', '--account-name', $StorageAccountName, '--resource-group', $ResourceGroupName) }
        'tag-write' { @('group', 'update', '--name', $ResourceGroupName, '--set', "tags.probe$stamp=1") }
        'role-assign' {
            # Reader is the least alarming role available, chosen so that a
            # success here is unambiguous: the identity could assign a role at
            # all, which is the finding. A failure to create it is the pass.
            @('role', 'assignment', 'create', '--assignee-object-id', $PrincipalObjectId,
              '--assignee-principal-type', 'ServicePrincipal',
              '--role', 'Reader', '--scope', $Scope)
        }
        default { throw "Unknown probe '$Probe'." }
    }

    $stderrFile = Join-Path ([System.IO.Path]::GetTempPath()) "probe-$([guid]::NewGuid().ToString('N')).txt"
    try {
        & az @command --only-show-errors 2> $stderrFile | Out-Null
        $allowed = ($LASTEXITCODE -eq 0)
        $detail = if ($allowed) { '' } else { (Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue) }
    }
    finally {
        if (Test-Path $stderrFile) { [System.IO.File]::Delete($stderrFile) }
    }

    [pscustomobject]@{
        Allowed = $allowed
        Detail  = if ($detail) { ($detail -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(240, ($detail -replace '\s+', ' ').Trim().Length)) } else { '' }
    }
}

$observed = [System.Collections.Generic.List[object]]::new()
$principals = @($matrix.probes | ForEach-Object { $_.principal } | Sort-Object -Unique)

foreach ($principal in $principals) {
    $clientId = $clientIds.$principal
    if (-not $clientId) { throw "No client id supplied for subject '$principal'." }

    $configDir = Join-Path ([System.IO.Path]::GetTempPath()) "azcfg-$principal-$PID"
    $keyId = $null

    Write-Host ""
    Write-Host "Signing in as $principal"

    try {
        # Short-lived and append-only: an existing credential on the
        # application is not disturbed, and this one is removed below.
        $end = [DateTime]::UtcNow.AddHours(2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $resetRaw = az ad app credential reset --id $clientId --append `
            --display-name "proof-$PID" --end-date $end --only-show-errors 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not mint a credential for ${principal}: $($resetRaw -join ' ')"
        }
        $credential = $resetRaw | ConvertFrom-Json
        if (-not $credential.password) {
            throw "Credential reset for $principal returned no password."
        }
        $keyId = $credential.keyId

        $objectId = az ad sp show --id $clientId --query id -o tsv --only-show-errors

        # A freshly minted secret is not always usable immediately; Entra can
        # take a couple of minutes to replicate it. The last error is kept so
        # a real failure is distinguishable from a slow one, because a retry
        # loop that hides why it is retrying is no help at all.
        $signedIn = $false
        $lastError = ''
        foreach ($attempt in 1..20) {
            $env:AZURE_CONFIG_DIR = $configDir
            $loginOut = az login --service-principal -u $clientId -p $credential.password `
                --tenant $TenantId --allow-no-subscriptions --only-show-errors 2>&1
            if ($LASTEXITCODE -eq 0) {
                $signedIn = $true
                if ($attempt -gt 1) { Write-Host "  signed in on attempt $attempt" }
                break
            }
            $lastError = ($loginOut | Out-String).Trim()
            Start-Sleep -Seconds 10
        }
        if (-not $signedIn) {
            throw "Could not sign in as $principal after 20 attempts over ~200s. Last error: $lastError"
        }

        az account set --subscription $SubscriptionId --only-show-errors *> $null

        foreach ($probe in @($matrix.probes | Where-Object principal -eq $principal)) {
            $result = Invoke-Probe -Probe $probe.probe -ConfigDir $configDir -PrincipalObjectId $objectId -ResourceGroupName $ResourceGroup -StorageAccountName $StorageAccount -Scope $rgScope
            $verdict = if ($result.Allowed) { 'allowed' } else { 'denied ' }
            Write-Host ("  {0}  {1,-20} {2}" -f $verdict, $probe.probe, $probe.action)

            $observed.Add([pscustomobject]@{
                    Principal = $principal
                    Action    = $probe.probe
                    Allowed   = $result.Allowed
                    Detail    = $result.Detail
                })
        }
    }
    finally {
        $env:AZURE_CONFIG_DIR = $configDir
        az logout --only-show-errors *> $null
        $env:AZURE_CONFIG_DIR = $null

        # The secret goes whether or not the probes passed. A proof that
        # leaves credentials behind has made the estate worse.
        if ($keyId) {
            az ad app credential delete --id $clientId --key-id $keyId --only-show-errors *> $null
            Write-Host "  secret removed"
        }
        if (Test-Path $configDir) { Remove-Item $configDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

$expected = @($matrix.probes | ForEach-Object {
        [pscustomobject]@{ Principal = $_.principal; Action = $_.probe; Allowed = $_.allowed }
    })

$result = Test-AccessExpectation -Expected $expected -Observed $observed.ToArray()

Write-Host ""
Write-Host ("As expected: {0}   Unexpectedly allowed: {1}   Unexpectedly denied: {2}   Not tested: {3}" -f `
        $result.AsExpected, $result.UnexpectedlyAllowed, $result.UnexpectedlyDenied, $result.NotTested)

$failures = @($result.Results | Where-Object Verdict -ne 'AsExpected')
if ($failures.Count) {
    Write-Host ""
    $failures | Format-Table -AutoSize Principal, Action, Expected, Observed, Verdict | Out-String -Width 120 | Write-Host
}

if ($OutFile) {
    $dir = Split-Path $OutFile -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $payload = [pscustomobject]@{
        GeneratedUtc = [DateTime]::UtcNow.ToString('o')
        Summary      = $result | Select-Object AsExpected, UnexpectedlyAllowed, UnexpectedlyDenied, NotTested, Passed
        Results      = $result.Results
        Observed     = $observed.ToArray()
    }
    [System.IO.File]::WriteAllText($OutFile, ($payload | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}

if (-not $result.Passed) {
    throw "Access does not match the declared policy: $($result.UnexpectedlyAllowed) unexpectedly allowed, $($result.UnexpectedlyDenied) unexpectedly denied, $($result.NotTested) not tested."
}

Write-Host "Every identity was allowed exactly what the policy says, and refused everything else."
$result
