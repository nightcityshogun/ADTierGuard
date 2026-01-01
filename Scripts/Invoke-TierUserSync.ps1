<#
.SYNOPSIS
    ADTierGuard - Tier User Management
    
.DESCRIPTION
    Manages user objects for Tier 0 and Tier 1 isolation.
    Applies Kerberos Authentication Policies to privileged users.
    Enforces Protected Users membership and privileged group cleanup.
    Uses pure ADSI operations with runspace-based parallel processing.
    
.PARAMETER ConfigurationPath
    Path to the ADTierGuard configuration JSON file.
    
.PARAMETER TierLevel
    The tier level to process (0 or 1).
    
.PARAMETER ForestScope
    Process all domains in the forest (overrides config).
    
.PARAMETER SkipProtectedUsers
    Skip adding users to Protected Users group.
    
.PARAMETER SkipPrivilegedGroupCleanup
    Skip removing users from privileged groups.
    
.PARAMETER WhatIf
    Shows what changes would be made without executing them.
    
.EXAMPLE
    .\Invoke-TierUserSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0
    
.EXAMPLE
    .\Invoke-TierUserSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0 -WhatIf
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ConfigurationPath,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet(0, 1)]
    [int]$TierLevel,
    
    [Parameter()]
    [switch]$ForestScope,
    
    [Parameter()]
    [switch]$SkipProtectedUsers,
    
    [Parameter()]
    [switch]$SkipPrivilegedGroupCleanup,
    
    [Parameter()]
    [int]$ThrottleLimit = 0
)

#region Script Initialization

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Script:StartTime = [DateTime]::Now
$Script:ModulePath = Split-Path -Parent $PSScriptRoot

# Import modules
$modulesToImport = @(
    (Join-Path $Script:ModulePath 'Core\AdsiOperations.psm1'),
    (Join-Path $Script:ModulePath 'Engine\RunspaceEngine.psm1'),
    (Join-Path $Script:ModulePath 'Core\ConfigurationManager.psm1')
)

foreach ($module in $modulesToImport) {
    if (Test-Path $module) {
        Import-Module $module -Force
    }
    else {
        throw "Required module not found: $module"
    }
}

#endregion

#region Logging Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Verbose', 'Information', 'Warning', 'Error')]
        [string]$Level = 'Information',
        
        [Parameter()]
        [int]$EventId = 0
    )
    
    $timestamp = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss.fff')
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Verbose'     { Write-Verbose $logMessage }
        'Information' { Write-Information $logMessage -InformationAction Continue }
        'Warning'     { Write-Warning $logMessage }
        'Error'       { Write-Error $logMessage }
    }
    
    # Write to log file if configured
    if ($Script:Config -and $Script:Config.General.LogPath) {
        $logFile = Join-Path $Script:Config.General.LogPath "UserSync_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    
    # Write to event log
    if ($EventId -gt 0 -and $Script:Config) {
        $entryType = switch ($Level) {
            'Error'   { 'Error' }
            'Warning' { 'Warning' }
            default   { 'Information' }
        }
        Write-TierGuardEvent -Message $Message -EntryType $entryType `
            -EventId $EventId -Source $Script:Config.General.EventLogSource
    }
}

#endregion

#region Main Processing Functions

function Get-TierConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Tier
    )
    
    return switch ($Tier) {
        0 { $Script:Config.Tier0 }
        1 { $Script:Config.Tier1 }
    }
}

function Get-TargetDomains {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()
    
    $allDomains = Get-AdsiForestDomains
    
    # Filter by target domains if specified
    if ($Script:Config.Domains.TargetDomains.Count -gt 0) {
        $allDomains = $allDomains | Where-Object {
            $_.DnsName -in $Script:Config.Domains.TargetDomains -or
            $_.NetBIOSName -in $Script:Config.Domains.TargetDomains
        }
    }
    
    # Exclude specified domains
    if ($Script:Config.Domains.ExcludedDomains.Count -gt 0) {
        $allDomains = $allDomains | Where-Object {
            $_.DnsName -notin $Script:Config.Domains.ExcludedDomains -and
            $_.NetBIOSName -notin $Script:Config.Domains.ExcludedDomains
        }
    }
    
    return @($allDomains)
}

function Get-TierAdminUsers {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )
    
    $users = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($ouPath in $Script:TierConfig.AdminOUs) {
        $fullPath = if ($ouPath -match 'DC=') {
            # Full DN - check if it belongs to this domain
            $pathDomain = Get-AdsiDomainFromDN -DistinguishedName $ouPath
            if ($pathDomain -ne $DomainDN) { continue }
            $ouPath
        }
        else {
            "$ouPath,$DomainDN"
        }
        
        try {
            Write-Log "Searching for admin users in OU: $fullPath" -Level Verbose
            
            $results = Get-AdsiUser -SearchBase $fullPath -Server $DomainDnsName
            
            foreach ($user in $results) {
                # Skip excluded accounts
                if ($Script:TierConfig.ExcludedAccounts -contains $user.sAMAccountName) {
                    Write-Log "Skipping excluded account: $($user.sAMAccountName)" -Level Verbose
                    continue
                }
                
                # Skip managed service accounts
                if (Test-AdsiManagedServiceAccount -UserObject $user) {
                    Write-Log "Skipping managed service account: $($user.sAMAccountName)" -Level Verbose
                    continue
                }
                
                $users.Add($user)
            }
            
            Write-Log "Found $($results.Count) users in OU: $fullPath" -Level Verbose
        }
        catch {
            Write-Log "Error searching OU '$fullPath': $_" -Level Warning
        }
    }
    
    return $users
}

function Get-TierServiceAccounts {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )
    
    $users = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($ouPath in $Script:TierConfig.ServiceAccountOUs) {
        $fullPath = if ($ouPath -match 'DC=') {
            $pathDomain = Get-AdsiDomainFromDN -DistinguishedName $ouPath
            if ($pathDomain -ne $DomainDN) { continue }
            $ouPath
        }
        else {
            "$ouPath,$DomainDN"
        }
        
        try {
            $results = Get-AdsiUser -SearchBase $fullPath -Server $DomainDnsName
            foreach ($user in $results) {
                $users.Add($user)
            }
        }
        catch {
            Write-Log "Error searching service account OU '$fullPath': $_" -Level Warning
        }
    }
    
    return $users
}

function Get-KerberosAuthenticationPolicyDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyName
    )
    
    $policies = Get-AdsiKerberosAuthenticationPolicy -Name $PolicyName
    
    if ($policies.Count -gt 0) {
        return $policies[0].distinguishedName
    }
    
    return $null
}

function Test-UserHasAuthenticationPolicy {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$User,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPolicyDN
    )
    
    $currentPolicy = $User.'msDS-AssignedAuthNPolicy'
    
    if (-not $currentPolicy) {
        return $false
    }
    
    return $currentPolicy -eq $ExpectedPolicyDN
}

function Invoke-UserPolicyApplication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable[]]$Users,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )
    
    $eventIds = Get-TierGuardEventIds
    $appliedCount = 0
    $skippedCount = 0
    $errorCount = 0
    
    $throttle = if ($ThrottleLimit -gt 0) { $ThrottleLimit } else { $Script:Config.General.MaxParallelOperations }
    
    # Filter users that don't have the policy
    $usersNeedingPolicy = @($Users | Where-Object { 
        -not (Test-UserHasAuthenticationPolicy -User $_ -ExpectedPolicyDN $PolicyDN) 
    })
    
    $skippedCount = $Users.Count - $usersNeedingPolicy.Count
    
    if ($usersNeedingPolicy.Count -eq 0) {
        Write-Log "All users already have the authentication policy applied" -Level Information
        return @{
            Applied = 0
            Skipped = $skippedCount
            Errors  = 0
        }
    }
    
    Write-Log "Applying authentication policy to $($usersNeedingPolicy.Count) users" -Level Information
    
    $applyScript = {
        param($PolicyDN, $DomainDnsName)
        
        try {
            Set-AdsiAuthenticationPolicy -TargetDistinguishedName $_.distinguishedName `
                -PolicyDistinguishedName $PolicyDN `
                -Server $DomainDnsName -Confirm:$false
            
            return @{
                Success = $true
                User    = $_.sAMAccountName
                DN      = $_.distinguishedName
            }
        }
        catch {
            return @{
                Success = $false
                User    = $_.sAMAccountName
                DN      = $_.distinguishedName
                Error   = $_.Exception.Message
            }
        }
    }
    
    if ($PSCmdlet.ShouldProcess("$($usersNeedingPolicy.Count) users", "Apply authentication policy")) {
        $results = $usersNeedingPolicy | Invoke-ParallelOperation -ScriptBlock $applyScript `
            -ThrottleLimit $throttle `
            -ArgumentList @{ PolicyDN = $PolicyDN; DomainDnsName = $DomainDnsName } `
            -ShowProgress -ProgressActivity "Applying Kerberos Authentication Policy"
        
        foreach ($result in $results) {
            if ($result.Output.Success) {
                $appliedCount++
                Write-Log "Applied authentication policy to: $($result.Output.User)" -Level Verbose `
                    -EventId $eventIds.PolicyApplied
            }
            else {
                $errorCount++
                Write-Log "Failed to apply policy to $($result.Output.User): $($result.Output.Error)" -Level Warning
            }
        }
    }
    
    return @{
        Applied = $appliedCount
        Skipped = $skippedCount
        Errors  = $errorCount
    }
}

function Invoke-ProtectedUsersMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable[]]$Users,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName
    )
    
    if ($SkipProtectedUsers -or -not $Script:TierConfig.AddToProtectedUsers) {
        Write-Log "Protected Users membership management is disabled" -Level Verbose
        return @{ Added = 0; Skipped = $Users.Count; Errors = 0 }
    }
    
    $eventIds = Get-TierGuardEventIds
    $addedCount = 0
    $skippedCount = 0
    $errorCount = 0
    
    # Get Protected Users group
    try {
        $protectedGroup = Get-AdsiProtectedUsersGroup -DomainDN $DomainDN -Server $DomainDnsName
        $protectedGroupMembers = Get-AdsiGroupMember -GroupDistinguishedName $protectedGroup.distinguishedName `
            -Server $DomainDnsName
        $memberSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($member in $protectedGroupMembers) {
            [void]$memberSet.Add($member)
        }
    }
    catch {
        Write-Log "Failed to get Protected Users group: $_" -Level Warning
        return @{ Added = 0; Skipped = $Users.Count; Errors = 1 }
    }
    
    # Filter users not in Protected Users
    $usersToAdd = @($Users | Where-Object { -not $memberSet.Contains($_.distinguishedName) })
    $skippedCount = $Users.Count - $usersToAdd.Count
    
    if ($usersToAdd.Count -eq 0) {
        Write-Log "All users are already in Protected Users group" -Level Information
        return @{ Added = 0; Skipped = $skippedCount; Errors = 0 }
    }
    
    Write-Log "Adding $($usersToAdd.Count) users to Protected Users group" -Level Information
    
    $throttle = if ($ThrottleLimit -gt 0) { $ThrottleLimit } else { $Script:Config.General.MaxParallelOperations }
    
    $addScript = {
        param($ProtectedGroupDN, $DomainDnsName)
        
        try {
            Add-AdsiGroupMember -GroupDistinguishedName $ProtectedGroupDN `
                -MemberDistinguishedName $_.distinguishedName `
                -Server $DomainDnsName -Confirm:$false
            
            return @{
                Success = $true
                User    = $_.sAMAccountName
            }
        }
        catch {
            return @{
                Success = $false
                User    = $_.sAMAccountName
                Error   = $_.Exception.Message
            }
        }
    }
    
    if ($PSCmdlet.ShouldProcess("$($usersToAdd.Count) users", "Add to Protected Users")) {
        $results = $usersToAdd | Invoke-ParallelOperation -ScriptBlock $addScript `
            -ThrottleLimit $throttle `
            -ArgumentList @{ ProtectedGroupDN = $protectedGroup.distinguishedName; DomainDnsName = $DomainDnsName } `
            -ShowProgress -ProgressActivity "Adding to Protected Users"
        
        foreach ($result in $results) {
            if ($result.Output.Success) {
                $addedCount++
                Write-Log "Added to Protected Users: $($result.Output.User)" -Level Verbose `
                    -EventId $eventIds.AddedToProtectedUsers
            }
            else {
                $errorCount++
                Write-Log "Failed to add to Protected Users: $($result.Output.User) - $($result.Output.Error)" -Level Warning
            }
        }
    }
    
    return @{
        Added   = $addedCount
        Skipped = $skippedCount
        Errors  = $errorCount
    }
}

function Invoke-PrivilegedGroupCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainDN,
        
        [Parameter(Mandatory = $true)]
        [string]$DomainDnsName,
        
        [Parameter(Mandatory = $true)]
        [hashtable[]]$TierAdmins,
        
        [Parameter(Mandatory = $true)]
        [hashtable[]]$ServiceAccounts
    )
    
    if ($TierLevel -ne 0 -or $SkipPrivilegedGroupCleanup -or -not $Script:TierConfig.EnforcePrivilegedGroupCleanup) {
        Write-Log "Privileged group cleanup is disabled or not applicable for Tier $TierLevel" -Level Verbose
        return @{ Removed = 0; Errors = 0 }
    }
    
    $eventIds = Get-TierGuardEventIds
    $removedCount = 0
    $errorCount = 0
    
    # Build set of allowed accounts
    $allowedAccounts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    
    foreach ($admin in $TierAdmins) {
        [void]$allowedAccounts.Add($admin.distinguishedName)
    }
    
    foreach ($svc in $ServiceAccounts) {
        [void]$allowedAccounts.Add($svc.distinguishedName)
    }
    
    # Built-in administrator account is always allowed
    $builtinAdmin = "CN=Administrator,CN=Users,$DomainDN"
    [void]$allowedAccounts.Add($builtinAdmin)
    
    Write-Log "Getting privileged groups in domain: $DomainDnsName" -Level Verbose
    $privilegedGroups = Get-AdsiPrivilegedGroup -DomainDN $DomainDN -Server $DomainDnsName
    
    foreach ($group in $privilegedGroups) {
        Write-Log "Checking group: $($group.sAMAccountName)" -Level Verbose
        
        $members = Get-AdsiGroupMember -GroupDistinguishedName $group.distinguishedName `
            -Server $DomainDnsName
        
        foreach ($memberDN in $members) {
            if ($allowedAccounts.Contains($memberDN)) {
                continue
            }
            
            # Check if this is a group (skip groups)
            try {
                $memberObj = Get-AdsiObject -DistinguishedName $memberDN `
                    -Properties @('objectClass', 'sAMAccountName', 'userAccountControl') `
                    -Server $DomainDnsName
                
                if ($memberObj.objectClass -contains 'group') {
                    continue
                }
                
                # Check if it's a GMSA
                if ($memberObj.objectClass -contains 'msDS-GroupManagedServiceAccount') {
                    Write-Log "Skipping GMSA: $($memberObj.sAMAccountName)" -Level Verbose
                    continue
                }
                
                # This is an unauthorized member
                Write-Log "Unauthorized member found in $($group.sAMAccountName): $($memberObj.sAMAccountName)" -Level Warning
                
                if ($PSCmdlet.ShouldProcess("$($memberObj.sAMAccountName)", "Remove from $($group.sAMAccountName)")) {
                    try {
                        Remove-AdsiGroupMember -GroupDistinguishedName $group.distinguishedName `
                            -MemberDistinguishedName $memberDN `
                            -Server $DomainDnsName -Confirm:$false
                        
                        $removedCount++
                        Write-Log "Removed $($memberObj.sAMAccountName) from $($group.sAMAccountName)" -Level Information `
                            -EventId $eventIds.RemovedFromPrivilegedGroup
                    }
                    catch {
                        $errorCount++
                        Write-Log "Failed to remove $($memberObj.sAMAccountName) from $($group.sAMAccountName): $_" -Level Warning
                    }
                }
            }
            catch {
                Write-Log "Error checking member '$memberDN': $_" -Level Warning
            }
        }
    }
    
    return @{
        Removed = $removedCount
        Errors  = $errorCount
    }
}

function Invoke-DomainUserSync {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Domain
    )
    
    $domainDN = $Domain.DistinguishedName
    $domainDns = $Domain.DnsName
    
    Write-Log "Processing domain: $domainDns" -Level Information
    
    # Get Kerberos Authentication Policy
    $policyDN = Get-KerberosAuthenticationPolicyDN -PolicyName $Script:TierConfig.KerberosAuthPolicyName
    
    if (-not $policyDN) {
        Write-Log "Kerberos Authentication Policy '$($Script:TierConfig.KerberosAuthPolicyName)' not found" -Level Error
        return @{
            Domain  = $domainDns
            Success = $false
            Message = "Kerberos Authentication Policy not found"
        }
    }
    
    # Get tier admin users
    $adminUsers = Get-TierAdminUsers -DomainDN $domainDN -DomainDnsName $domainDns
    Write-Log "Found $($adminUsers.Count) Tier $TierLevel admin users in domain $domainDns" -Level Information
    
    # Get service accounts (no policy applied, but allowed in privileged groups)
    $serviceAccounts = Get-TierServiceAccounts -DomainDN $domainDN -DomainDnsName $domainDns
    Write-Log "Found $($serviceAccounts.Count) Tier $TierLevel service accounts in domain $domainDns" -Level Information
    
    # Apply Kerberos Authentication Policy
    $policyResult = Invoke-UserPolicyApplication -Users $adminUsers.ToArray() `
        -PolicyDN $policyDN -DomainDnsName $domainDns
    
    # Add to Protected Users
    $protectedResult = Invoke-ProtectedUsersMembership -Users $adminUsers.ToArray() `
        -DomainDN $domainDN -DomainDnsName $domainDns
    
    # Privileged group cleanup (Tier 0 only)
    $cleanupResult = Invoke-PrivilegedGroupCleanup -DomainDN $domainDN -DomainDnsName $domainDns `
        -TierAdmins $adminUsers.ToArray() -ServiceAccounts $serviceAccounts.ToArray()
    
    return @{
        Domain                = $domainDns
        Success               = $true
        AdminUsersFound       = $adminUsers.Count
        ServiceAccountsFound  = $serviceAccounts.Count
        PoliciesApplied       = $policyResult.Applied
        PoliciesSkipped       = $policyResult.Skipped
        PolicyErrors          = $policyResult.Errors
        AddedToProtectedUsers = $protectedResult.Added
        RemovedFromGroups     = $cleanupResult.Removed
        CleanupErrors         = $cleanupResult.Errors
    }
}

#endregion

#region Main Execution

try {
    # Load configuration
    Write-Log "Loading configuration from: $ConfigurationPath" -Level Information
    $Script:Config = Import-TierGuardConfiguration -Path $ConfigurationPath
    
    # Initialize event logging
    Initialize-TierGuardEventLog -Source $Script:Config.General.EventLogSource
    
    $eventIds = Get-TierGuardEventIds
    Write-Log "Starting Tier $TierLevel User Sync" -Level Information -EventId $eventIds.UserSyncStarted
    
    # Get tier-specific configuration
    $Script:TierConfig = Get-TierConfiguration -Tier $TierLevel
    
    if (-not $Script:TierConfig.Enabled) {
        Write-Log "Tier $TierLevel is not enabled in configuration. Exiting." -Level Warning
        exit 0
    }
    
    # Override forest scope if specified
    if ($ForestScope) {
        $Script:Config.General.ForestScope = $true
    }
    
    # Get target domains
    $targetDomains = if ($Script:Config.General.ForestScope) {
        Get-TargetDomains
    }
    else {
        $rootDse = Get-AdsiRootDse
        @(@{
            DistinguishedName = $rootDse.DefaultNamingContext
            DnsName           = $rootDse.DnsHostName -replace '^[^.]+\.'
            NetBIOSName       = ($rootDse.DefaultNamingContext -split ',' | 
                Where-Object { $_ -like 'DC=*' } | 
                Select-Object -First 1) -replace 'DC='
        })
    }
    
    Write-Log "Processing $($targetDomains.Count) domain(s)" -Level Information
    
    # Process each domain
    $results = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($domain in $targetDomains) {
        $result = Invoke-DomainUserSync -Domain $domain
        $results.Add($result)
    }
    
    # Generate summary
    $totalAdmins = ($results | Measure-Object -Property AdminUsersFound -Sum).Sum
    $totalServiceAccounts = ($results | Measure-Object -Property ServiceAccountsFound -Sum).Sum
    $totalPoliciesApplied = ($results | Measure-Object -Property PoliciesApplied -Sum).Sum
    $totalAddedProtected = ($results | Measure-Object -Property AddedToProtectedUsers -Sum).Sum
    $totalRemovedFromGroups = ($results | Measure-Object -Property RemovedFromGroups -Sum).Sum
    $totalErrors = ($results | Measure-Object -Property PolicyErrors -Sum).Sum + 
                   ($results | Measure-Object -Property CleanupErrors -Sum).Sum
    $successfulDomains = ($results | Where-Object { $_.Success }).Count
    
    $duration = [DateTime]::Now - $Script:StartTime
    
    $summary = @"
Tier $TierLevel User Sync Completed
========================================
Duration: $($duration.ToString('hh\:mm\:ss'))
Domains Processed: $($targetDomains.Count) (Success: $successfulDomains)
Admin Users Found: $totalAdmins
Service Accounts Found: $totalServiceAccounts
Authentication Policies Applied: $totalPoliciesApplied
Users Added to Protected Users: $totalAddedProtected
Users Removed from Privileged Groups: $totalRemovedFromGroups
Errors: $totalErrors
"@
    
    Write-Log $summary -Level Information -EventId $eventIds.UserSyncCompleted
    
    # Output results object
    [PSCustomObject]@{
        TierLevel              = $TierLevel
        Duration               = $duration
        DomainsProcessed       = $targetDomains.Count
        SuccessfulDomains      = $successfulDomains
        TotalAdminUsers        = $totalAdmins
        TotalServiceAccounts   = $totalServiceAccounts
        PoliciesApplied        = $totalPoliciesApplied
        AddedToProtectedUsers  = $totalAddedProtected
        RemovedFromGroups      = $totalRemovedFromGroups
        Errors                 = $totalErrors
        DomainResults          = $results
    }
}
catch {
    $eventIds = Get-TierGuardEventIds
    Write-Log "Critical error during Tier $TierLevel User Sync: $_" -Level Error `
        -EventId $eventIds.UserSyncFailed
    throw
}

#endregion
