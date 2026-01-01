<#
.SYNOPSIS
    ADTierGuard - Tier User Synchronization
    
.DESCRIPTION
    Manages user objects for Tier 0 and Tier 1 isolation by:
    - Applying Kerberos Authentication Policies to admin users
    - Adding admin users to Protected Users group
    - Removing unauthorized users from privileged groups (Tier 0 only)
    
    Uses pure ADSI operations with runspace-based parallel processing for
    high performance in large environments.
    
.PARAMETER ConfigurationPath
    Path to the ADTierGuard configuration JSON file.
    
.PARAMETER TierLevel
    The tier level to process (0 or 1).
    
.PARAMETER ForestScope
    Process all domains in the forest (overrides configuration setting).
    
.PARAMETER SkipProtectedUsers
    Skip adding users to Protected Users group.
    
.PARAMETER SkipPrivilegedGroupCleanup
    Skip removing unauthorized users from privileged groups.
    
.PARAMETER ThrottleLimit
    Maximum concurrent operations. Defaults to configuration value.
    
.PARAMETER WhatIf
    Shows what changes would be made without executing them.
    
.PARAMETER Confirm
    Prompts for confirmation before each change.
    
.EXAMPLE
    .\Invoke-TierUserSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0
    
    Full Tier 0 user synchronization including policy, Protected Users, and cleanup.
    
.EXAMPLE
    .\Invoke-TierUserSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 0 -WhatIf
    
    Shows what changes would be made without executing them.
    
.EXAMPLE
    .\Invoke-TierUserSync.ps1 -ConfigurationPath "C:\ADTierGuard\config.json" -TierLevel 1 -SkipPrivilegedGroupCleanup
    
    Tier 1 sync without privileged group cleanup (cleanup is Tier 0 only anyway).
    
.OUTPUTS
    PSCustomObject with sync results including:
    - TierLevel, Duration, DomainsProcessed
    - AdminUsersFound, ServiceAccountsFound
    - PoliciesApplied, AddedToProtectedUsers, RemovedFromGroups
    - Errors, DomainResults array
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Domain connectivity
    - Forest functional level 2012 R2+ for Kerberos Authentication Policies
    - Appropriate permissions
    
.LINK
    https://github.com/ADTierGuard/ADTierGuard
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Path to configuration JSON file')]
    [ValidateScript({ 
        if (-not (Test-Path $_)) { throw "Configuration file not found: $_" }
        if ($_ -notmatch '\.json$') { throw "Configuration must be a JSON file" }
        $true
    })]
    [string]$ConfigurationPath,
    
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = 'Tier level (0 or 1)')]
    [ValidateSet(0, 1)]
    [int]$TierLevel,
    
    [Parameter(HelpMessage = 'Process all domains in forest')]
    [switch]$ForestScope,
    
    [Parameter(HelpMessage = 'Skip Protected Users membership')]
    [switch]$SkipProtectedUsers,
    
    [Parameter(HelpMessage = 'Skip privileged group cleanup')]
    [switch]$SkipPrivilegedGroupCleanup,
    
    [Parameter(HelpMessage = 'Maximum concurrent operations')]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 0
)

#region Script Initialization

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script-level state
$Script:StartTime = [DateTime]::UtcNow
$Script:ModulePath = Split-Path -Parent $PSScriptRoot
$Script:Config = $null
$Script:TierConfig = $null

# Import required modules
$requiredModules = @(
    'Core\AdsiOperations.psm1'
    'Core\ConfigurationManager.psm1'
    'Core\SyncUtilities.psm1'
    'Engine\RunspaceEngine.psm1'
)

foreach ($moduleName in $requiredModules) {
    $modulePath = Join-Path $Script:ModulePath $moduleName
    if (-not (Test-Path $modulePath)) {
        throw "Required module not found: $modulePath"
    }
    Import-Module $modulePath -Force -ErrorAction Stop
}

#endregion

#region User Discovery Functions

<#
.SYNOPSIS
    Discovers admin users in configured OUs for a domain.
#>
function Get-TierAdminUsers {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$DomainDnsName,
        
        [Parameter(Mandatory)]
        [string[]]$AdminOUs,
        
        [Parameter()]
        [string[]]$ExcludedAccounts = @()
    )
    
    $users = [System.Collections.Generic.List[hashtable]]::new()
    $excludeSet = [System.Collections.Generic.HashSet[string]]::new(
        $ExcludedAccounts, [StringComparer]::OrdinalIgnoreCase
    )
    
    foreach ($ouPath in $AdminOUs) {
        $fullPath = Resolve-OUPathForDomain -OUPath $ouPath -DomainDN $DomainDN
        
        if ($null -eq $fullPath) {
            continue
        }
        
        try {
            Write-SyncLog -Message "Searching for admin users in: $fullPath" -Level Verbose
            
            $results = Get-AdsiUser -SearchBase $fullPath -Server $DomainDnsName
            
            foreach ($user in $results) {
                # Skip excluded accounts
                if ($excludeSet.Contains($user.sAMAccountName)) {
                    Write-SyncLog -Message "Skipping excluded account: $($user.sAMAccountName)" -Level Verbose
                    continue
                }
                
                # Skip managed service accounts (MSA/gMSA)
                if (Test-AdsiManagedServiceAccount -UserObject $user) {
                    Write-SyncLog -Message "Skipping service account: $($user.sAMAccountName)" -Level Verbose
                    continue
                }
                
                $users.Add($user)
            }
            
            Write-SyncLog -Message "Found $($results.Count) users in: $fullPath" -Level Verbose
        }
        catch {
            Write-SyncLog -Message "Error searching OU '$fullPath': $($_.Exception.Message)" -Level Warning
        }
    }
    
    return $users
}

<#
.SYNOPSIS
    Discovers service accounts in configured OUs for a domain.
#>
function Get-TierServiceAccounts {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$DomainDnsName,
        
        [Parameter(Mandatory)]
        [string[]]$ServiceAccountOUs,
        
        [Parameter()]
        [string[]]$ExcludedAccounts = @()
    )
    
    $accounts = [System.Collections.Generic.List[hashtable]]::new()
    $excludeSet = [System.Collections.Generic.HashSet[string]]::new(
        $ExcludedAccounts, [StringComparer]::OrdinalIgnoreCase
    )
    
    foreach ($ouPath in $ServiceAccountOUs) {
        $fullPath = Resolve-OUPathForDomain -OUPath $ouPath -DomainDN $DomainDN
        
        if ($null -eq $fullPath) {
            continue
        }
        
        try {
            Write-SyncLog -Message "Searching for service accounts in: $fullPath" -Level Verbose
            
            $results = Get-AdsiUser -SearchBase $fullPath -Server $DomainDnsName
            
            foreach ($account in $results) {
                if ($excludeSet.Contains($account.sAMAccountName)) {
                    continue
                }
                $accounts.Add($account)
            }
        }
        catch {
            Write-SyncLog -Message "Error searching OU '$fullPath': $($_.Exception.Message)" -Level Warning
        }
    }
    
    return $accounts
}

#endregion

#region Kerberos Policy Functions

<#
.SYNOPSIS
    Locates a Kerberos Authentication Policy by name.
#>
function Get-KerberosAuthPolicyDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName
    )
    
    $policy = Get-AdsiKerberosAuthenticationPolicy -PolicyName $PolicyName
    
    if ($policy) {
        return $policy.distinguishedName
    }
    
    return $null
}

<#
.SYNOPSIS
    Checks if a user already has the specified authentication policy.
#>
function Test-UserHasPolicy {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$User,
        
        [Parameter(Mandatory)]
        [string]$PolicyDN
    )
    
    $currentPolicy = $User.'msDS-AssignedAuthNPolicy'
    return ($currentPolicy -eq $PolicyDN)
}

<#
.SYNOPSIS
    Applies Kerberos Authentication Policy to users in parallel.
#>
function Invoke-UserPolicyApplication {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Users,
        
        [Parameter(Mandatory)]
        [string]$PolicyDN,
        
        [Parameter(Mandatory)]
        [string]$Server,
        
        [Parameter()]
        [int]$ThrottleLimit = 4
    )
    
    $eventIds = Get-TierGuardEventIds
    $stats = @{
        Applied = 0
        Skipped = 0
        Errors  = 0
    }
    
    # Filter users who need policy applied
    $usersNeedingPolicy = $Users | Where-Object {
        -not (Test-UserHasPolicy -User $_ -PolicyDN $PolicyDN)
    }
    
    $stats.Skipped = $Users.Count - $usersNeedingPolicy.Count
    
    if ($usersNeedingPolicy.Count -eq 0) {
        Write-SyncLog -Message "All users already have the authentication policy applied" -Level Information
        return $stats
    }
    
    Write-SyncLog -Message "Applying authentication policy to $($usersNeedingPolicy.Count) users" -Level Information
    
    $applyScript = {
        param($PolicyDN, $Server)
        try {
            Set-AdsiAuthenticationPolicy -UserDistinguishedName $_.distinguishedName `
                -PolicyDistinguishedName $PolicyDN -Server $Server
            @{ Success = $true; DN = $_.distinguishedName; Name = $_.sAMAccountName }
        }
        catch {
            @{ Success = $false; DN = $_.distinguishedName; Name = $_.sAMAccountName; Error = $_.Exception.Message }
        }
    }
    
    if ($PSCmdlet.ShouldProcess("$($usersNeedingPolicy.Count) users", "Apply Kerberos Authentication Policy")) {
        $results = $usersNeedingPolicy | Invoke-ParallelOperation -ScriptBlock $applyScript `
            -ThrottleLimit $ThrottleLimit `
            -ArgumentList @{ PolicyDN = $PolicyDN; Server = $Server } `
            -ShowProgress -ProgressActivity "Applying authentication policies"
        
        foreach ($result in $results) {
            if ($result.Output.Success) {
                $stats.Applied++
                Write-SyncLog -Message "Policy applied: $($result.Output.Name)" -Level Verbose `
                    -EventId $eventIds.PolicyApplied
            }
            else {
                $stats.Errors++
                Write-SyncLog -Message "Failed to apply policy to $($result.Output.Name): $($result.Output.Error)" -Level Warning
            }
        }
    }
    
    return $stats
}

#endregion

#region Protected Users Functions

<#
.SYNOPSIS
    Adds users to the Protected Users group in parallel.
#>
function Invoke-ProtectedUsersMembership {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Users,
        
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$Server,
        
        [Parameter()]
        [int]$ThrottleLimit = 4
    )
    
    $eventIds = Get-TierGuardEventIds
    $stats = @{
        Added   = 0
        Skipped = 0
        Errors  = 0
    }
    
    # Get Protected Users group
    $protectedGroup = Get-AdsiProtectedUsersGroup -DomainDN $DomainDN -Server $Server
    
    if (-not $protectedGroup) {
        Write-SyncLog -Message "Protected Users group not found in domain" -Level Warning
        return $stats
    }
    
    $protectedGroupDN = $protectedGroup.distinguishedName
    
    # Get current members
    $currentMembers = Get-AdsiGroupMember -GroupDistinguishedName $protectedGroupDN -Server $Server
    $memberSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($member in $currentMembers) {
        [void]$memberSet.Add($member)
    }
    
    # Filter users not already in Protected Users
    $usersToAdd = $Users | Where-Object {
        -not $memberSet.Contains($_.distinguishedName)
    }
    
    $stats.Skipped = $Users.Count - $usersToAdd.Count
    
    if ($usersToAdd.Count -eq 0) {
        Write-SyncLog -Message "All users already in Protected Users group" -Level Information
        return $stats
    }
    
    Write-SyncLog -Message "Adding $($usersToAdd.Count) users to Protected Users" -Level Information
    
    $addScript = {
        param($GroupDN, $Server)
        try {
            Add-AdsiGroupMember -GroupDistinguishedName $GroupDN `
                -MemberDistinguishedName $_.distinguishedName `
                -Server $Server -Confirm:$false
            @{ Success = $true; DN = $_.distinguishedName; Name = $_.sAMAccountName }
        }
        catch {
            @{ Success = $false; DN = $_.distinguishedName; Name = $_.sAMAccountName; Error = $_.Exception.Message }
        }
    }
    
    if ($PSCmdlet.ShouldProcess("$($usersToAdd.Count) users", "Add to Protected Users group")) {
        $results = $usersToAdd | Invoke-ParallelOperation -ScriptBlock $addScript `
            -ThrottleLimit $ThrottleLimit `
            -ArgumentList @{ GroupDN = $protectedGroupDN; Server = $Server } `
            -ShowProgress -ProgressActivity "Adding users to Protected Users"
        
        foreach ($result in $results) {
            if ($result.Output.Success) {
                $stats.Added++
                Write-SyncLog -Message "Added to Protected Users: $($result.Output.Name)" -Level Verbose `
                    -EventId $eventIds.AddedToProtectedUsers
            }
            else {
                $stats.Errors++
                Write-SyncLog -Message "Failed to add $($result.Output.Name) to Protected Users: $($result.Output.Error)" -Level Warning
            }
        }
    }
    
    return $stats
}

#endregion

#region Privileged Group Cleanup Functions

<#
.SYNOPSIS
    Removes unauthorized users from privileged groups.
#>
function Invoke-PrivilegedGroupCleanup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$Server,
        
        [Parameter(Mandatory)]
        [hashtable[]]$TierAdmins,
        
        [Parameter(Mandatory)]
        [hashtable[]]$ServiceAccounts
    )
    
    $eventIds = Get-TierGuardEventIds
    $stats = @{
        Removed = 0
        Errors  = 0
    }
    
    # Build allowed accounts set
    $allowedAccounts = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    
    foreach ($admin in $TierAdmins) {
        [void]$allowedAccounts.Add($admin.distinguishedName)
    }
    
    foreach ($svc in $ServiceAccounts) {
        [void]$allowedAccounts.Add($svc.distinguishedName)
    }
    
    # Built-in Administrator is always allowed
    $builtinAdmin = "CN=Administrator,CN=Users,$DomainDN"
    [void]$allowedAccounts.Add($builtinAdmin)
    
    Write-SyncLog -Message "Allowed accounts: $($allowedAccounts.Count)" -Level Verbose
    
    # Get privileged groups (adminCount=1)
    Write-SyncLog -Message "Enumerating privileged groups" -Level Information
    $privilegedGroups = Get-AdsiPrivilegedGroup -DomainDN $DomainDN -Server $Server
    
    foreach ($group in $privilegedGroups) {
        Write-SyncLog -Message "Checking group: $($group.sAMAccountName)" -Level Verbose
        
        $members = Get-AdsiGroupMember -GroupDistinguishedName $group.distinguishedName -Server $Server
        
        foreach ($memberDN in $members) {
            if ($allowedAccounts.Contains($memberDN)) {
                continue
            }
            
            try {
                # Get member details to determine type
                $memberObj = Get-AdsiObject -DistinguishedName $memberDN `
                    -Properties @('objectClass', 'sAMAccountName', 'userAccountControl') `
                    -Server $Server
                
                # Skip groups (nested group membership)
                if ($memberObj.objectClass -contains 'group') {
                    Write-SyncLog -Message "Skipping nested group: $($memberObj.sAMAccountName)" -Level Verbose
                    continue
                }
                
                # Skip gMSAs
                if ($memberObj.objectClass -contains 'msDS-GroupManagedServiceAccount') {
                    Write-SyncLog -Message "Skipping gMSA: $($memberObj.sAMAccountName)" -Level Verbose
                    continue
                }
                
                # Unauthorized member found
                Write-SyncLog -Message "UNAUTHORIZED: $($memberObj.sAMAccountName) in $($group.sAMAccountName)" -Level Warning
                
                if ($PSCmdlet.ShouldProcess($memberObj.sAMAccountName, "Remove from $($group.sAMAccountName)")) {
                    try {
                        Remove-AdsiGroupMember -GroupDistinguishedName $group.distinguishedName `
                            -MemberDistinguishedName $memberDN `
                            -Server $Server -Confirm:$false
                        
                        $stats.Removed++
                        Write-SyncLog -Message "Removed $($memberObj.sAMAccountName) from $($group.sAMAccountName)" `
                            -Level Information -EventId $eventIds.RemovedFromPrivilegedGroup
                    }
                    catch {
                        $stats.Errors++
                        Write-SyncLog -Message "Failed to remove $($memberObj.sAMAccountName): $($_.Exception.Message)" -Level Warning
                    }
                }
            }
            catch {
                Write-SyncLog -Message "Error checking member '$memberDN': $($_.Exception.Message)" -Level Warning
            }
        }
    }
    
    return $stats
}

#endregion

#region Domain Processing

<#
.SYNOPSIS
    Processes a single domain for user synchronization.
#>
function Invoke-DomainUserSync {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$TierConfig,
        
        [Parameter()]
        [int]$ThrottleLimit = 4,
        
        [Parameter()]
        [bool]$SkipProtectedUsers = $false,
        
        [Parameter()]
        [bool]$SkipPrivilegedGroupCleanup = $false
    )
    
    $domainDN = $Domain.DistinguishedName
    $domainDns = $Domain.DnsName
    
    Write-SyncLog -Message "Processing domain: $domainDns" -Level Information
    
    # Locate Kerberos Authentication Policy
    $policyDN = Get-KerberosAuthPolicyDN -PolicyName $TierConfig.KerberosAuthPolicyName
    
    if (-not $policyDN) {
        $msg = "Kerberos Authentication Policy '$($TierConfig.KerberosAuthPolicyName)' not found"
        Write-SyncLog -Message $msg -Level Error
        return New-SyncOperationResult -Domain $domainDns -Success $false -Message $msg
    }
    
    # Discover tier admin users
    $adminUsers = Get-TierAdminUsers -DomainDN $domainDN -DomainDnsName $domainDns `
        -AdminOUs $TierConfig.AdminOUs -ExcludedAccounts $TierConfig.ExcludedAccounts
    
    Write-SyncLog -Message "Found $($adminUsers.Count) Tier $TierLevel admin users" -Level Information
    
    # Discover service accounts
    $serviceAccounts = Get-TierServiceAccounts -DomainDN $domainDN -DomainDnsName $domainDns `
        -ServiceAccountOUs $TierConfig.ServiceAccountOUs -ExcludedAccounts $TierConfig.ExcludedAccounts
    
    Write-SyncLog -Message "Found $($serviceAccounts.Count) Tier $TierLevel service accounts" -Level Information
    
    # Apply Kerberos Authentication Policy
    $policyResult = Invoke-UserPolicyApplication -Users $adminUsers.ToArray() `
        -PolicyDN $policyDN -Server $domainDns -ThrottleLimit $ThrottleLimit
    
    # Add to Protected Users (if enabled)
    $protectedResult = @{ Added = 0; Skipped = 0; Errors = 0 }
    if (-not $SkipProtectedUsers -and $TierConfig.AddToProtectedUsers) {
        $protectedResult = Invoke-ProtectedUsersMembership -Users $adminUsers.ToArray() `
            -DomainDN $domainDN -Server $domainDns -ThrottleLimit $ThrottleLimit
    }
    
    # Privileged group cleanup (Tier 0 only, if enabled)
    $cleanupResult = @{ Removed = 0; Errors = 0 }
    if (-not $SkipPrivilegedGroupCleanup -and $TierLevel -eq 0 -and $TierConfig.EnforcePrivilegedGroupCleanup) {
        $cleanupResult = Invoke-PrivilegedGroupCleanup -DomainDN $domainDN -Server $domainDns `
            -TierAdmins $adminUsers.ToArray() -ServiceAccounts $serviceAccounts.ToArray()
    }
    
    return New-SyncOperationResult -Domain $domainDns -Success $true -AdditionalProperties @{
        AdminUsersFound       = $adminUsers.Count
        ServiceAccountsFound  = $serviceAccounts.Count
        PoliciesApplied       = $policyResult.Applied
        PoliciesSkipped       = $policyResult.Skipped
        PolicyErrors          = $policyResult.Errors
        AddedToProtectedUsers = $protectedResult.Added
        ProtectedUsersSkipped = $protectedResult.Skipped
        ProtectedUsersErrors  = $protectedResult.Errors
        RemovedFromGroups     = $cleanupResult.Removed
        CleanupErrors         = $cleanupResult.Errors
    }
}

#endregion

#region Main Execution

try {
    # Load and validate configuration
    $Script:Config = Import-TierGuardConfiguration -Path $ConfigurationPath
    
    # Initialize shared utilities
    Initialize-SyncUtilities -Configuration $Script:Config -LogPrefix 'UserSync'
    
    # Initialize event logging
    Initialize-TierGuardEventLog -Source $Script:Config.General.EventLogSource
    
    $eventIds = Get-TierGuardEventIds
    Write-SyncLog -Message "=== Starting Tier $TierLevel User Sync ===" -Level Information `
        -EventId $eventIds.UserSyncStarted
    Write-SyncLog -Message "Configuration: $ConfigurationPath" -Level Verbose
    
    # Validate tier is enabled
    if (-not (Test-TierEnabled -Configuration $Script:Config -TierLevel $TierLevel)) {
        Write-SyncLog -Message "Tier $TierLevel is disabled in configuration. Exiting." -Level Warning
        exit 0
    }
    
    # Get tier-specific configuration
    $Script:TierConfig = Get-TierSpecificConfiguration -Configuration $Script:Config -TierLevel $TierLevel
    
    # Determine target domains
    $useForestScope = $ForestScope.IsPresent -or $Script:Config.General.ForestScope
    $targetDomains = Get-SyncTargetDomains -Configuration $Script:Config -ForestScope $useForestScope
    
    Write-SyncLog -Message "Target domains: $($targetDomains.Count)" -Level Information
    foreach ($d in $targetDomains) {
        Write-SyncLog -Message "  - $($d.DnsName)" -Level Verbose
    }
    
    # Determine throttle limit
    $effectiveThrottle = Get-EffectiveThrottleLimit -ExplicitLimit $ThrottleLimit `
        -Configuration $Script:Config -Default 4
    Write-SyncLog -Message "Throttle limit: $effectiveThrottle" -Level Verbose
    
    # Log options
    Write-SyncLog -Message "Options: SkipProtectedUsers=$($SkipProtectedUsers.IsPresent), SkipPrivilegedGroupCleanup=$($SkipPrivilegedGroupCleanup.IsPresent)" -Level Verbose
    
    # Process each domain
    $results = [System.Collections.Generic.List[hashtable]]::new()
    
    foreach ($domain in $targetDomains) {
        $result = Invoke-DomainUserSync -Domain $domain -TierConfig $Script:TierConfig `
            -ThrottleLimit $effectiveThrottle `
            -SkipProtectedUsers $SkipProtectedUsers.IsPresent `
            -SkipPrivilegedGroupCleanup $SkipPrivilegedGroupCleanup.IsPresent
        $results.Add($result)
    }
    
    # Calculate totals
    $duration = [DateTime]::UtcNow - $Script:StartTime
    $totalAdmins = ($results | Measure-Object -Property AdminUsersFound -Sum).Sum
    $totalServiceAccounts = ($results | Measure-Object -Property ServiceAccountsFound -Sum).Sum
    $totalPoliciesApplied = ($results | Measure-Object -Property PoliciesApplied -Sum).Sum
    $totalAddedProtected = ($results | Measure-Object -Property AddedToProtectedUsers -Sum).Sum
    $totalRemovedFromGroups = ($results | Measure-Object -Property RemovedFromGroups -Sum).Sum
    $totalErrors = ($results | ForEach-Object { $_.PolicyErrors + $_.ProtectedUsersErrors + $_.CleanupErrors } | Measure-Object -Sum).Sum
    $successfulDomains = ($results | Where-Object { $_.Success }).Count
    
    # Generate and log summary
    $summary = Format-SyncSummary -OperationType 'User' -TierLevel $TierLevel `
        -Duration $duration -Results $results.ToArray() -Metrics @{
            'Admin Users Found'       = 'AdminUsersFound'
            'Service Accounts Found'  = 'ServiceAccountsFound'
            'Policies Applied'        = 'PoliciesApplied'
            'Added to Protected Users' = 'AddedToProtectedUsers'
            'Removed from Groups'     = 'RemovedFromGroups'
        }
    
    Write-SyncLog -Message $summary -Level Information -EventId $eventIds.UserSyncCompleted
    
    # Return structured result object
    [PSCustomObject]@{
        TierLevel             = $TierLevel
        StartTime             = $Script:StartTime
        Duration              = $duration
        DomainsProcessed      = $targetDomains.Count
        SuccessfulDomains     = $successfulDomains
        TotalAdminUsers       = [int]$totalAdmins
        TotalServiceAccounts  = [int]$totalServiceAccounts
        PoliciesApplied       = [int]$totalPoliciesApplied
        AddedToProtectedUsers = [int]$totalAddedProtected
        RemovedFromGroups     = [int]$totalRemovedFromGroups
        Errors                = [int]$totalErrors
        DomainResults         = $results.ToArray()
    }
}
catch {
    $eventIds = Get-TierGuardEventIds
    $errorMessage = "FATAL: Tier $TierLevel User Sync failed: $($_.Exception.Message)"
    
    if (Test-SyncUtilitiesInitialized) {
        Write-SyncLog -Message $errorMessage -Level Error -EventId $eventIds.UserSyncFailed
        Write-SyncLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level Error
    }
    else {
        Write-Error $errorMessage
    }
    
    throw
}

#endregion
