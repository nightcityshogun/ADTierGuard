<#
.SYNOPSIS
    TierGuard User Synchronization Script for Domain Controllers
    
.DESCRIPTION
    This script runs on Domain Controllers via GPO-deployed scheduled tasks.
    It manages tier user protections including:
    
    - Applying Kerberos Authentication Policies to tier admins
    - Adding Tier 0 users to Protected Users group
    - Removing unexpected users from privileged groups (optional)
    
.PARAMETER ConfigFile
    Path to TierGuard.config. Defaults to SYSVOL location.
    
.PARAMETER Scope
    Which tier to process: Tier-0, Tier-1, or All-Tiers
    
.PARAMETER WhatIf
    Show what would happen without making changes
    
.NOTES
    Version: 1.0.0
    Runs as: GMSA (Group Managed Service Account) with Enterprise Admin rights
    Schedule: Every 10 minutes via GPO
    
    Event IDs:
    2000 - Script started
    2001 - Script completed
    2100 - User policy applied
    2101 - User added to Protected Users
    2102 - User removed from privileged group
    2103 - AdminCount cleared from user
    2200 - Error occurred
    2201 - Policy not found
    2202 - User skipped (service account)
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ConfigFile,
    
    [Parameter()]
    [ValidateSet('Tier-0', 'Tier-1', 'All-Tiers')]
    [string]$Scope
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Constants

$Script:EventSource = 'TierGuard'
$Script:EventLogName = 'Application'
$Script:LogFile = $null

# Event IDs
$Script:EventIds = @{
    ScriptStarted = 2000
    ScriptCompleted = 2001
    PolicyApplied = 2100
    ProtectedUserAdded = 2101
    PrivGroupRemoved = 2102
    AdminCountCleared = 2103
    ErrorOccurred = 2200
    PolicyNotFound = 2201
    UserSkipped = 2202
    ConfigLoaded = 2010
}

# Well-known privileged group RIDs
$Script:PrivilegedGroupRIDs = @{
    DomainAdmins = 512
    SchemaAdmins = 518
    EnterpriseAdmins = 519
    Administrators = 544
    AccountOperators = 548
    ServerOperators = 549
    PrintOperators = 550
    BackupOperators = 551
    DnsAdmins = 1101
}

#endregion

#region Logging Functions

function Initialize-EventLog {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Script:EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($Script:EventSource, $Script:EventLogName)
        }
    }
    catch { }
}

function Write-TierGuardLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information',
        
        [Parameter()]
        [int]$EventId = 2000
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Severity] $Message"
    
    if ($Script:LogFile) {
        try { Add-Content -Path $Script:LogFile -Value $logMessage -ErrorAction SilentlyContinue }
        catch { }
    }
    
    try {
        $entryType = switch ($Severity) {
            'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
            'Error' { [System.Diagnostics.EventLogEntryType]::Error }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        
        Write-EventLog -LogName $Script:EventLogName -Source $Script:EventSource `
            -EventId $EventId -EntryType $entryType -Message $Message -ErrorAction SilentlyContinue
    }
    catch { }
    
    switch ($Severity) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Host $Message -ForegroundColor Red }
        default { Write-Verbose $Message }
    }
}

#endregion

#region Configuration Functions

function Get-TierGuardConfig {
    param([string]$Path)
    
    if (-not $Path) {
        $domainDns = (Get-ADDomain).DNSRoot
        $Path = "\\$domainDns\SYSVOL\$domainDns\scripts\TierGuard\TierGuard.config"
    }
    
    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }
    
    $config = Get-Content -Path $Path -Raw | ConvertFrom-Json
    
    $result = @{
        SchemaVersion = $config.SchemaVersion
        Scope = $config.Scope
        Domains = @($config.Domains)
        ProtectedUsers = $config.ProtectedUsers
        PrivilegedGroupCleanup = $config.PrivilegedGroupCleanup
        Tier0 = @{
            AdminOUs = @($config.Tier0.AdminOUs)
            ServiceAccountOUs = @($config.Tier0.ServiceAccountOUs)
            ComputerOUs = @($config.Tier0.ComputerOUs)
            ComputerGroup = $config.Tier0.ComputerGroup
            PolicyName = $config.Tier0.PolicyName
            TGTLifetimeMinutes = $config.Tier0.TGTLifetimeMinutes
        }
        Tier1 = @{
            AdminOUs = @($config.Tier1.AdminOUs)
            ServiceAccountOUs = @($config.Tier1.ServiceAccountOUs)
            ComputerOUs = @($config.Tier1.ComputerOUs)
            ComputerGroup = $config.Tier1.ComputerGroup
            PolicyName = $config.Tier1.PolicyName
            TGTLifetimeMinutes = $config.Tier1.TGTLifetimeMinutes
        }
    }
    
    if ($config.LogPath) {
        $Script:LogFile = Join-Path $config.LogPath "TierGuard-User-$(Get-Date -Format 'yyyyMMdd').log"
    }
    else {
        $Script:LogFile = Join-Path $env:LOCALAPPDATA "TierGuard\TierGuard-User-$(Get-Date -Format 'yyyyMMdd').log"
        $logDir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    }
    
    return $result
}

#endregion

#region OU and User Functions

function Resolve-TierOU {
    param(
        [Parameter(Mandatory)]
        [string]$OUPath,
        
        [Parameter(Mandatory)]
        [string]$DomainDN
    )
    
    if ($OUPath -match 'DC=') {
        if ($OUPath -like "*$DomainDN") { return $OUPath }
        return $null
    }
    
    return "$OUPath,$DomainDN"
}

function Test-IsServiceAccount {
    param(
        [Parameter(Mandatory)]
        [string]$UserDN,
        
        [Parameter(Mandatory)]
        [string[]]$ServiceAccountOUs,
        
        [Parameter(Mandatory)]
        [string]$DomainDN
    )
    
    foreach ($ou in $ServiceAccountOUs) {
        $resolvedOU = Resolve-TierOU -OUPath $ou -DomainDN $DomainDN
        if ($resolvedOU -and $UserDN -like "*$resolvedOU") {
            return $true
        }
    }
    
    return $false
}

function Test-IsBuiltInAdmin {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        
        [Parameter(Mandatory)]
        [string]$DomainSID
    )
    
    # Check if this is the built-in Administrator (RID 500)
    return $User.SID.Value -eq "$DomainSID-500"
}

function Get-TierUsers {
    param(
        [Parameter(Mandatory)]
        [string]$SearchBase,
        
        [Parameter(Mandatory)]
        [string]$Server
    )
    
    try {
        $users = Get-ADUser -Filter { Enabled -eq $true } -SearchBase $SearchBase -SearchScope Subtree `
            -Properties DistinguishedName, SamAccountName, UserPrincipalName, MemberOf, `
                        msDS-AssignedAuthNPolicy, ObjectClass, SID, adminCount `
            -Server $Server -ErrorAction Stop
        
        # Filter out computer accounts and GMSAs
        return @($users | Where-Object { 
            $_.ObjectClass -eq 'user' -and 
            $_.SamAccountName -notlike '*$'
        })
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-TierGuardLog -Message "OU not found: $SearchBase" -Severity Warning -EventId $Script:EventIds.ErrorOccurred
        return @()
    }
    catch {
        Write-TierGuardLog -Message "Error searching OU $SearchBase`: $_" -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return @()
    }
}

#endregion

#region Policy Functions

function Get-AuthenticationPolicyDN {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName
    )
    
    try {
        $policy = Get-ADAuthenticationPolicy -Identity $PolicyName -ErrorAction Stop
        return $policy.DistinguishedName
    }
    catch {
        Write-TierGuardLog -Message "Authentication Policy '$PolicyName' not found" `
            -Severity Error -EventId $Script:EventIds.PolicyNotFound
        return $null
    }
}

function Set-UserAuthPolicy {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        
        [Parameter(Mandatory)]
        [string]$PolicyDN,
        
        [Parameter()]
        [string]$Server
    )
    
    $currentPolicy = $User.'msDS-AssignedAuthNPolicy'
    if ($currentPolicy -eq $PolicyDN) {
        return $true  # Already set
    }
    
    if ($WhatIfPreference) {
        Write-Host "WhatIf: Would set auth policy on $($User.SamAccountName)" -ForegroundColor Cyan
        return $true
    }
    
    try {
        $params = @{
            Identity = $User.DistinguishedName
            Replace = @{ 'msDS-AssignedAuthNPolicy' = $PolicyDN }
        }
        if ($Server) { $params.Server = $Server }
        
        Set-ADUser @params -ErrorAction Stop
        
        Write-TierGuardLog -Message "Applied auth policy to user $($User.SamAccountName)" `
            -Severity Information -EventId $Script:EventIds.PolicyApplied
        
        return $true
    }
    catch {
        Write-TierGuardLog -Message "Failed to set policy on $($User.SamAccountName): $_" `
            -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return $false
    }
}

#endregion

#region Protected Users Functions

function Add-UserToProtectedUsers {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        
        [Parameter(Mandatory)]
        [string]$DomainSID,
        
        [Parameter()]
        [string]$Server
    )
    
    try {
        $protectedUsersGroup = Get-ADGroup -Identity "$DomainSID-525" -Server $Server
        $members = Get-ADGroupMember -Identity $protectedUsersGroup -Server $Server -ErrorAction SilentlyContinue
        
        if ($members.SID -contains $User.SID) {
            return $true  # Already a member
        }
        
        if ($WhatIfPreference) {
            Write-Host "WhatIf: Would add $($User.SamAccountName) to Protected Users" -ForegroundColor Cyan
            return $true
        }
        
        Add-ADGroupMember -Identity $protectedUsersGroup -Members $User -Server $Server -ErrorAction Stop
        
        Write-TierGuardLog -Message "Added $($User.SamAccountName) to Protected Users" `
            -Severity Information -EventId $Script:EventIds.ProtectedUserAdded
        
        return $true
    }
    catch {
        Write-TierGuardLog -Message "Failed to add $($User.SamAccountName) to Protected Users: $_" `
            -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return $false
    }
}

#endregion

#region Privileged Group Cleanup Functions

function Get-PrivilegedGroupMembers {
    param(
        [Parameter(Mandatory)]
        [string]$DomainSID,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [switch]$IncludeEnterpriseGroups
    )
    
    $results = @{}
    
    # Domain-level groups
    $domainGroups = @(
        @{ Name = 'Domain Admins'; SID = "$DomainSID-512" },
        @{ Name = 'Administrators'; SID = "$DomainSID-544" },
        @{ Name = 'Account Operators'; SID = "$DomainSID-548" },
        @{ Name = 'Server Operators'; SID = "$DomainSID-549" },
        @{ Name = 'Backup Operators'; SID = "$DomainSID-551" }
    )
    
    foreach ($groupInfo in $domainGroups) {
        try {
            $group = Get-ADGroup -Identity $groupInfo.SID -Server $Server -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $group -Server $Server -ErrorAction SilentlyContinue
                $results[$groupInfo.Name] = @{
                    Group = $group
                    Members = @($members | Where-Object { $_.objectClass -eq 'user' })
                }
            }
        }
        catch { }
    }
    
    # Forest-level groups (only for forest root domain)
    if ($IncludeEnterpriseGroups) {
        $forestGroups = @(
            @{ Name = 'Enterprise Admins'; SID = "$DomainSID-519" },
            @{ Name = 'Schema Admins'; SID = "$DomainSID-518" }
        )
        
        foreach ($groupInfo in $forestGroups) {
            try {
                $group = Get-ADGroup -Identity $groupInfo.SID -Server $Server -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -Server $Server -ErrorAction SilentlyContinue
                    $results[$groupInfo.Name] = @{
                        Group = $group
                        Members = @($members | Where-Object { $_.objectClass -eq 'user' })
                    }
                }
            }
            catch { }
        }
    }
    
    return $results
}

function Remove-UserFromPrivilegedGroup {
    param(
        [Parameter(Mandatory)]
        $Member,
        
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,
        
        [Parameter()]
        [string]$Server
    )
    
    if ($WhatIfPreference) {
        Write-Host "WhatIf: Would remove $($Member.SamAccountName) from $($Group.Name)" -ForegroundColor Cyan
        return $true
    }
    
    try {
        Remove-ADGroupMember -Identity $Group -Members $Member -Server $Server -Confirm:$false -ErrorAction Stop
        
        Write-TierGuardLog -Message "Removed $($Member.SamAccountName) from $($Group.Name)" `
            -Severity Warning -EventId $Script:EventIds.PrivGroupRemoved
        
        # Clear adminCount
        try {
            Set-ADUser -Identity $Member.DistinguishedName -Clear adminCount -Server $Server -ErrorAction SilentlyContinue
            Write-TierGuardLog -Message "Cleared adminCount on $($Member.SamAccountName)" `
                -Severity Information -EventId $Script:EventIds.AdminCountCleared
        }
        catch { }
        
        return $true
    }
    catch {
        Write-TierGuardLog -Message "Failed to remove $($Member.SamAccountName) from $($Group.Name): $_" `
            -Severity Error -EventId $Script:EventIds.ErrorOccurred
        return $false
    }
}

#endregion

#region Main Sync Function

function Sync-TierUsers {
    param(
        [Parameter(Mandatory)]
        [int]$TierLevel,
        
        [Parameter(Mandatory)]
        [hashtable]$Config,
        
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    $tierConfig = if ($TierLevel -eq 0) { $Config.Tier0 } else { $Config.Tier1 }
    
    Write-TierGuardLog -Message "Starting Tier $TierLevel user sync for domain $Domain" `
        -Severity Information -EventId $Script:EventIds.ScriptStarted
    
    # Get domain info
    $domainObj = Get-ADDomain -Server $Domain
    $domainDN = $domainObj.DistinguishedName
    $domainSID = $domainObj.DomainSID.Value
    $dc = $domainObj.PDCEmulator
    $isForestRoot = ($domainObj.Forest -eq $domainObj.DNSRoot)
    
    # Get authentication policy DN
    $policyDN = Get-AuthenticationPolicyDN -PolicyName $tierConfig.PolicyName
    if (-not $policyDN) {
        Write-TierGuardLog -Message "Cannot proceed without authentication policy" `
            -Severity Error -EventId $Script:EventIds.PolicyNotFound
        return @{ Policies = 0; Protected = 0; Removed = 0; Errors = 1 }
    }
    
    $stats = @{ Policies = 0; Protected = 0; Removed = 0; Errors = 0; Skipped = 0 }
    
    # Collect valid tier users
    $validTierUsers = @{}
    
    foreach ($ouPath in $tierConfig.AdminOUs) {
        $resolvedOU = Resolve-TierOU -OUPath $ouPath -DomainDN $domainDN
        if (-not $resolvedOU) { continue }
        
        $users = Get-TierUsers -SearchBase $resolvedOU -Server $dc
        foreach ($user in $users) {
            $validTierUsers[$user.DistinguishedName] = $user
        }
    }
    
    # Process each user
    foreach ($userDN in $validTierUsers.Keys) {
        $user = $validTierUsers[$userDN]
        
        # Skip service accounts
        if (Test-IsServiceAccount -UserDN $userDN -ServiceAccountOUs $tierConfig.ServiceAccountOUs -DomainDN $domainDN) {
            Write-TierGuardLog -Message "Skipping service account: $($user.SamAccountName)" `
                -Severity Information -EventId $Script:EventIds.UserSkipped
            $stats.Skipped++
            continue
        }
        
        # Apply authentication policy
        $success = Set-UserAuthPolicy -User $user -PolicyDN $policyDN -Server $dc
        if ($success -and -not $user.'msDS-AssignedAuthNPolicy') {
            $stats.Policies++
        }
        elseif (-not $success) {
            $stats.Errors++
        }
        
        # Add to Protected Users (Tier 0 only, unless configured for Tier 1)
        $addToProtected = switch ($Config.ProtectedUsers) {
            'Tier-0' { $TierLevel -eq 0 }
            'Tier-1' { $TierLevel -eq 1 }
            'All-Tiers' { $true }
            default { $false }
        }
        
        if ($addToProtected) {
            $success = Add-UserToProtectedUsers -User $user -DomainSID $domainSID -Server $dc
            if ($success) { $stats.Protected++ }
            else { $stats.Errors++ }
        }
    }
    
    # Privileged group cleanup (Tier 0 only)
    if ($TierLevel -eq 0 -and $Config.PrivilegedGroupCleanup) {
        $privGroups = Get-PrivilegedGroupMembers -DomainSID $domainSID -Server $dc `
            -IncludeEnterpriseGroups:$isForestRoot
        
        foreach ($groupName in $privGroups.Keys) {
            $groupInfo = $privGroups[$groupName]
            
            foreach ($member in $groupInfo.Members) {
                # Check if this member is a valid Tier 0 user
                if ($validTierUsers.ContainsKey($member.DistinguishedName)) {
                    continue
                }
                
                # Check if it's a service account
                if (Test-IsServiceAccount -UserDN $member.DistinguishedName `
                    -ServiceAccountOUs $tierConfig.ServiceAccountOUs -DomainDN $domainDN) {
                    continue
                }
                
                # Check if it's the built-in Administrator
                $memberUser = Get-ADUser -Identity $member.DistinguishedName -Properties SID -Server $dc -ErrorAction SilentlyContinue
                if ($memberUser -and (Test-IsBuiltInAdmin -User $memberUser -DomainSID $domainSID)) {
                    continue
                }
                
                # Remove from privileged group
                $success = Remove-UserFromPrivilegedGroup -Member $member -Group $groupInfo.Group -Server $dc
                if ($success) { $stats.Removed++ }
                else { $stats.Errors++ }
            }
        }
    }
    
    Write-TierGuardLog -Message "Tier $TierLevel user sync complete. Policies: $($stats.Policies), Protected: $($stats.Protected), Removed: $($stats.Removed), Errors: $($stats.Errors)" `
        -Severity Information -EventId $Script:EventIds.ScriptCompleted
    
    return $stats
}

#endregion

#region Main Entry Point

try {
    Initialize-EventLog
    
    $config = Get-TierGuardConfig -Path $ConfigFile
    
    Write-TierGuardLog -Message "TierGuard User Sync started" `
        -Severity Information -EventId $Script:EventIds.ConfigLoaded
    
    $effectiveScope = if ($Scope) { $Scope } else { $config.Scope }
    
    if ($effectiveScope -ne 'All-Tiers' -and $effectiveScope -ne $config.Scope -and $config.Scope -ne 'All-Tiers') {
        Write-TierGuardLog -Message "Scope '$effectiveScope' not enabled in configuration" `
            -Severity Warning -EventId $Script:EventIds.ErrorOccurred
        exit 0
    }
    
    $totalStats = @{ Policies = 0; Protected = 0; Removed = 0; Errors = 0 }
    
    foreach ($domain in $config.Domains) {
        try {
            if ($effectiveScope -eq 'Tier-0' -or $effectiveScope -eq 'All-Tiers') {
                $stats = Sync-TierUsers -TierLevel 0 -Config $config -Domain $domain
                $totalStats.Policies += $stats.Policies
                $totalStats.Protected += $stats.Protected
                $totalStats.Removed += $stats.Removed
                $totalStats.Errors += $stats.Errors
            }
            
            if ($effectiveScope -eq 'Tier-1' -or $effectiveScope -eq 'All-Tiers') {
                $stats = Sync-TierUsers -TierLevel 1 -Config $config -Domain $domain
                $totalStats.Policies += $stats.Policies
                $totalStats.Protected += $stats.Protected
                $totalStats.Removed += $stats.Removed
                $totalStats.Errors += $stats.Errors
            }
        }
        catch {
            Write-TierGuardLog -Message "Error processing domain $domain`: $_" `
                -Severity Error -EventId $Script:EventIds.ErrorOccurred
            $totalStats.Errors++
        }
    }
    
    Write-TierGuardLog -Message "TierGuard User Sync complete. Total - Policies: $($totalStats.Policies), Protected: $($totalStats.Protected), Removed: $($totalStats.Removed), Errors: $($totalStats.Errors)" `
        -Severity Information -EventId $Script:EventIds.ScriptCompleted
    
    if ($totalStats.Errors -gt 0) {
        exit 1
    }
}
catch {
    Write-TierGuardLog -Message "Fatal error: $_" -Severity Error -EventId $Script:EventIds.ErrorOccurred
    exit 1
}

exit 0
