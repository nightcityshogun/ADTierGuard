<#
.SYNOPSIS
    ADTierGuard - GMSA Context Switch (Pure ADSI)
    
.DESCRIPTION
    Changes User Sync scheduled tasks from SYSTEM to GMSA context.
    Uses native ScheduledTasks cmdlets and ADSI - no ActiveDirectory module required.
    
    This script is run by the "ADTierGuard - GMSA Context Switch" scheduled task
    to work around Group Policy Preferences limitation where GMSA cannot be
    directly specified as the task principal.
    
.PARAMETER GMSAName
    The sAMAccountName of the GMSA (without $)
    
.PARAMETER TaskNames
    Array of task names to update. Defaults to ADTierGuard user sync tasks.
    
.NOTES
    Version: 1.0.0
    Based on: Kili69/TierLevelIsolation "Change User Context" pattern
    Pure ADSI - No ActiveDirectory module required
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$GMSAName,
    
    [Parameter()]
    [string[]]$TaskNames = @(
        'ADTierGuard - Tier 0 User Sync',
        'ADTierGuard - Tier 1 User Sync'
    )
)

$ErrorActionPreference = 'Stop'
$script:LogFile = Join-Path $env:ProgramData "ADTierGuard\GMSAContext_$(Get-Date -Format 'yyyyMMdd').log"

#region Logging

# Ensure log directory exists
$logDir = Split-Path $script:LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message, 
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8
    
    switch ($Level) {
        'Error'   { Write-Host $entry -ForegroundColor Red }
        'Warning' { Write-Host $entry -ForegroundColor Yellow }
        'Success' { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry }
    }
}

#endregion

#region ADSI Functions

function Get-GMSAInfo {
    <#
    .SYNOPSIS
        Gets GMSA SID and DN using pure ADSI
    #>
    param([string]$SAMAccountName)
    
    # Normalize account name (add $ if not present)
    $gmsaAccount = if ($SAMAccountName.EndsWith('$')) { $SAMAccountName } else { "$SAMAccountName`$" }
    
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext.Value
        $configNC = $rootDSE.configurationNamingContext.Value
        
        # Search in Managed Service Accounts container first
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=$gmsaAccount))"
        $searcher.PropertiesToLoad.AddRange(@('objectSid', 'distinguishedName', 'msDS-GroupMSAMembership'))
        $searcher.SearchScope = 'Subtree'
        
        $result = $searcher.FindOne()
        
        if ($result) {
            $sidBytes = $result.Properties['objectSid'][0]
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $dn = $result.Properties['distinguishedName'][0]
            
            return @{
                SID = $sid
                DN = $dn
                SAMAccountName = $gmsaAccount
                Found = $true
            }
        }
        
        Write-Log "GMSA '$gmsaAccount' not found in domain" -Level Warning
        return @{ Found = $false }
    }
    catch {
        Write-Log "Error searching for GMSA: $_" -Level Error
        return @{ Found = $false; Error = $_.Exception.Message }
    }
}

function Get-DomainControllersSIDs {
    <#
    .SYNOPSIS
        Gets all Domain Controllers computer accounts using pure ADSI
    #>
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext.Value
        
        # Search for Domain Controllers (userAccountControl has SERVER_TRUST_ACCOUNT flag = 0x2000 = 8192)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $searcher.PropertiesToLoad.AddRange(@('objectSid', 'sAMAccountName', 'distinguishedName'))
        $searcher.SearchScope = 'Subtree'
        
        $results = $searcher.FindAll()
        $dcs = @()
        
        foreach ($result in $results) {
            $sidBytes = $result.Properties['objectSid'][0]
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $dcs += @{
                SID = $sid
                SAMAccountName = $result.Properties['sAMAccountName'][0]
                DN = $result.Properties['distinguishedName'][0]
            }
        }
        
        Write-Log "Found $($dcs.Count) Domain Controllers" -Level Info
        return $dcs
    }
    catch {
        Write-Log "Error enumerating Domain Controllers: $_" -Level Error
        return @()
    }
}

function Update-GMSAPrincipalsAllowed {
    <#
    .SYNOPSIS
        Updates GMSA PrincipalsAllowedToRetrieveManagedPassword to include all DCs
        Uses pure ADSI - no ActiveDirectory module
    #>
    param(
        [string]$GMSADN,
        [array]$DomainControllers
    )
    
    try {
        # Get current GMSA object
        $gmsa = [ADSI]"LDAP://$GMSADN"
        
        # Build security descriptor with all DCs
        # msDS-GroupMSAMembership is a security descriptor (NT Security Descriptor syntax)
        # We need to add all DC computer accounts to the DACL
        
        $dcSids = $DomainControllers | ForEach-Object { $_.SID }
        
        if ($dcSids.Count -eq 0) {
            Write-Log "No DCs found to add to GMSA principals" -Level Warning
            return $false
        }
        
        # Build SDDL string granting all DCs access
        # D:P = DACL Present
        # (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SID) = Full control for each SID
        # Simpler: (A;;GA;;;SID) = Generic All
        $dacl = "D:P"
        foreach ($sid in $dcSids) {
            $dacl += "(A;;GA;;;$sid)"
        }
        
        # Convert SDDL to binary security descriptor
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($dacl)
        $sdBytes = New-Object byte[] $sd.BinaryLength
        $sd.GetBinaryForm($sdBytes, 0)
        
        # Update the attribute
        $gmsa.Put('msDS-GroupMSAMembership', $sdBytes)
        $gmsa.SetInfo()
        
        Write-Log "Updated GMSA principals to include $($dcSids.Count) DCs" -Level Success
        return $true
    }
    catch {
        Write-Log "Error updating GMSA principals: $_" -Level Error
        return $false
    }
}

#endregion

#region Task Management

function Set-TaskToGMSA {
    <#
    .SYNOPSIS
        Changes a scheduled task to run as GMSA
    #>
    param(
        [string]$TaskName,
        [string]$GMSASID,
        [string]$GMSAAccount
    )
    
    try {
        # Check if task exists
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        
        if (-not $task) {
            Write-Log "Task '$TaskName' not found - may not be deployed yet" -Level Warning
            return @{ Success = $false; Reason = 'NotFound' }
        }
        
        # Check current principal
        $currentUser = $task.Principal.UserId
        
        # Already running as GMSA?
        if ($currentUser -like "*$($GMSAAccount.TrimEnd('$'))*" -or $currentUser -eq $GMSASID) {
            Write-Log "Task '$TaskName' already running as GMSA" -Level Info
            return @{ Success = $true; Reason = 'AlreadyConfigured' }
        }
        
        Write-Log "Changing '$TaskName' from '$currentUser' to GMSA '$GMSAAccount'" -Level Info
        
        # Create new principal for GMSA
        # LogonType Password is required for GMSA scheduled tasks
        $principal = New-ScheduledTaskPrincipal -UserId $GMSASID -LogonType Password -RunLevel Highest
        
        # Update the task
        Set-ScheduledTask -TaskName $TaskName -Principal $principal | Out-Null
        
        Write-Log "Successfully updated '$TaskName' to GMSA context" -Level Success
        return @{ Success = $true; Reason = 'Updated' }
    }
    catch {
        Write-Log "Failed to update '$TaskName': $_" -Level Error
        return @{ Success = $false; Reason = 'Error'; Error = $_.Exception.Message }
    }
}

#endregion

#region Main

Write-Log "========== GMSA Context Switch Starting ==========" -Level Info
Write-Log "GMSA Name: $GMSAName" -Level Info
Write-Log "Computer: $env:COMPUTERNAME" -Level Info
Write-Log "Tasks to update: $($TaskNames -join ', ')" -Level Info

# Step 1: Get GMSA information via ADSI
$gmsaInfo = Get-GMSAInfo -SAMAccountName $GMSAName

if (-not $gmsaInfo.Found) {
    Write-Log "Could not find GMSA '$GMSAName' - ensure GMSA exists and is accessible" -Level Error
    exit 1
}

Write-Log "GMSA SID: $($gmsaInfo.SID)" -Level Info
Write-Log "GMSA DN: $($gmsaInfo.DN)" -Level Info

# Step 2: Update GMSA to allow all DCs to retrieve password
Write-Log "Updating GMSA principals allowed to retrieve password..." -Level Info
$dcs = Get-DomainControllersSIDs

if ($dcs.Count -gt 0) {
    $updateResult = Update-GMSAPrincipalsAllowed -GMSADN $gmsaInfo.DN -DomainControllers $dcs
    if (-not $updateResult) {
        Write-Log "Warning: Could not update GMSA principals - tasks may fail on some DCs" -Level Warning
    }
} else {
    Write-Log "Warning: No DCs found - skipping GMSA principals update" -Level Warning
}

# Step 3: Update scheduled tasks to run as GMSA
$results = @{
    Updated = 0
    AlreadyConfigured = 0
    NotFound = 0
    Errors = 0
}

foreach ($taskName in $TaskNames) {
    $result = Set-TaskToGMSA -TaskName $taskName -GMSASID $gmsaInfo.SID -GMSAAccount $gmsaInfo.SAMAccountName
    
    switch ($result.Reason) {
        'Updated'           { $results.Updated++ }
        'AlreadyConfigured' { $results.AlreadyConfigured++ }
        'NotFound'          { $results.NotFound++ }
        default             { $results.Errors++ }
    }
}

# Summary
Write-Log "========== GMSA Context Switch Complete ==========" -Level Info
Write-Log "Results: Updated=$($results.Updated), Already=$($results.AlreadyConfigured), NotFound=$($results.NotFound), Errors=$($results.Errors)" -Level $(if ($results.Errors -gt 0) { 'Warning' } else { 'Success' })

# Exit with error code if there were failures
if ($results.Errors -gt 0) {
    exit 1
} else {
    exit 0
}

#endregion
