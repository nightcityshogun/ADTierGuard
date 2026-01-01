<#
.SYNOPSIS
    ADTierGuard - Core ADSI Operations Module
    
.DESCRIPTION
    Pure ADSI implementation for Active Directory operations.
    No dependency on ActiveDirectory PowerShell module.
    Provides high-performance directory operations using System.DirectoryServices.
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#region Module Configuration
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level cache for performance optimization
$Script:DirectoryCache = @{
    RootDSE          = $null
    DomainControllers = @{}
    SchemaAttributes  = @{}
    ForestDomains     = @()
    LastRefresh       = [DateTime]::MinValue
    CacheDuration     = [TimeSpan]::FromMinutes(15)
}
#endregion

#region ADSI Connection Management

<#
.SYNOPSIS
    Creates an ADSI DirectoryEntry connection with optional credentials.
#>
function New-AdsiConnection {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LdapPath,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [System.DirectoryServices.AuthenticationTypes]$AuthenticationType = 
            ([System.DirectoryServices.AuthenticationTypes]::Secure -bor 
             [System.DirectoryServices.AuthenticationTypes]::Sealing -bor
             [System.DirectoryServices.AuthenticationTypes]::Signing)
    )
    
    try {
        if ($Credential) {
            $networkCredential = $Credential.GetNetworkCredential()
            return [System.DirectoryServices.DirectoryEntry]::new(
                $LdapPath,
                $networkCredential.UserName,
                $networkCredential.Password,
                $AuthenticationType
            )
        }
        return [System.DirectoryServices.DirectoryEntry]::new($LdapPath, $null, $null, $AuthenticationType)
    }
    catch {
        Write-Error "Failed to establish ADSI connection to '$LdapPath': $_"
        throw
    }
}

<#
.SYNOPSIS
    Gets the RootDSE for the current or specified domain.
#>
function Get-AdsiRootDse {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [switch]$ForceRefresh
    )
    
    $cacheKey = if ($Server) { $Server } else { 'Default' }
    
    if (-not $ForceRefresh -and $Script:DirectoryCache.RootDSE -and 
        ([DateTime]::Now - $Script:DirectoryCache.LastRefresh) -lt $Script:DirectoryCache.CacheDuration) {
        return $Script:DirectoryCache.RootDSE
    }
    
    $ldapPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
    
    try {
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new($ldapPath)
        
        $result = @{
            DefaultNamingContext       = $rootDse.Properties['defaultNamingContext'].Value
            ConfigurationNamingContext = $rootDse.Properties['configurationNamingContext'].Value
            SchemaNamingContext        = $rootDse.Properties['schemaNamingContext'].Value
            RootDomainNamingContext    = $rootDse.Properties['rootDomainNamingContext'].Value
            DnsHostName               = $rootDse.Properties['dnsHostName'].Value
            ForestFunctionalLevel     = [int]$rootDse.Properties['forestFunctionality'].Value
            DomainFunctionalLevel     = [int]$rootDse.Properties['domainFunctionality'].Value
            DomainControllerFunctionality = [int]$rootDse.Properties['domainControllerFunctionality'].Value
        }
        
        $Script:DirectoryCache.RootDSE = $result
        $Script:DirectoryCache.LastRefresh = [DateTime]::Now
        
        return $result
    }
    catch {
        Write-Error "Failed to retrieve RootDSE: $_"
        throw
    }
    finally {
        if ($rootDse) { $rootDse.Dispose() }
    }
}

<#
.SYNOPSIS
    Gets all domains in the current forest using ADSI.
#>
function Get-AdsiForestDomains {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter()]
        [switch]$ForceRefresh
    )
    
    if (-not $ForceRefresh -and $Script:DirectoryCache.ForestDomains.Count -gt 0) {
        return $Script:DirectoryCache.ForestDomains
    }
    
    $rootDse = Get-AdsiRootDse
    $configNC = $rootDse.ConfigurationNamingContext
    $partitionsPath = "LDAP://CN=Partitions,$configNC"
    
    $domains = [System.Collections.Generic.List[hashtable]]::new()
    $searcher = $null
    $partitions = $null
    
    try {
        $partitions = New-AdsiConnection -LdapPath $partitionsPath
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($partitions)
        $searcher.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))"
        $searcher.PropertiesToLoad.AddRange(@('nCName', 'dnsRoot', 'nETBIOSName', 'trustParent'))
        $searcher.PageSize = 1000
        
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $domains.Add(@{
                DistinguishedName = $result.Properties['nCName'][0]
                DnsName           = $result.Properties['dnsRoot'][0]
                NetBIOSName       = $result.Properties['nETBIOSName'][0]
                IsForestRoot      = -not $result.Properties['trustParent'].Count
            })
        }
        
        $Script:DirectoryCache.ForestDomains = $domains
        return $domains
    }
    catch {
        Write-Error "Failed to enumerate forest domains: $_"
        throw
    }
    finally {
        if ($results) { $results.Dispose() }
        if ($searcher) { $searcher.Dispose() }
        if ($partitions) { $partitions.Dispose() }
    }
}
#endregion

#region LDAP Search Operations

<#
.SYNOPSIS
    Performs an optimized LDAP search using ADSI DirectorySearcher.
#>
function Search-AdsiDirectory {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LdapFilter,
        
        [Parameter()]
        [string[]]$Properties = @('distinguishedName', 'objectClass', 'name'),
        
        [Parameter()]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope = 'Subtree',
        
        [Parameter()]
        [int]$PageSize = 1000,
        
        [Parameter()]
        [int]$SizeLimit = 0,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [string]$Server
    )
    
    $results = [System.Collections.Generic.List[hashtable]]::new()
    $searchEntry = $null
    $searcher = $null
    $searchResults = $null
    
    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$SearchBase" } else { "LDAP://$SearchBase" }
        $searchEntry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
        
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($searchEntry)
        $searcher.Filter = $LdapFilter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$SearchScope
        $searcher.PageSize = $PageSize
        
        if ($SizeLimit -gt 0) {
            $searcher.SizeLimit = $SizeLimit
        }
        
        $searcher.PropertiesToLoad.Clear()
        foreach ($prop in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($prop.ToLower())
        }
        
        $searchResults = $searcher.FindAll()
        
        foreach ($result in $searchResults) {
            $entry = @{}
            foreach ($prop in $Properties) {
                $propLower = $prop.ToLower()
                if ($result.Properties.Contains($propLower)) {
                    $values = @($result.Properties[$propLower])
                    $entry[$prop] = if ($values.Count -eq 1) { $values[0] } else { $values }
                }
            }
            $entry['AdsPath'] = $result.Path
            $results.Add($entry)
        }
        
        return $results
    }
    catch {
        Write-Error "LDAP search failed on '$SearchBase' with filter '$LdapFilter': $_"
        throw
    }
    finally {
        if ($searchResults) { $searchResults.Dispose() }
        if ($searcher) { $searcher.Dispose() }
        if ($searchEntry) { $searchEntry.Dispose() }
    }
}

<#
.SYNOPSIS
    Gets a single directory object by distinguished name.
#>
function Get-AdsiObject {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName,
        
        [Parameter()]
        [string[]]$Properties,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $escapedDN = $DistinguishedName -replace '/', '\/'
    $ldapPath = if ($Server) { "LDAP://$Server/$escapedDN" } else { "LDAP://$escapedDN" }
    $entry = $null
    
    try {
        $entry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
        $entry.RefreshCache()
        
        $result = @{
            DistinguishedName = $entry.Properties['distinguishedName'].Value
            ObjectGuid        = [Guid]$entry.Properties['objectGuid'].Value
            ObjectClass       = @($entry.Properties['objectClass'])
            Name              = $entry.Properties['name'].Value
            AdsPath           = $entry.Path
        }
        
        if ($Properties) {
            foreach ($prop in $Properties) {
                if ($entry.Properties.Contains($prop)) {
                    $result[$prop] = $entry.Properties[$prop].Value
                }
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to retrieve object '$DistinguishedName': $_"
        throw
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
}
#endregion

#region Computer Operations

<#
.SYNOPSIS
    Gets computer objects from specified OUs using ADSI.
#>
function Get-AdsiComputer {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [string]$LdapFilter = '(objectClass=computer)',
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$IncludeDisabled
    )
    
    $filter = if ($IncludeDisabled) {
        "(&(objectClass=computer)(objectCategory=computer)$LdapFilter)"
    }
    else {
        "(&(objectClass=computer)(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))$LdapFilter)"
    }
    
    $properties = @(
        'distinguishedName', 'sAMAccountName', 'dNSHostName', 'name',
        'operatingSystem', 'operatingSystemVersion', 'userAccountControl',
        'whenCreated', 'whenChanged', 'objectSid', 'memberOf', 'servicePrincipalName'
    )
    
    return Search-AdsiDirectory -SearchBase $SearchBase -LdapFilter $filter `
        -Properties $properties -Server $Server -Credential $Credential
}

<#
.SYNOPSIS
    Tests if a computer is a domain controller.
#>
function Test-AdsiDomainController {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ComputerObject
    )
    
    $uac = [int]$ComputerObject.userAccountControl
    $serverTrustFlag = 0x2000  # SERVER_TRUST_ACCOUNT
    
    return ($uac -band $serverTrustFlag) -eq $serverTrustFlag
}
#endregion

#region User Operations

<#
.SYNOPSIS
    Gets user objects from specified OUs using ADSI.
#>
function Get-AdsiUser {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [string]$LdapFilter,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$IncludeDisabled
    )
    
    $baseFilter = if ($IncludeDisabled) {
        "(&(objectClass=user)(objectCategory=person))"
    }
    else {
        "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    }
    
    if ($LdapFilter) {
        $baseFilter = "(&$baseFilter$LdapFilter)"
    }
    
    $properties = @(
        'distinguishedName', 'sAMAccountName', 'userPrincipalName', 'displayName',
        'givenName', 'sn', 'mail', 'memberOf', 'userAccountControl', 'adminCount',
        'whenCreated', 'whenChanged', 'objectSid', 'msDS-AssignedAuthNPolicy',
        'msDS-AssignedAuthNPolicySilo', 'servicePrincipalName', 'objectClass'
    )
    
    return Search-AdsiDirectory -SearchBase $SearchBase -LdapFilter $baseFilter `
        -Properties $properties -Server $Server -Credential $Credential
}

<#
.SYNOPSIS
    Tests if a user object is a Group Managed Service Account (gMSA).
#>
function Test-AdsiGroupManagedServiceAccount {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$UserObject
    )
    
    $objectClasses = @($UserObject.objectClass)
    return $objectClasses -contains 'msDS-GroupManagedServiceAccount'
}

<#
.SYNOPSIS
    Tests if a user object is a Managed Service Account (MSA).
#>
function Test-AdsiManagedServiceAccount {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$UserObject
    )
    
    $objectClasses = @($UserObject.objectClass)
    return $objectClasses -contains 'msDS-ManagedServiceAccount' -or 
           $objectClasses -contains 'msDS-GroupManagedServiceAccount'
}
#endregion

#region Group Operations

<#
.SYNOPSIS
    Gets members of an AD group using ADSI with support for large groups.
#>
function Get-AdsiGroupMember {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[string]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupDistinguishedName,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$Recursive
    )
    
    $members = [System.Collections.Generic.List[string]]::new()
    $processed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $toProcess = [System.Collections.Generic.Queue[string]]::new()
    
    $toProcess.Enqueue($GroupDistinguishedName)
    
    while ($toProcess.Count -gt 0) {
        $currentGroup = $toProcess.Dequeue()
        
        if (-not $processed.Add($currentGroup)) {
            continue
        }
        
        $ldapPath = if ($Server) { "LDAP://$Server/$currentGroup" } else { "LDAP://$currentGroup" }
        $groupEntry = $null
        
        try {
            $groupEntry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
            
            # Handle range retrieval for large groups
            $rangeStart = 0
            $rangeStep = 1500
            $finished = $false
            
            while (-not $finished) {
                $rangeEnd = $rangeStart + $rangeStep - 1
                $rangeAttr = "member;range=$rangeStart-$rangeEnd"
                
                try {
                    $groupEntry.RefreshCache(@($rangeAttr))
                    $memberProp = $groupEntry.Properties.PropertyNames | Where-Object { $_ -like 'member;*' }
                    
                    if ($memberProp) {
                        foreach ($member in $groupEntry.Properties[$memberProp]) {
                            if ($Recursive) {
                                # Check if this is a group
                                try {
                                    $memberObj = Get-AdsiObject -DistinguishedName $member `
                                        -Properties @('objectClass') -Server $Server -Credential $Credential
                                    
                                    if ($memberObj.objectClass -contains 'group') {
                                        $toProcess.Enqueue($member)
                                    }
                                    else {
                                        [void]$members.Add($member)
                                    }
                                }
                                catch {
                                    [void]$members.Add($member)
                                }
                            }
                            else {
                                [void]$members.Add($member)
                            }
                        }
                        
                        if ($memberProp -like '*-*') {
                            $finished = $true
                        }
                        else {
                            $rangeStart = $rangeEnd + 1
                        }
                    }
                    else {
                        $finished = $true
                    }
                }
                catch {
                    # No more members in range
                    $finished = $true
                }
            }
        }
        catch {
            Write-Warning "Failed to enumerate members of group '$currentGroup': $_"
        }
        finally {
            if ($groupEntry) { $groupEntry.Dispose() }
        }
    }
    
    return $members
}

<#
.SYNOPSIS
    Adds a member to an AD group using ADSI.
#>
function Add-AdsiGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupDistinguishedName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberDistinguishedName,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $ldapPath = if ($Server) { "LDAP://$Server/$GroupDistinguishedName" } else { "LDAP://$GroupDistinguishedName" }
    $groupEntry = $null
    
    try {
        if ($PSCmdlet.ShouldProcess($GroupDistinguishedName, "Add member '$MemberDistinguishedName'")) {
            $groupEntry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
            $memberPath = if ($Server) { "LDAP://$Server/$MemberDistinguishedName" } else { "LDAP://$MemberDistinguishedName" }
            
            $groupEntry.Properties['member'].Add($MemberDistinguishedName)
            $groupEntry.CommitChanges()
            
            Write-Verbose "Added '$MemberDistinguishedName' to group '$GroupDistinguishedName'"
        }
    }
    catch [System.Runtime.InteropServices.COMException] {
        if ($_.Exception.ErrorCode -eq 0x80071392) {
            Write-Verbose "Member '$MemberDistinguishedName' already exists in group '$GroupDistinguishedName'"
        }
        else {
            throw
        }
    }
    finally {
        if ($groupEntry) { $groupEntry.Dispose() }
    }
}

<#
.SYNOPSIS
    Removes a member from an AD group using ADSI.
#>
function Remove-AdsiGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupDistinguishedName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MemberDistinguishedName,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $ldapPath = if ($Server) { "LDAP://$Server/$GroupDistinguishedName" } else { "LDAP://$GroupDistinguishedName" }
    $groupEntry = $null
    
    try {
        if ($PSCmdlet.ShouldProcess($GroupDistinguishedName, "Remove member '$MemberDistinguishedName'")) {
            $groupEntry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
            
            $groupEntry.Properties['member'].Remove($MemberDistinguishedName)
            $groupEntry.CommitChanges()
            
            Write-Verbose "Removed '$MemberDistinguishedName' from group '$GroupDistinguishedName'"
        }
    }
    catch {
        Write-Warning "Failed to remove member from group: $_"
        throw
    }
    finally {
        if ($groupEntry) { $groupEntry.Dispose() }
    }
}

<#
.SYNOPSIS
    Gets privileged groups from a domain.
#>
function Get-AdsiPrivilegedGroup {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter()]
        [string]$DomainDN,
        
        [Parameter()]
        [string]$Server
    )
    
    if (-not $DomainDN) {
        $rootDse = Get-AdsiRootDse -Server $Server
        $DomainDN = $rootDse.DefaultNamingContext
    }
    
    # Well-known SID RIDs for privileged groups
    $privilegedRids = @{
        512 = 'Domain Admins'
        516 = 'Domain Controllers'
        518 = 'Schema Admins'
        519 = 'Enterprise Admins'
        520 = 'Group Policy Creator Owners'
        521 = 'Read-only Domain Controllers'
        544 = 'Administrators'
        548 = 'Account Operators'
        549 = 'Server Operators'
        550 = 'Print Operators'
        551 = 'Backup Operators'
        552 = 'Replicators'
    }
    
    $groups = [System.Collections.Generic.List[hashtable]]::new()
    
    # Search for groups with adminCount = 1
    $filter = '(&(objectClass=group)(adminCount=1))'
    $properties = @('distinguishedName', 'sAMAccountName', 'objectSid', 'member', 'name', 'groupType')
    
    try {
        $results = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
            -Properties $properties -Server $Server
        
        foreach ($group in $results) {
            $groups.Add($group)
        }
    }
    catch {
        Write-Warning "Failed to enumerate privileged groups: $_"
    }
    
    return $groups
}
#endregion

#region Kerberos Authentication Policy Operations

<#
.SYNOPSIS
    Gets Kerberos Authentication Policies from the domain.
#>
function Get-AdsiKerberosAuthenticationPolicy {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter()]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $rootDse = Get-AdsiRootDse -Server $Server
    $configNC = $rootDse.ConfigurationNamingContext
    $policiesPath = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configNC"
    
    $filter = if ($Name) {
        "(&(objectClass=msDS-AuthNPolicy)(cn=$Name))"
    }
    else {
        '(objectClass=msDS-AuthNPolicy)'
    }
    
    $properties = @(
        'distinguishedName', 'cn', 'description', 'msDS-AuthNPolicyEnforced',
        'msDS-UserAllowedToAuthenticateFrom', 'msDS-UserAllowedToAuthenticateTo',
        'msDS-UserTGTLifetime', 'msDS-ComputerAllowedToAuthenticateTo',
        'msDS-ComputerTGTLifetime', 'msDS-ServiceAllowedToAuthenticateFrom',
        'msDS-ServiceAllowedToAuthenticateTo', 'msDS-ServiceTGTLifetime',
        'whenCreated', 'whenChanged'
    )
    
    return Search-AdsiDirectory -SearchBase $policiesPath -LdapFilter $filter `
        -Properties $properties -Server $Server
}

<#
.SYNOPSIS
    Applies a Kerberos Authentication Policy to a user or computer.
#>
function Set-AdsiAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetDistinguishedName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyDistinguishedName,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $ldapPath = if ($Server) { "LDAP://$Server/$TargetDistinguishedName" } else { "LDAP://$TargetDistinguishedName" }
    $entry = $null
    
    try {
        if ($PSCmdlet.ShouldProcess($TargetDistinguishedName, "Set Authentication Policy to '$PolicyDistinguishedName'")) {
            $entry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
            
            $entry.Properties['msDS-AssignedAuthNPolicy'].Clear()
            $entry.Properties['msDS-AssignedAuthNPolicy'].Add($PolicyDistinguishedName)
            $entry.CommitChanges()
            
            Write-Verbose "Applied authentication policy to '$TargetDistinguishedName'"
        }
    }
    catch {
        Write-Error "Failed to set authentication policy on '$TargetDistinguishedName': $_"
        throw
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
}

<#
.SYNOPSIS
    Removes a Kerberos Authentication Policy from a user or computer.
#>
function Remove-AdsiAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetDistinguishedName,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $ldapPath = if ($Server) { "LDAP://$Server/$TargetDistinguishedName" } else { "LDAP://$TargetDistinguishedName" }
    $entry = $null
    
    try {
        if ($PSCmdlet.ShouldProcess($TargetDistinguishedName, "Remove Authentication Policy")) {
            $entry = New-AdsiConnection -LdapPath $ldapPath -Credential $Credential
            
            $entry.Properties['msDS-AssignedAuthNPolicy'].Clear()
            $entry.CommitChanges()
            
            Write-Verbose "Removed authentication policy from '$TargetDistinguishedName'"
        }
    }
    catch {
        Write-Error "Failed to remove authentication policy from '$TargetDistinguishedName': $_"
        throw
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
}
#endregion

#region Protected Users Group Operations

<#
.SYNOPSIS
    Gets the Protected Users group from a domain.
#>
function Get-AdsiProtectedUsersGroup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$DomainDN,
        
        [Parameter()]
        [string]$Server
    )
    
    if (-not $DomainDN) {
        $rootDse = Get-AdsiRootDse -Server $Server
        $DomainDN = $rootDse.DefaultNamingContext
    }
    
    # Protected Users group has well-known SID ending in -525
    $filter = '(&(objectClass=group)(objectSid=*-525))'
    $properties = @('distinguishedName', 'sAMAccountName', 'objectSid', 'member')
    
    $results = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
        -Properties $properties -Server $Server
    
    if ($results.Count -gt 0) {
        return $results[0]
    }
    
    # Fallback to searching by name
    $filter = '(&(objectClass=group)(sAMAccountName=Protected Users))'
    $results = Search-AdsiDirectory -SearchBase $DomainDN -LdapFilter $filter `
        -Properties $properties -Server $Server
    
    if ($results.Count -gt 0) {
        return $results[0]
    }
    
    throw "Protected Users group not found in domain '$DomainDN'"
}

<#
.SYNOPSIS
    Adds a user to the Protected Users group.
#>
function Add-AdsiProtectedUser {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserDistinguishedName,
        
        [Parameter()]
        [string]$DomainDN,
        
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $protectedGroup = Get-AdsiProtectedUsersGroup -DomainDN $DomainDN -Server $Server
    
    Add-AdsiGroupMember -GroupDistinguishedName $protectedGroup.distinguishedName `
        -MemberDistinguishedName $UserDistinguishedName -Server $Server -Credential $Credential
}
#endregion

#region OU Path Utilities

<#
.SYNOPSIS
    Converts a relative OU path to a full distinguished name.
#>
function ConvertTo-AdsiDistinguishedName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RelativePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainDN
    )
    
    # If already a full DN, return as-is
    if ($RelativePath -match 'DC=') {
        return $RelativePath
    }
    
    # Append domain DN
    return "$RelativePath,$DomainDN"
}

<#
.SYNOPSIS
    Extracts the domain DN from a distinguished name.
#>
function Get-AdsiDomainFromDN {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DistinguishedName
    )
    
    $dcComponents = [regex]::Matches($DistinguishedName, 'DC=[^,]+')
    return ($dcComponents | ForEach-Object { $_.Value }) -join ','
}

<#
.SYNOPSIS
    Tests if a distinguished name is within a specified OU path.
#>
function Test-AdsiObjectInOU {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectDN,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$OUPaths
    )
    
    foreach ($ouPath in $OUPaths) {
        if ($ObjectDN -like "*,$ouPath" -or $ObjectDN -eq $ouPath) {
            return $true
        }
    }
    
    return $false
}
#endregion

#region Export Module Members
Export-ModuleMember -Function @(
    # Connection
    'New-AdsiConnection'
    'Get-AdsiRootDse'
    'Get-AdsiForestDomains'
    
    # Search
    'Search-AdsiDirectory'
    'Get-AdsiObject'
    
    # Computer
    'Get-AdsiComputer'
    'Test-AdsiDomainController'
    
    # User
    'Get-AdsiUser'
    'Test-AdsiGroupManagedServiceAccount'
    'Test-AdsiManagedServiceAccount'
    
    # Group
    'Get-AdsiGroupMember'
    'Add-AdsiGroupMember'
    'Remove-AdsiGroupMember'
    'Get-AdsiPrivilegedGroup'
    
    # Kerberos AuthN Policy
    'Get-AdsiKerberosAuthenticationPolicy'
    'Set-AdsiAuthenticationPolicy'
    'Remove-AdsiAuthenticationPolicy'
    
    # Protected Users
    'Get-AdsiProtectedUsersGroup'
    'Add-AdsiProtectedUser'
    
    # Utilities
    'ConvertTo-AdsiDistinguishedName'
    'Get-AdsiDomainFromDN'
    'Test-AdsiObjectInOU'
)
#endregion
