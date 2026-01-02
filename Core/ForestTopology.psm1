<#
.SYNOPSIS
    ADTierGuard - Forest Topology Module
    
.DESCRIPTION
    Provides forest topology awareness for tier isolation operations.
    Handles root/child/tree domain classification and forest-scoped
    privileged group management (Enterprise Admins, Schema Admins).
    
    Based on Get-ForestInfo by NightCityShogun.
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.0.0
    License: GPL-3.0
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest

#region Module State

# Cached forest topology
$Script:ForestTopology = @{
    Initialized       = $false
    ForestRootFQDN    = $null
    ForestRootSID     = $null
    Domains           = @()
    DomainControllers = @()
    LastRefresh       = $null
}

#endregion

#region Forest Discovery

<#
.SYNOPSIS
    Initializes forest topology information.
    
.DESCRIPTION
    Discovers all domains and domain controllers in the forest,
    classifying each as Forest Root, Child Domain, or Tree Root.
    Caches results for subsequent operations.
    
.PARAMETER Credential
    Optional credentials for cross-domain queries.
    
.PARAMETER Force
    Forces refresh even if cache is populated.
    
.EXAMPLE
    Initialize-ForestTopology
    
.EXAMPLE
    Initialize-ForestTopology -Force
#>
function Initialize-ForestTopology {
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter()]
        [switch]$Force
    )
    
    if ($Script:ForestTopology.Initialized -and -not $Force) {
        return $Script:ForestTopology
    }
    
    # Get forest info using the integrated function
    $dcInfo = Get-ForestInfo -Credential $Credential -WinStyleHidden
    
    if (-not $dcInfo -or $dcInfo.Count -eq 0) {
        throw "Failed to discover forest topology. Ensure domain connectivity."
    }
    
    # Extract forest root from first DC (all have same ForestRootFQDN)
    $forestRootFQDN = $dcInfo[0].ForestRootFQDN
    
    # Find forest root domain SID
    $forestRootDC = $dcInfo | Where-Object { $_.Type -eq 'Forest Root' } | Select-Object -First 1
    $forestRootSID = if ($forestRootDC) { $forestRootDC.DomainSid } else { $null }
    
    # Build unique domain list with topology info
    $domains = $dcInfo | Group-Object -Property Domain | ForEach-Object {
        $firstDC = $_.Group[0]
        @{
            DnsName           = $firstDC.Domain
            DomainSid         = $firstDC.DomainSid
            Type              = $firstDC.Type
            DefaultNC         = $firstDC.DefaultNamingContext
            IsForestRoot      = ($firstDC.Type -eq 'Forest Root')
            IsTreeRoot        = ($firstDC.Type -eq 'Tree Root')
            IsChildDomain     = ($firstDC.Type -eq 'Child Domain')
            DomainControllers = @($_.Group | ForEach-Object { $_.FQDN })
            OnlineDCs         = @($_.Group | Where-Object { $_.Online } | ForEach-Object { $_.FQDN })
        }
    }
    
    # Update cache
    $Script:ForestTopology.Initialized = $true
    $Script:ForestTopology.ForestRootFQDN = $forestRootFQDN
    $Script:ForestTopology.ForestRootSID = $forestRootSID
    $Script:ForestTopology.Domains = @($domains)
    $Script:ForestTopology.DomainControllers = @($dcInfo)
    $Script:ForestTopology.LastRefresh = [DateTime]::UtcNow
    
    return $Script:ForestTopology
}

<#
.SYNOPSIS
    Gets the cached forest topology.
    
.DESCRIPTION
    Returns the cached forest topology. Initializes if not already done.
    
.EXAMPLE
    $topology = Get-ForestTopology
#>
function Get-ForestTopology {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    if (-not $Script:ForestTopology.Initialized) {
        Initialize-ForestTopology
    }
    
    return $Script:ForestTopology
}

<#
.SYNOPSIS
    Gets the forest root domain information.
    
.EXAMPLE
    $forestRoot = Get-ForestRootDomain
    $forestRoot.DnsName      # "contoso.com"
    $forestRoot.DomainSid    # "S-1-5-21-..."
#>
function Get-ForestRootDomain {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    $topology = Get-ForestTopology
    return $topology.Domains | Where-Object { $_.IsForestRoot } | Select-Object -First 1
}

<#
.SYNOPSIS
    Gets all child domains in the forest.
    
.EXAMPLE
    $children = Get-ChildDomains
#>
function Get-ChildDomains {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()
    
    $topology = Get-ForestTopology
    return @($topology.Domains | Where-Object { $_.IsChildDomain })
}

<#
.SYNOPSIS
    Gets all tree root domains (separate trees in the forest).
    
.EXAMPLE
    $trees = Get-TreeRootDomains
#>
function Get-TreeRootDomains {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()
    
    $topology = Get-ForestTopology
    return @($topology.Domains | Where-Object { $_.IsTreeRoot })
}

<#
.SYNOPSIS
    Gets domain information by DNS name.
    
.PARAMETER DomainDnsName
    The DNS name of the domain.
    
.EXAMPLE
    $domain = Get-DomainByName -DomainDnsName "child.contoso.com"
#>
function Get-DomainByName {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDnsName
    )
    
    $topology = Get-ForestTopology
    return $topology.Domains | Where-Object { 
        $_.DnsName -eq $DomainDnsName 
    } | Select-Object -First 1
}

<#
.SYNOPSIS
    Tests if a domain is the forest root.
    
.PARAMETER DomainDnsName
    The DNS name of the domain to check.
    
.EXAMPLE
    if (Test-IsForestRoot -DomainDnsName "contoso.com") { ... }
#>
function Test-IsForestRoot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDnsName
    )
    
    $topology = Get-ForestTopology
    return $topology.ForestRootFQDN -eq $DomainDnsName
}

#endregion

#region Forest-Scoped Privileged Groups

<#
.SYNOPSIS
    Gets forest-scoped privileged groups (Enterprise Admins, Schema Admins).
    
.DESCRIPTION
    These groups only exist in the forest root domain but have
    forest-wide privileges. Returns the groups with their SIDs.
    
.EXAMPLE
    $groups = Get-ForestPrivilegedGroups
#>
function Get-ForestPrivilegedGroups {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()
    
    $forestRoot = Get-ForestRootDomain
    
    if (-not $forestRoot -or -not $forestRoot.DomainSid) {
        Write-Warning "Cannot determine forest root domain SID"
        return @()
    }
    
    $forestSid = $forestRoot.DomainSid
    
    return @(
        @{
            Name           = 'Enterprise Admins'
            RID            = 519
            SID            = "$forestSid-519"
            Domain         = $forestRoot.DnsName
            DomainDN       = $forestRoot.DefaultNC
            Description    = 'Forest-wide administrative access'
        }
        @{
            Name           = 'Schema Admins'
            RID            = 518
            SID            = "$forestSid-518"
            Domain         = $forestRoot.DnsName
            DomainDN       = $forestRoot.DefaultNC
            Description    = 'Can modify Active Directory schema'
        }
    )
}

<#
.SYNOPSIS
    Gets domain-scoped privileged groups for a specific domain.
    
.DESCRIPTION
    Returns privileged groups that exist in every domain
    (Domain Admins, Account Operators, etc.)
    
.PARAMETER DomainDnsName
    The DNS name of the domain.
    
.EXAMPLE
    $groups = Get-DomainPrivilegedGroups -DomainDnsName "child.contoso.com"
#>
function Get-DomainPrivilegedGroups {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDnsName
    )
    
    $domain = Get-DomainByName -DomainDnsName $DomainDnsName
    
    if (-not $domain -or -not $domain.DomainSid) {
        Write-Warning "Cannot determine domain SID for $DomainDnsName"
        return @()
    }
    
    $domainSid = $domain.DomainSid
    
    # Domain-specific groups (exist in every domain)
    $domainGroups = @(
        @{ Name = 'Domain Admins';              RID = 512 }
        @{ Name = 'Domain Controllers';         RID = 516 }
        @{ Name = 'Group Policy Creator Owners'; RID = 520 }
        @{ Name = 'Cloneable Domain Controllers'; RID = 522 }
    )
    
    # Builtin groups (well-known SIDs, same in every domain)
    $builtinGroups = @(
        @{ Name = 'Administrators';     SID = 'S-1-5-32-544' }
        @{ Name = 'Account Operators';  SID = 'S-1-5-32-548' }
        @{ Name = 'Server Operators';   SID = 'S-1-5-32-549' }
        @{ Name = 'Print Operators';    SID = 'S-1-5-32-550' }
        @{ Name = 'Backup Operators';   SID = 'S-1-5-32-551' }
        @{ Name = 'Replicators';        SID = 'S-1-5-32-552' }
    )
    
    $result = @()
    
    foreach ($group in $domainGroups) {
        $result += @{
            Name      = $group.Name
            RID       = $group.RID
            SID       = "$domainSid-$($group.RID)"
            Domain    = $DomainDnsName
            DomainDN  = $domain.DefaultNC
            IsBuiltin = $false
        }
    }
    
    foreach ($group in $builtinGroups) {
        $result += @{
            Name      = $group.Name
            SID       = $group.SID
            Domain    = $DomainDnsName
            DomainDN  = $domain.DefaultNC
            IsBuiltin = $true
        }
    }
    
    return $result
}

<#
.SYNOPSIS
    Gets all privileged groups for a domain, including forest-scoped if applicable.
    
.DESCRIPTION
    For forest root domain: Returns both domain and forest privileged groups.
    For child/tree domains: Returns only domain privileged groups.
    
.PARAMETER DomainDnsName
    The DNS name of the domain.
    
.EXAMPLE
    # For forest root - includes Enterprise/Schema Admins
    $groups = Get-AllPrivilegedGroupsForDomain -DomainDnsName "contoso.com"
    
.EXAMPLE
    # For child domain - only domain groups
    $groups = Get-AllPrivilegedGroupsForDomain -DomainDnsName "child.contoso.com"
#>
function Get-AllPrivilegedGroupsForDomain {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDnsName
    )
    
    $groups = @()
    
    # Always get domain-scoped groups
    $groups += Get-DomainPrivilegedGroups -DomainDnsName $DomainDnsName
    
    # Add forest-scoped groups only for forest root
    if (Test-IsForestRoot -DomainDnsName $DomainDnsName) {
        $groups += Get-ForestPrivilegedGroups
    }
    
    return $groups
}

#endregion

#region Online DC Selection

<#
.SYNOPSIS
    Gets an online domain controller for a domain.
    
.DESCRIPTION
    Returns the FQDN of an online DC, preferring GCs and PDC.
    
.PARAMETER DomainDnsName
    The DNS name of the domain.
    
.EXAMPLE
    $dc = Get-OnlineDomainController -DomainDnsName "contoso.com"
#>
function Get-OnlineDomainController {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDnsName
    )
    
    $topology = Get-ForestTopology
    
    # Get DCs for this domain
    $dcs = $topology.DomainControllers | Where-Object { 
        $_.Domain -eq $DomainDnsName -and $_.Online 
    }
    
    if (-not $dcs) {
        Write-Warning "No online DCs found for $DomainDnsName"
        return $null
    }
    
    # Prefer PDC, then GC, then any online
    $pdc = $dcs | Where-Object { $_.IsPdcRoleOwner } | Select-Object -First 1
    if ($pdc) { return $pdc.FQDN }
    
    $gc = $dcs | Where-Object { $_.IsGC } | Select-Object -First 1
    if ($gc) { return $gc.FQDN }
    
    return ($dcs | Select-Object -First 1).FQDN
}

<#
.SYNOPSIS
    Gets a Global Catalog server for forest-wide queries.
    
.EXAMPLE
    $gc = Get-GlobalCatalogServer
#>
function Get-GlobalCatalogServer {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    $topology = Get-ForestTopology
    
    $gc = $topology.DomainControllers | Where-Object { 
        $_.Online -and $_.IsGC 
    } | Select-Object -First 1
    
    if ($gc) {
        return $gc.FQDN
    }
    
    Write-Warning "No online Global Catalog servers found"
    return $null
}

#endregion

#region Integrated Get-ForestInfo

# Check if Write-IdentIRLog exists, if not create a stub for standalone use
if (-not (Get-Command -Name 'Write-IdentIRLog' -ErrorAction SilentlyContinue)) {
    function script:Write-IdentIRLog {
        param(
            [string]$Message,
            [string]$TypeName = 'Info',
            [System.ConsoleColor]$ForegroundColor = 'White'
        )
        
        switch ($TypeName) {
            'Error'   { Write-Error $Message }
            'Warning' { Write-Warning $Message }
            default   { Write-Verbose $Message }
        }
    }
}

# Dot-source Get-ForestInfo.ps1 from the same directory
$getForestInfoPath = Join-Path $PSScriptRoot 'Get-ForestInfo.ps1'
if (Test-Path $getForestInfoPath) {
    . $getForestInfoPath
}
else {
    throw "Get-ForestInfo.ps1 not found at: $getForestInfoPath"
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
    # Initialization
    'Initialize-ForestTopology'
    'Get-ForestTopology'
    
    # Domain Classification
    'Get-ForestRootDomain'
    'Get-ChildDomains'
    'Get-TreeRootDomains'
    'Get-DomainByName'
    'Test-IsForestRoot'
    
    # Privileged Groups
    'Get-ForestPrivilegedGroups'
    'Get-DomainPrivilegedGroups'
    'Get-AllPrivilegedGroupsForDomain'
    
    # DC Selection
    'Get-OnlineDomainController'
    'Get-GlobalCatalogServer'
    
    # Core Discovery
    'Get-ForestInfo'
)

#endregion
