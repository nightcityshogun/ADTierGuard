<img width="1024" height="1024" alt="adtierguard" src="https://github.com/user-attachments/assets/46bf3990-7cdc-4ec1-9f6b-ba2b1d11f519" />

**Enterprise Active Directory Tier Isolation using Kerberos Authentication Policies**

A 100% pure ADSI implementation for Active Directory Tier 0/1 isolation. Zero dependency on the ActiveDirectory or GroupPolicy PowerShell modules.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%20R2%2B-blue.svg)](https://www.microsoft.com/en-us/windows-server)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

ADTierGuard implements Microsoft's Administrative Tier Model using Kerberos Authentication Policies. This restricts where privileged credentials can be used, preventing credential theft escalation attacks like Pass-the-Hash and Pass-the-Ticket.

### Key Features

- **100% Pure ADSI** - No ActiveDirectory or GroupPolicy PowerShell modules required
- **Forest-Wide Deployment** - Single command deploys to all domains in the forest
- **Kerberos Authentication Policies** - Restrict admin authentication to tier-specific computers
- **Kerberos Armoring (FAST)** - Automatic GPO configuration for all domains
- **Protected Users Group** - Automatic membership management for Tier 0 admins
- **Privileged Group Cleanup** - Remove unauthorized users from DA/EA/etc.
- **GMSA Support** - Secure Group Managed Service Account for scheduled tasks
- **GPO-Based Scheduled Tasks** - Distributed sync on all Domain Controllers
- **P/Invoke SDDL Conversion** - Win32 API for conditional ACE handling

### The Tier Model

| Tier | Description | Examples |
|------|-------------|----------|
| **Tier 0** | Forest/Domain administration | Domain Controllers, AD admins, PKI, ADFS |
| **Tier 1** | Server administration | Member servers, application servers |
| **Tier 2** | Workstation administration | Workstations, helpdesk |

## Quick Start

### One-Command Installation

Run from the **Forest Root Domain Controller** as **Enterprise Admin**:

```powershell
.\Install-ADTierGuard.ps1 -Scope All
```

This single command will:
1. Create `OU=ADTierGuard` structure in all domains
2. Deploy sync scripts to SYSVOL in all domains
3. Create GMSA `ADTierGuard-svc` for scheduled tasks
4. Create `Tier0-Computers` and `Tier1-Computers` universal groups
5. Create `Tier0-RestrictedAuth` and `Tier1-RestrictedAuth` authentication policies
6. Create `Tier0-Silo` and `Tier1-Silo` authentication silos
7. Deploy GPO with scheduled tasks to all domains
8. Enable Kerberos Armoring in Default Domain Controllers Policy and Default Domain Policy

### Post-Installation Steps

```powershell
# 1. Apply GPO on all Domain Controllers
gpupdate /force

# 2. Verify Kerberos Armoring is active
klist purge
# Request new ticket and check:
klist
# Look for: Cache Flags: 0x41 -> PRIMARY FAST

# 3. Move Tier 0 computers to the correct OU
# OU=Computers,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com

# 4. Move Tier 0 admin users to the correct OU  
# OU=Users,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com

# 5. Wait for computer sync (runs every 10 minutes)
# Or run manually: Invoke-TierComputerSync.ps1 -TierLevel 0

# 6. Reboot Tier 0 computers to pick up new group membership

# 7. Test authentication with a pilot admin account

# 8. Enable User Sync scheduled tasks in GPO after testing
```

## Architecture

### What Gets Created

```
Active Directory Forest
├── Configuration NC (Forest-Wide)
│   └── CN=AuthN Policy Configuration
│       ├── CN=AuthN Policies
│       │   ├── Tier0-RestrictedAuth     ← Kerberos Auth Policy
│       │   └── Tier1-RestrictedAuth
│       └── CN=AuthN Silos
│           ├── Tier0-Silo               ← Authentication Silo
│           └── Tier1-Silo
│
├── Forest Root Domain
│   ├── CN=Managed Service Accounts
│   │   └── ADTierGuard-svc$             ← GMSA
│   ├── CN=Users
│   │   ├── Tier0-Computers              ← Universal Security Group
│   │   └── Tier1-Computers
│   └── OU=ADTierGuard                   ← Admin OU Structure
│       ├── OU=Tier 0
│       │   ├── OU=Users
│       │   ├── OU=Service Accounts
│       │   ├── OU=Computers
│       │   └── OU=Groups
│       └── OU=Tier 1
│           └── ...
│
├── Each Domain
│   ├── OU=ADTierGuard                   ← Same structure
│   ├── OU=Domain Controllers
│   │   └── GPO Link: ADTierGuard Tier Isolation
│   ├── Default Domain Controllers Policy
│   │   └── Kerberos Armoring (KDC)      ← Registry.pol settings
│   └── Default Domain Policy
│       └── Kerberos Armoring (Client)
│
└── SYSVOL (Each Domain)
    └── \\domain\SYSVOL\domain\scripts\
        ├── Invoke-TierComputerSync.ps1
        ├── Invoke-TierUserSync.ps1
        ├── Set-GMSAContext.ps1
        ├── ADTierGuard.config.json
        └── Core\*.psm1
```

### Scheduled Tasks (GPO-Deployed)

| Task | Context | Trigger | Status |
|------|---------|---------|--------|
| Tier 0 Computer Sync | SYSTEM | Every 10 min | **Enabled** |
| Tier 1 Computer Sync | SYSTEM | Every 10 min | **Enabled** |
| Tier 0 User Sync | GMSA | Every 10 min | Disabled (enable after testing) |
| Tier 1 User Sync | GMSA | Every 10 min | Disabled (enable after testing) |
| GMSA Context Switch | SYSTEM | Hourly + GPO refresh | **Enabled** |

### How Authentication Policies Work

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TIER 0 AUTHENTICATION FLOW                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Admin User                    KDC (Domain Controller)               │
│  ───────────                   ────────────────────────              │
│       │                              │                               │
│       │  1. Request TGT              │                               │
│       │ ─────────────────────────────►                               │
│       │                              │                               │
│       │                     2. Check msDS-AssignedAuthNPolicy        │
│       │                        User has: Tier0-RestrictedAuth        │
│       │                              │                               │
│       │                     3. Evaluate Policy SDDL:                 │
│       │                        (Member_of {SID(ED)}) ||              │
│       │                        (Member_of_any {SID(Tier0-Computers)})│
│       │                              │                               │
│       │                     4. Check requesting computer:            │
│       │                        - Is it a Domain Controller? (ED)     │
│       │                        - Is it in Tier0-Computers group?     │
│       │                              │                               │
│       │  5a. ✓ ALLOWED ◄─────────────┤ (Computer in Tier 0)          │
│       │      Return TGT              │                               │
│       │                              │                               │
│       │  5b. ✗ DENIED ◄──────────────┤ (Computer NOT in Tier 0)      │
│       │      KDC_ERR_POLICY          │                               │
│       │                              │                               │
└─────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
ADTierGuard/
├── Install-ADTierGuard.ps1       # Main installer (pure ADSI)
├── Test-ADTierGuard.ps1          # Pre-installation validation
├── ADTierGuard.psd1              # Module manifest
├── ADTierGuard.psm1              # Module loader
│
├── Scripts/                      # Deployed to SYSVOL
│   ├── Invoke-TierComputerSync.ps1   # Computer group sync
│   ├── Invoke-TierUserSync.ps1       # User policy/protection sync
│   ├── Set-GMSAContext.ps1           # GMSA context switcher
│   └── Initialize-TierGuardAuth.ps1  # Auth policy initialization
│
├── Core/                         # Core modules
│   ├── AdsiOperations.psm1       # Pure ADSI operations
│   ├── AuthPolicyManager.psm1    # Auth policy management
│   ├── ForestTopology.psm1       # Forest discovery
│   ├── ForestDeployment.psm1     # Deployment functions
│   ├── SyncUtilities.psm1        # Logging & utilities
│   └── ConfigurationManager.psm1 # Config handling
│
├── Engine/
│   └── RunspaceEngine.psm1       # Parallel processing
│
├── GPO/
│   └── ScheduledTasks.xml        # GPO scheduled tasks template
│
├── Config/
│   └── Sample-TierGuard.json     # Sample configuration
│
└── Docs/
    ├── Deployment-Guide.md
    ├── AuthPolicy-Configuration.md
    └── UML-Mermaid.md
```

## User Sync Operations

When the User Sync scheduled task runs, it performs these operations on each admin user:

| Operation | Attribute/Group | Description |
|-----------|-----------------|-------------|
| Apply Auth Policy | `msDS-AssignedAuthNPolicy` | Sets to Tier0-RestrictedAuth or Tier1-RestrictedAuth |
| Protected Users | `CN=Protected Users` | Adds Tier 0 users to Protected Users group |
| Privileged Cleanup | DA, EA, SA, etc. | Removes users not in Tier 0 OU from privileged groups |

## Requirements

- Windows Server 2012 R2 Domain Functional Level (minimum)
- PowerShell 5.1 or higher
- Enterprise Admin privileges (for installation)
- All Domain Controllers must support Kerberos Armoring

## Event Log Monitoring

Events are logged to the Application log with source "ADTierGuard":

| Event ID | Category | Description |
|----------|----------|-------------|
| 1000 | Computer | Computer sync started |
| 1001 | Computer | Computer sync completed |
| 1100 | Computer | Computer added to group |
| 1101 | Computer | Computer removed from group |
| 2000 | User | User sync started |
| 2001 | User | User sync completed |
| 2100 | User | Auth policy applied to user |
| 2101 | User | User added to Protected Users |
| 2102 | User | User removed from privileged group |

## Troubleshooting

### Verify Kerberos Armoring

```powershell
# On a DC, check KDC events
Get-WinEvent -LogName "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" -MaxEvents 10

# Look for Event ID 309 - Kerberos armoring is working
```

### Check Authentication Policy

```powershell
# Get user's assigned policy
Get-ADUser -Identity "AdminUser" -Properties msDS-AssignedAuthNPolicy | 
    Select-Object Name, "msDS-AssignedAuthNPolicy"

# Get policy details
Get-ADAuthenticationPolicy -Identity "Tier0-RestrictedAuth" | Format-List *
```

### Test Policy Enforcement

```powershell
# From a Tier 0 computer - should succeed
runas /user:DOMAIN\Tier0Admin cmd.exe

# From a non-Tier 0 computer - should fail with:
# "The system cannot log you on due to the following error: 
#  The user's account has restrictions which prevent this user from signing in."
```

## Credits

- Based on Microsoft's [Enterprise Access Model](https://docs.microsoft.com/en-us/security/compass/privileged-access-strategy)
- [Kerberos Authentication Policies](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos) documentation

## License

MIT License - See LICENSE file for details.

---

**ADTierGuard** - Protecting your Active Directory, one tier at a time. 🛡️
