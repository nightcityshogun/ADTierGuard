# ADTierGuard Deployment Guide

## Table of Contents

1. [Pre-Deployment Requirements](#pre-deployment-requirements)
2. [Quick Installation](#quick-installation)
3. [Post-Installation Configuration](#post-installation-configuration)
4. [Phased Rollout](#phased-rollout)
5. [Monitoring and Validation](#monitoring-and-validation)
6. [Troubleshooting](#troubleshooting)
7. [Rollback Procedures](#rollback-procedures)

---

## Pre-Deployment Requirements

### Environment Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Domain Functional Level | Windows Server 2012 R2 | Windows Server 2016+ |
| Forest Functional Level | Windows Server 2012 R2 | Windows Server 2016+ |
| PowerShell | 5.1 | 5.1+ |
| Permissions | Enterprise Admin | Enterprise Admin |

### Pre-Flight Checklist

- [ ] Verify Domain Functional Level is 2012 R2 or higher
- [ ] Ensure Enterprise Admin credentials
- [ ] Test connectivity to all Domain Controllers
- [ ] Backup Active Directory (System State)
- [ ] Document current privileged accounts
- [ ] Identify Tier 0 and Tier 1 computers
- [ ] Plan for PAW (Privileged Access Workstation) deployment

### Verify Environment

```powershell
# Run pre-installation test
.\Test-ADTierGuard.ps1

# Manual checks
# Check forest functional level (needs 6+ = 2012 R2+)
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.forestFunctionality  # Should be >= 6

# Verify Enterprise Admin membership
whoami /groups | Select-String "Enterprise Admins"
```

---

## Quick Installation

### One-Command Deployment

Run from any **Domain Controller** in the **Forest Root Domain** as **Enterprise Admin**:

```powershell
.\Install-ADTierGuard.ps1 -Scope All
```

### What Gets Created

| Object | Location | Description |
|--------|----------|-------------|
| `OU=ADTierGuard` | Each domain root | Parent OU for tier structure |
| `OU=Tier 0` / `OU=Tier 1` | Under ADTierGuard | Tier containers |
| `OU=Users`, `Computers`, etc. | Under each tier | Organizational units |
| `Tier0-Computers` | Forest root CN=Users | Universal security group |
| `Tier1-Computers` | Forest root CN=Users | Universal security group |
| `ADTierGuard-svc$` | CN=Managed Service Accounts | Group Managed Service Account |
| `Tier0-RestrictedAuth` | CN=AuthN Policies,CN=Configuration | Kerberos auth policy |
| `Tier1-RestrictedAuth` | CN=AuthN Policies,CN=Configuration | Kerberos auth policy |
| `Tier0-Silo` / `Tier1-Silo` | CN=AuthN Silos,CN=Configuration | Authentication silos |
| `ADTierGuard Tier Isolation` | Each domain DC OU | GPO with scheduled tasks |

### Installation Options

```powershell
# Full installation (Tier 0 and Tier 1)
.\Install-ADTierGuard.ps1 -Scope All

# Tier 0 only
.\Install-ADTierGuard.ps1 -Scope Tier0

# Tier 1 only (requires Tier 0 already deployed)
.\Install-ADTierGuard.ps1 -Scope Tier1

# Skip GMSA creation (use existing)
.\Install-ADTierGuard.ps1 -Scope All -SkipGMSA

# Skip GPO deployment
.\Install-ADTierGuard.ps1 -Scope All -SkipGPO

# Skip Kerberos Armoring configuration
.\Install-ADTierGuard.ps1 -Scope All -SkipArmoring
```

---

## Post-Installation Configuration

### Step 1: Apply Group Policy

Run on **ALL Domain Controllers**:

```powershell
gpupdate /force
```

### Step 2: Verify Kerberos Armoring

```powershell
# Clear Kerberos cache
klist purge

# Authenticate to get new TGT
dir \\domain.com\SYSVOL

# Check for armoring
klist

# Look for: Cache Flags: 0x41 -> PRIMARY FAST
```

If `Cache Flags` shows `0x41`, Kerberos Armoring is working.

### Step 3: Verify Scheduled Tasks

On any Domain Controller:

```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -like "ADTierGuard*" }
```

Expected tasks:
- `ADTierGuard - Tier 0 Computer Sync` (Enabled)
- `ADTierGuard - Tier 1 Computer Sync` (Enabled)
- `ADTierGuard - Tier 0 User Sync` (Disabled)
- `ADTierGuard - Tier 1 User Sync` (Disabled)
- `ADTierGuard - GMSA Context Switch` (Enabled)

### Step 4: Populate Computer Groups

#### Option A: Wait for Automatic Sync
Computer sync runs every 10 minutes automatically.

#### Option B: Run Manually
```powershell
# From SYSVOL scripts location
\\domain.com\SYSVOL\domain.com\scripts\Invoke-TierComputerSync.ps1 -TierLevel 0
```

### Step 5: Move Computers to Tier OUs

Move Tier 0 computers (PAWs, Jump Servers, etc.):
```
OU=Computers,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com
```

Move Tier 1 computers (Member Servers):
```
OU=Computers,OU=Tier 1,OU=ADTierGuard,DC=domain,DC=com
```

### Step 6: Verify Group Membership

```powershell
# Check Tier 0 computers group
Get-ADGroupMember -Identity "Tier0-Computers" | Select-Object Name

# Check Tier 1 computers group  
Get-ADGroupMember -Identity "Tier1-Computers" | Select-Object Name
```

### Step 7: Reboot Tier Computers

Computers must reboot to receive their new group membership token.

---

## Phased Rollout

### Phase 1: Infrastructure (Week 1)

1. Run installation
2. Verify GPO deployment
3. Verify Kerberos Armoring
4. Move Domain Controllers to Tier 0 (automatic via DC OU)

### Phase 2: Computer Sync (Week 2)

1. Move PAWs to `OU=Computers,OU=Tier 0,OU=ADTierGuard`
2. Move Tier 1 servers to `OU=Computers,OU=Tier 1,OU=ADTierGuard`
3. Wait for computer sync (or run manually)
4. Reboot all tier computers
5. Verify group membership

### Phase 3: Pilot User Testing (Week 3)

1. Create test admin account in `OU=Users,OU=Tier 0,OU=ADTierGuard`
2. Manually apply policy:

```powershell
# Get policy DN
$policyDN = "CN=Tier0-RestrictedAuth,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=domain,DC=com"

# Apply to test user
$user = [ADSI]"LDAP://CN=TestAdmin,OU=Users,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com"
$user.Put('msDS-AssignedAuthNPolicy', $policyDN)
$user.SetInfo()
```

3. Test authentication:
   - From Tier 0 computer → **Should succeed**
   - From non-Tier 0 computer → **Should fail**

### Phase 4: Enable User Sync (Week 4)

1. Move production Tier 0 admins to `OU=Users,OU=Tier 0,OU=ADTierGuard`
2. Enable User Sync scheduled task in GPO:
   - Open `ADTierGuard Tier Isolation` GPO
   - Navigate to Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks
   - Enable `ADTierGuard - Tier 0 User Sync`
3. Run `gpupdate /force` on DCs
4. Monitor for issues

### Phase 5: Full Deployment (Week 5+)

1. Enable Tier 1 User Sync
2. Move remaining admins to appropriate tier OUs
3. Configure privileged group cleanup (optional)
4. Monitor and tune

---

## Monitoring and Validation

### Event Log Monitoring

```powershell
# View ADTierGuard events
Get-EventLog -LogName Application -Source "ADTierGuard" -Newest 50

# Filter by type
Get-EventLog -LogName Application -Source "ADTierGuard" -EntryType Error -Newest 10
```

### KDC Event Monitoring

On Domain Controllers, check for policy enforcement:

```powershell
# Event ID 106 = Authentication blocked by policy
Get-WinEvent -LogName "System" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and EventID=106]]" -MaxEvents 20
```

### Compliance Check

```powershell
# Check users with auth policy assigned
Get-ADUser -Filter * -Properties msDS-AssignedAuthNPolicy | 
    Where-Object { $_.'msDS-AssignedAuthNPolicy' } |
    Select-Object Name, 'msDS-AssignedAuthNPolicy'

# Check Protected Users membership
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name
```

### Log File Locations

| Component | Log Location |
|-----------|--------------|
| Installation | `%TEMP%\ADTierGuard_*.log` |
| Computer Sync | `%ProgramData%\ADTierGuard\ComputerSync_*.log` |
| User Sync | `%ProgramData%\ADTierGuard\UserSync_*.log` |
| GMSA Context | `%ProgramData%\ADTierGuard\GMSAContext_*.log` |

---

## Troubleshooting

### Issue: User Can't Authenticate from Tier 0 Computer

1. Verify computer is in Tier0-Computers group
2. Verify computer has been rebooted since group membership
3. Check user has correct auth policy:
   ```powershell
   Get-ADUser -Identity "username" -Properties msDS-AssignedAuthNPolicy
   ```

### Issue: Kerberos Armoring Not Working

1. Verify GPO is applied:
   ```powershell
   gpresult /r | Select-String "Default Domain"
   ```
2. Check registry settings:
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
   ```

### Issue: Scheduled Tasks Not Running

1. Check task exists:
   ```powershell
   Get-ScheduledTask | Where-Object { $_.TaskName -like "ADTierGuard*" }
   ```
2. Check task history in Task Scheduler
3. Verify scripts exist in SYSVOL:
   ```powershell
   dir \\domain.com\SYSVOL\domain.com\scripts\*.ps1
   ```

### Issue: GMSA Context Switch Failing

1. Verify GMSA exists:
   ```powershell
   Get-ADServiceAccount -Identity "ADTierGuard-svc"
   ```
2. Check GMSA can be used by DCs:
   ```powershell
   Test-ADServiceAccount -Identity "ADTierGuard-svc"
   ```

---

## Rollback Procedures

### Remove Policy from Single User

```powershell
$user = [ADSI]"LDAP://CN=AdminUser,OU=Users,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com"
$user.Put('msDS-AssignedAuthNPolicy', $null)
$user.SetInfo()
```

### Disable All User Sync

Disable scheduled tasks in GPO:
1. Edit `ADTierGuard Tier Isolation` GPO
2. Disable Tier 0/1 User Sync tasks
3. Run `gpupdate /force`

### Remove Authentication Policies

```powershell
# Warning: This breaks all users assigned to the policy
Get-ADAuthenticationPolicy -Filter {Name -like "Tier*"} | 
    Remove-ADAuthenticationPolicy -Confirm:$false
```

### Remove Protected Users Membership

```powershell
$protectedUsers = Get-ADGroup -Identity "Protected Users"
Get-ADGroupMember -Identity $protectedUsers | ForEach-Object {
    Remove-ADGroupMember -Identity $protectedUsers -Members $_ -Confirm:$false
}
```

### Full Rollback

```powershell
# 1. Remove users from Protected Users
# 2. Clear msDS-AssignedAuthNPolicy from all users
# 3. Delete authentication policies
# 4. Delete authentication silos
# 5. Delete GPO
# 6. Delete GMSA
# 7. Delete universal groups
# 8. Delete ADTierGuard OUs (if empty)
```

---

## Maintenance

### Regular Tasks

| Task | Frequency | Description |
|------|-----------|-------------|
| Review event logs | Daily | Check for errors or warnings |
| Verify computer groups | Weekly | Ensure computers are in correct groups |
| Compliance audit | Monthly | Generate report of protected users |
| Test authentication | Monthly | Verify policies work as expected |
| Backup configuration | Monthly | Export GPO and document settings |

### Updating Configuration

To add new computers to tiers:
1. Move computer object to appropriate Tier OU
2. Wait for sync (or run manually)
3. Reboot computer

To add new admins to tiers:
1. Move user object to appropriate Tier OU
2. Wait for sync (or run manually)
3. User will receive policy on next authentication

---

*Document Version: 2.0*
*Last Updated: January 2026*
