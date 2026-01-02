# ADTierGuard GPO Template

This folder contains the Group Policy scheduled tasks template for ADTierGuard.

## Files

- `ScheduledTasks.xml` - GPO Preferences scheduled task definitions

## Automatic Deployment

The `Install-ADTierGuard.ps1` script automatically:
1. Reads this template
2. Replaces `#ScriptPath` with the SYSVOL scripts path
3. Replaces `#GMSAName` with the configured GMSA name
4. Creates the GPO and imports the scheduled tasks
5. Links the GPO to the Domain Controllers OU

## Manual Deployment

If you prefer manual deployment:

1. Create a new GPO named "ADTierGuard Tier Isolation"
2. Edit the GPO
3. Navigate to: Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks
4. Import or manually create the tasks from `ScheduledTasks.xml`
5. Replace `#ScriptPath` with your SYSVOL path (e.g., `\\contoso.com\SYSVOL\contoso.com\scripts`)
6. Replace `#GMSAName` with your GMSA name
7. Link the GPO to the Domain Controllers OU

## Scheduled Tasks

| Task Name | Runs As | Frequency | Default State |
|-----------|---------|-----------|---------------|
| Tier 0 Computer Sync | SYSTEM | Every 10 min | Enabled |
| Tier 1 Computer Sync | SYSTEM | Every 10 min | Enabled |
| Tier 0 User Sync | GMSA | Every 10 min | **Disabled** |
| Tier 1 User Sync | GMSA | Every 10 min | **Disabled** |
| GMSA Context Switch | SYSTEM | Hourly + GPO refresh | Enabled |

**Important:** User Sync tasks are disabled by default for safety. Enable them only after:
1. Verifying Computer Sync has populated the computer groups
2. Rebooting Tier 0 servers to pick up new group membership
3. Testing Authentication Policy with a single user
4. Having a break-glass account ready
