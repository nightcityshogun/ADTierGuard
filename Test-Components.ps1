# Test P/Invoke SDDL Converter
Write-Host "Testing SDDL Converter..." -ForegroundColor Cyan

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class SddlConverter
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        out uint SecurityDescriptorSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] ConvertSddlToBinary(string sddl)
    {
        IntPtr pSD = IntPtr.Zero;
        uint size = 0;
        
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out pSD, out size))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception("SDDL conversion failed with error: " + error);
            }
            
            byte[] sdBytes = new byte[size];
            Marshal.Copy(pSD, sdBytes, 0, (int)size);
            return sdBytes;
        }
        finally
        {
            if (pSD != IntPtr.Zero)
                LocalFree(pSD);
        }
    }
}
'@

# Test simple SDDL first
$simpleSddl = "O:SYG:SYD:(A;;GA;;;BA)"
try {
    $bytes = [SddlConverter]::ConvertSddlToBinary($simpleSddl)
    Write-Host "Simple SDDL: SUCCESS - $($bytes.Length) bytes" -ForegroundColor Green
} catch {
    Write-Host "Simple SDDL: FAILED - $_" -ForegroundColor Red
}

# Test claim-based SDDL (the problematic one)
$claimSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID(S-1-5-21-86036939-1243097855-2017249254-6606)})))"
try {
    $bytes = [SddlConverter]::ConvertSddlToBinary($claimSddl)
    Write-Host "Claim SDDL: SUCCESS - $($bytes.Length) bytes" -ForegroundColor Green
    Write-Host "First 20 bytes: $([BitConverter]::ToString($bytes[0..19]))" -ForegroundColor Gray
} catch {
    Write-Host "Claim SDDL: FAILED - $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Testing Registry.pol Writer..." -ForegroundColor Cyan

# Check the format - Registry.pol is tricky
# Format: PReg header (8 bytes) + entries
# Each entry: [key\0;value\0;type;size;data]

$regPolPath = "$env:TEMP\test_registry.pol"

# Simple binary writer approach
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

# Header: PReg signature and version
$bw.Write([uint32]0x67655250)  # "PReg" in little-endian
$bw.Write([uint32]0x00000001)  # Version 1

# Write an entry
# Format: [key;valuename;type;size;data]
$key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
$valueName = "EnableCbacAndArmor"
$value = [uint32]1

# Entry format uses UTF-16LE with specific delimiters
$encoding = [System.Text.Encoding]::Unicode

# Opening bracket
$bw.Write([byte[]]@(0x5B, 0x00))  # '['

# Key (UTF-16LE, null terminated)
$bw.Write($encoding.GetBytes($key))
$bw.Write([byte[]]@(0x00, 0x00))  # null terminator

# Semicolon
$bw.Write([byte[]]@(0x3B, 0x00))  # ';'

# Value name
$bw.Write($encoding.GetBytes($valueName))
$bw.Write([byte[]]@(0x00, 0x00))

# Semicolon
$bw.Write([byte[]]@(0x3B, 0x00))

# Type (REG_DWORD = 4)
$bw.Write([uint32]4)

# Semicolon
$bw.Write([byte[]]@(0x3B, 0x00))

# Size
$bw.Write([uint32]4)

# Semicolon
$bw.Write([byte[]]@(0x3B, 0x00))

# Data
$bw.Write([uint32]$value)

# Closing bracket
$bw.Write([byte[]]@(0x5D, 0x00))  # ']'

$bw.Flush()
$bytes = $ms.ToArray()
$bw.Close()
$ms.Close()

[System.IO.File]::WriteAllBytes($regPolPath, $bytes)
Write-Host "Registry.pol written to: $regPolPath" -ForegroundColor Green
Write-Host "Size: $($bytes.Length) bytes" -ForegroundColor Gray
Write-Host "Header: $([BitConverter]::ToString($bytes[0..7]))" -ForegroundColor Gray

Write-Host ""
Write-Host "Done. Check if the files look correct." -ForegroundColor Cyan
