using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;

namespace Oops
{
	class Oops
	{
		static void Main(string[] args)
		{
      //Move System.Management.Automation.dll into directory
			//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /reference:System.Management.Automation.dll /platform:x64 /t:exe /unsafe /out:\rastalabs\payloads\oops.exe C:\rastalabs\payloads\oops.cs
			PowerShell ps = PowerShell.Create().AddCommand ("cmd.exe").AddParameter("/c", "calc.exe");
			ps.Invoke();
		}
	}
}
