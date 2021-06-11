using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;


namespace Oopsnamespace
{
	public class Oopsclass
	{
		public static void Main()
		{
		}
		public class Code
		{
			public static void Exec()
			{
				PowerShell ps = PowerShell.Create().AddCommand("cmd.exe").AddParameter("/c", "start").AddParameter("cmd.exe","");
				ps.Invoke();
			}
		}
	}
}
