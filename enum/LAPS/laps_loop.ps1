#Author harmj0y
#https://www.harmj0y.net/blog/tag/laps/

Get-NetOU -FullData | 
    Get-ObjectAcl -ResolveGUIDs | 
    Where-Object {
        ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and 
        ($_.ActiveDirectoryRights -match 'ReadProperty')
    } | ForEach-Object {
        $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID;
        $_
    }
