function adsi-search {
    #возвращает Selected.System.String
    [cmdletbinding()]
	param (
		[Parameter(Mandatory=$false)]
        [string]$category = "User", #search category (User, Computer, group)
        [Parameter(Mandatory=$false)]
        [string]$attribute = "sAMAccountName", #search attribute (cn, description, samaccountname, etc)
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelinebyPropertyName=$true)]
        [string]$searchstring, #beware, use ldap escape characters https://social.technet.microsoft.com/wiki/contents/articles/5312.active-directory-characters-to-escape.aspx
        [Parameter(Mandatory=$false)]
        $properties =  @("distinguishedname", "userprincipalname", "samaccountname"), #necessary properties (cn, distinguishedName, description, etc)
		[Parameter(Mandatory=$false)]
        $SearchRoot
	)
    try {
        if ($SearchRoot) {
            [void][adsi]::exists("LDAP://$SearchRoot")
            $DomainEntry = [adsi]"LDAP://$SearchRoot"
        } else {
            $DomainEntry = [adsi]"LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName)"
        }
    } catch {
        Write-Host "can't establish connect to domain"
        return $null
    }
    $searcher=New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $DomainEntry
    $Searcher.Filter = "(&(objectCategory=$category)($attribute=$searchstring))"
    $Searcher.PageSize = 1000
    foreach($property in $properties) {
        [void]$Searcher.PropertiesToLoad.Add($property)
    }
    $Results = $Searcher.FindAll()
    
    if ($Results -ne $null) {
        $tArray = @()
        foreach ($Result in $Results) {
            $tItem = Select-Object -InputObject "" -Property $properties
            foreach ($property in $properties){
                $tItem.$property = $($Result.Properties.$property)
            }
            $tArray += $tItem
        }
        return $tArray
    }
    else {
        Write-Host "Nothing found for LDAP://$DomainEntry,(&(objectCategory=$category)($attribute=$searchstring))"
        return $null
    }
}
function Get-LoggedUsers {
	param (
		[Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelinebyPropertyName=$true)]
        [string]$computerName
	)
	try {
		$loggedUsersProcess = Get-WmiObject -ComputerName $computerName win32_process -Filter "Name='explorer.exe'" -ErrorAction "Stop" | %{$_.getOwner() | Sort | Get-Unique |Select-Object domain,user}
		$activeUser = (Get-WmiObject -ComputerName $computerName Win32_ComputerSystem -ErrorAction "Stop").userName
	} catch {
		return $null
	}
    $tArray = @()
    if ($loggedUsersProcess -eq $null) {return $null}
    ForEach ($process in $loggedUsersProcess) {
        $loggedUser = New-Object PSObject -Property @{
            User = $process.user
            Domain = $process.domain
            isActiveUser = $false
        }
        if ($activeUser -ne $null) {
            #2do check for active rdp\ts connections
            if ($loggedUser.user -eq $activeUser.split("\")[1] -and $loggedUser.Domain -eq $activeUser.split("\")[0]) {$loggedUser.isActiveUser = $true}
        }
        $tArray += $loggedUser
    }  
	return $tArray
}

function get-PCStatus {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelinebyPropertyName=$true)]
        [string]$ComputersNameMask
    )
	$Computers = adsi-search -category "Computer" -attribute "name" -searchstring $ComputersNameMask -properties @("dnshostname", "lastlogontimestamp", "lastlogon")
    if ($Computers -eq $null) {return $null}
	$tArray = @()
    foreach ($Computer in $Computers) {
		$tArray += New-Object PSObject -Property @{
			computerName = $Computer.dnshostname
			lastlogontimestamp = [datetime]::fromfiletime($Computer.lastlogontimestamp)
			lastlogon = [datetime]::fromfiletime($Computer.lastlogon)
		}
        if (Test-Connection -ComputerName $Computer.dnshostname -Count 2 -Quiet) {
			Add-Member -InputObject $tArray[-1] -MemberType NoteProperty -Name "status" -Value "online"
        } else {
			Add-Member -InputObject $tArray[-1] -MemberType NoteProperty -Name "status" -Value "offline"
		}
    }
	return $tArray
}

Function Find-InstalledApps{
    param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelinebyPropertyName=$true)]
        [switch]$IncludeEmptyRegEntry
    )
    
    $Apps = @()
    $RegistryKey = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\")
    $RegistryKeyX64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
    
    if (Test-Path -Path $RegistryKeyX64) {$RegistryKey += $RegistryKeyX64}
    $InstalledApps = Get-ChildItem -Path $RegistryKey
    Foreach($InstalledApp in $InstalledApps){
        $Apps += Get-ItemProperty -Path Registry::$InstalledApp | select $InstalledApp.property
        try {
            Add-Member -InputObject $Apps[-1] -MemberType NoteProperty -Name "RegistryKey" -Value $InstalledApp.name
        } catch {
            if ($IncludeEmptyRegEntry) {
                $Apps[-1] = New-Object PSCustomObject -Property @{"RegistryKey"=$InstalledApp.name}
            }
        }
    }
    return $Apps
}
#get-PCStatus wkst-31* | ?{$_.status -eq "online"} | %{write-host "$($_.computername)" ; get-LoggedUsers -computerName $_.computerName}
