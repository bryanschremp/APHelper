<#
 .Synopsis
  Provides a number of useful functions for working with Autopilot

 .Description
  Provides a number of useful functions for working with Autopilot

  .Version
  2016.06.24.1400
#>

#Region Common Initialize v2.1.26 **************************

    #Region functions

    #Region Write-*Info functions
    function Write-Info
    {
        param
        (
            [string]$EventID,
            [string]$Severity,
            [string]$Message,
            [switch]$NoApAudit
        )

        # To write to a log file, make sure that $WriteInfoLogFile is set to a valid path
        # for AP, use "D:\data\logs\local\[YourLogFileName].log

        if ($WriteInfoLogFile)
        {
            $time = Get-Date -Format s
            $Severity = $Severity.Substring(0,1).ToLower()
            $functionName = (Get-PSCallStack)[2].command
            $auditMessage = [string]::Format('{0}, {1}, {2}, [{3}], {4}', $Severity, $time, $EventID, $functionName, $Message)
            $auditMessage | Out-File -Append -FilePath $WriteInfoLogFile
        }

        if (-not $NoApAudit)
        {
            New-APAudit -Category $AuditCategory -ParameterList $auditMessage
        }

        switch ($Severity)
        {
            'i' {
                if ($Verbose -or $force)
                {
                    Write-Host ('{0}: [{1}]{2}' -f $Severity, $functionName, $Message)
                }
            }
            'w' {
                Write-Host ('{0}: [{1}]{2}' -f $Severity, $functionName, $Message) -BackgroundColor DarkBlue -ForegroundColor Yellow
            }
            'e' {
                Write-Host ('{0}: [{1}]{2}' -f $Severity, $functionName, $Message) -BackgroundColor DarkBlue -ForegroundColor Red
            }
        }
        # Write an event to the event log
        # Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventID -EntryType $severity -Message $message
    }

    function Write-DebugInfo
    {
        param
        (
            [string]$Message,
            [int]$Id = 100,
            [switch]$Force,
            [switch]$NoApAudit
        )

        if ($debug -or $Force)
        {
            $severity = 'Information'
            Write-Info $Id $severity $Message -NoApAudit:$NoApAudit
            # If $verbose, then write to the command line as well.
            # If($Verbose -or $force){Write-Host ("{0}: {1}" -f $severity,$message) }
        }
    }

    function Write-WarningInfo
    {
        param
        (
            [string]$Message,
            [int]$Id = 200,
            [switch]$NoApAudit
        )

        $severity = 'Warning'
        Write-Info $Id $severity $Message -NoApAudit:$NoApAudit
        # Write-Host ("{0}: {1}" -f $severity,$message) -BackgroundColor DarkBlue -ForegroundColor Yellow
    }

    function Write-ErrorInfo
    {
        param
        (
            [string]$Message,
            [int]$Id = 300,
            [switch]$NoApAudit
        )

        $severity = 'Error'
        Write-Info $Id $severity $Message -NoApAudit:$NoApAudit
        # Write-Host ("{0}: {1}" -f $severity,$message) -BackgroundColor DarkBlue -ForegroundColor Red
    }
    #EndRegion Write-*Info functions

    ###############################################################################

    #Region Generic functions
    function Convert-IniFile
    {
        param
        (
            [string]$File
        )

        if (-not (Test-Path $File))
        {
            Write-Error ('Error: {0} was not found.' -f $File)
        }
        else
        {
            $REGEX_INI_COMMENT_STRING = ";"
            $REGEX_INI_SECTION_HEADER = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*\[\s*(.*[^\s*])\s*]\s*$"
            $REGEX_INI_KEY_VALUE_LINE = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*([^=]*)\s*=\s*(.*)\s*$"

            $ini = @{}

            switch -regex -file $File
            {
                "$($REGEX_INI_SECTION_HEADER)" {
                    $section = $matches[1].trim()
                    $ini[$section] = @{}
                }
                "$($REGEX_INI_KEY_VALUE_LINE)" {
                    $name,$value = $matches[1..2]

                    if ($name -ne $null -and $section -ne $null)
                    {
                        $ini[$section][$name.trim()] = $value.trim()
                    }
                }
            }

            $ini
        }
    }

    function Convert-IniText
    {
        param
        (
            [Parameter(Mandatory = $true)][array]$Text
        )

        # Source: http://blogs.technet.com/b/deploymentguys/archive/2010/07/15/reading-and-modifying-ini-files-with-scripts.aspx
        $REGEX_INI_COMMENT_STRING = ";"
        $REGEX_INI_SECTION_HEADER = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*\[\s*(.*[^\s*])\s*]\s*$"
        $REGEX_INI_KEY_VALUE_LINE = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*([^=]*)\s*=\s*(.*)\s*$"

        $ini = @{}
        
        switch -regex ($Text)
        {
            "$($REGEX_INI_SECTION_HEADER)" {
                $section = $matches[1]
                $ini[$section] = @{}
            }
            "$($REGEX_INI_KEY_VALUE_LINE)" {
                $name,$value = $matches[1..2]
                if ($name -ne $null -and $section -ne $null)
                {
                    $ini[$section][$name] = $value.trim()
                }
            }
        }

        $ini
    }

    function Get-IniSetting
    {
        param
        (
            [Parameter(Mandatory=$true)]$Section,
            [Parameter(Mandatory=$true)]$Property,
            [Parameter(Mandatory=$True, ParameterSetName = 'Object')]$IniObject,
            [Parameter(Mandatory=$False, ParameterSetName = 'Object')]$FallbackIniObject,
            [Parameter(Mandatory=$True, ParameterSetName = 'File')]$IniFile,
            [Parameter(Mandatory=$False, ParameterSetName = 'File')]$FallbackIniFile
        )

        # The fallback options allow you to specify a second file/object to check
        # if the setting is not found in the first one

        if ($IniFile)
        {
            $IniObject = Convert-IniFile -File $IniFile
        }

        if ($FallbackIniFile)
        {
            $FallbackIniObject = Convert-IniFile -File $FallbackIniFile
        }

        # Look for the section/property in the Object
        try
        {
            $result = $IniObject.$($Section).$($Property)
        }
        catch
        {
            if (-not $FallbackIniObject)
            {
                throw $Error[0]
            }
        }

        if (-not $result -and $FallbackIniObject)
        {
            $result = $FallbackIniObject.$($Section).$($Property)
        }

        return $result
    }

    function Update-VariablesFromIni
    {
        param
        (
            [Parameter(Mandatory=$true)]$Section, 
            $File = '.\config.ini.flattened.ini'
        )

        if (Test-Path $File)
        {
            $ini = Convert-IniFile -File $File
        }
        else
        {
            Write-Error ('Ini file [{0}] not found.' -f $File)
        }

        foreach ($setting in ($ini.($Section)).GetEnumerator())
        {
            Set-Variable -Name $setting.Name -Value $setting.Value -Scope Global
        }
    }

    function SleepAndExit
    {
        param
        (
            [int]$Seconds = $defaultSleepSec,
            [switch]$NoInService
        )

        if (-not $NoInService)
        {
            Write-DebugInfo 'Setting APInService'
            Set-APInService $AuditCategory
        }

        if ($envName -eq 'VMHosts')
        {
            Write-DebugInfo ('Removing Servicelist_Override.ini.')
            Remove-APServiceListOverride
        }

        Write-Host ('Sleeping {0} seconds before exiting.' -f $Seconds)
        Start-Sleep -Seconds $Seconds
        Exit 0
    }

    function Get-RegValue
    {
        param
        (
            [string]$KeyName,
            [string]$ValueName,
            [string]$DefaultValue
        )

        $value = (Get-ItemProperty $KeyName $ValueName -ErrorAction SilentlyContinue).$ValueName

        if ($value)
        {
            $value
        }
        else
        {
            $DefaultValue
        }
    }

    function New-RegKey
    {
        param
        (
            [string]$KeyName
        )

        $parts = $KeyName -split '\\'
        $tempkey = ''

        $parts | ForEach-Object {
            $tempkey += ($_ + '\')

            if ((Test-Path $tempkey) -eq $false)
            {
                New-Item $tempkey -ErrorAction Stop | out-null
            }
        }

        return Get-Item $KeyName
    }

    function Set-RegValue
    {
        param
        (
            [string]$KeyName,
            [string]$ValueName,
            [string]$Value,
            [string]$Type = 'String'
        )

        if (-not (Test-Path $KeyName))
        {
            $key = New-RegKey -keyName $KeyName

            if (-not $key)
            {
                return $false
            }
        }

        New-ItemProperty -Path $KeyName -Name $ValueName -Value $Value -PropertyType $Type -Force -ErrorAction Stop
    }

    function Remove-RegValue
    {
        param
        (
            [string]$KeyName,
            [string]$ValueName
        )

        if ((Test-Path $KeyName) -eq $true)
        {
            try
            {
                Remove-ItemProperty -Path $KeyName -Name $ValueName -Force -ErrorAction Stop | Out-Null
                $true
            }
            catch
            {
                $false
            }
        }
    }

    function Get-MyFileInfo
    {
        # Usage: $script = Get-ScriptPath $MyInvocation
        param
        (
            $Invocation # What's my type?
        )
        
        if ($matches)
        {
            $matches.clear()
        }

        $Invocation.Line -match "\'(.*)\'"
        $scriptFileName = $MyInvocation.MyCommand
        $scriptFilePath = $matches[1]
        Dir $scriptFilePath
    }

    function Import-CsvFieldsHeader
    {
        param
        (
            [string]$File,
            [string]$String,
            [array]$Array
        )

        Write-Host 'Import-CsvFieldsHeader'

        if ($String -is [string])
        {
            $content = $String.split('`r`n')
        }
        elseif ($array -is [array])
        {
            $content = $Array
        }
        elseif (($File -is [IO.FileInfo]) -or (Test-path $File))
        {
            $content = get-content $File
        }
        else
        {
            Write-Error ('Must provide a valid `{0}, `{1}, or `{2}' -f $File, $String, $Array)
        }

        $fields  = ""
        $results = ""

        # Get the fields
        $content | where {$_} | foreach {
            if ($_ -match "#Fields:\s*(.*)")
            {
                $fields = $matches[1].split(",") | foreach {$_.trim()}
                $results = $content | where {$_ -notmatch "^#"} | ConvertFrom-Csv -Header $fields
            }
        }

        if (-not $results)
        {
            Write-Verbose 'Import-CsvFieldsHeader found no valid content in the file, string or array specified.'
        }

        $results
    }

    function Get-DNSHost
    {
        # Returns the list of hostname(s) from DNS for a given host entry
        param
        (
            [string]$HostParam
        )

        $maxTries = 10
        $sleepSeconds = 2

        for ($i = 1; $i -le $maxTries; $i++)
        {
            if ($i -gt 1)
            {
                Write-Host ('Attempt ({0} of {1}): Lookup {2}' -f $i, $maxTries, $HostParam)
                sleep $sleepSeconds
            }

            try
            {
                $nsLookup = [System.Net.Dns]::GetHostEntry($HostParam)
                $dsServers = $nsLookup.AddressList | foreach {[System.Net.Dns]::GetHostEntry($_.IPAddressToString).HostName}
            }
            catch
            {
            }

            if ($dsServers)
            {
                Write-Verbose ('Found {0}' -f $HostParam)
                $dsServers
                break
            }

            if ($i -eq $maxTries)
            {
                Write-Error ('Unable to lookup {0}' -f $HostParam)
            }
        }
    }

    function New-Folder
    {
        param
        (
            [string]$path
        )

        if ($path -contains '\\')
        {
            $msg = 'Cannot create folder ["$path"]. Network locations are not supported.'
            throw $msg
        }

        $splitPath = $path.replace('/','\').split('\')
        $rootFolder = $splitPath[0]

        if (Test-Path $rootFolder -ErrorAction SilentlyContinue)
        {
            $newPath = $rootFolder

            $splitPath | select -Skip 1 | foreach {
                $newPath = Join-Path $newPath $_

                if (-not (Test-Path $newPath))
                {
                    md $newPath | Out-Null
                }
            }

            Get-Item $path
        }
        else
        {
            $msg = 'Cannot create folder. Root folder ["$rootFolder"] is missing.'
            Write-Error $msg
        }
    }

    function WMIDateStringToDate
    {
        param
        (
            [string]$Time
        )
        
        [System.Management.ManagementDateTimeconverter]::ToDateTime($Time)
    }

    function Get-Uptime
    {
        param
        (
            [string]$Computer = '.',
            [switch]$ReturnTimeSpan
        )
        Write-Host 'Get-Uptime'

        $Computers = Get-WMIObject -class Win32_OperatingSystem -computer $Computer

        foreach ($System in $Computers)
        {
            $Bootup = $System.LastBootUpTime
            $LastBootUpTime = WMIDateStringToDate($Bootup)
            $Now = Get-Date
            $Uptime = $Now - $LastBootUpTime

            $d = $Uptime.Days
            $h = $Uptime.Hours
            $m = $Uptime.Minutes
            $ms= $Uptime.Milliseconds

            if ($ReturnTimeSpan)
            {
                $Uptime
            }
            else
            {
                $UptimeString = [string]::Format('Uptime: {0} days, {1} hours, {2}.{3} minutes', $d, $h, $m, $ms)
                Write-Host $UptimeString
            }
        }
    }

    function Get-OSInstallDate
    {
        param
        (
            [string[]]$Computer = $env:computername
        )

        Write-Host 'Get-OSInstallDate'

        if ($Computer -eq $env:COMPUTERNAME)
        {
            Write-Verbose '"$Computer" is localhost'
            $OS = Get-WmiObject -Class Win32_OperatingSystem -Computer $Computer
            $OS.ConvertToDateTime($OS.Installdate)
        }
        elseif (Test-Connection -ComputerName $Computer -Count 1 -ErrorAction 0)
        {
            Write-Verbose '"$Computer" is online'
            $OS = Get-WmiObject -Class Win32_OperatingSystem -Computer $Computer
            $OS.ConvertToDateTime($OS.Installdate)
        }
        else
        {
            Write-Verbose '"$Computer" is offline'
        }
    }

    function Get-VMHost
    {
        try
        {
            $item = get-item 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction SilentlyContinue
            $vmHost = $item.GetValue('PhysicalHostName').split('.')[0]
            $vmHost
        }
        catch
        {
        }
    }

    function Test-Admin
    {
        $id = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
        $id.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

    function Get-URLDecode
    {
        param
        (
            [string]$query = $(paste)
        )

        [System.Reflection.Assembly]::LoadWithPartialName('System.Web') | Out-Null
        [System.Web.HttpUtility]::UrlDecode($query)
    }

    function Get-URLEncode
    {
        param
        (
            [string]$query = $(paste)
        )

        [System.Reflection.Assembly]::LoadWithPartialName('System.Web') | Out-Null
        [System.Web.HttpUtility]::UrlEncode($query)
    }

    function Restart-ServiceScheduled
    {
        param
        (
            [string]$Name,
            [int]$DelayMin = 1,
            [string]$UserID = 'NT AUTHORITY\SYSTEM'
        )

        Import-Module ScheduledTasks -ErrorAction Continue

        $argument = '-command "& {Start-Transcript c:\temp\restart.txt; Restart-Service ' + $Name + ' ; stop-transcript}" -ExecutionPolicy RemoteSigned'
        $A = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $argument
        $P = New-ScheduledTaskPrincipal -UserId $UserID -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet
        $T = New-ScheduledTaskTrigger -At ((Get-Date).AddMinutes($DelayMin)) -Once
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        $taskName = ('Restart {0}' -f $Name)

        Register-ScheduledTask -TaskName $taskName -InputObject $D -Force
    }

    function Get-NetworkListener
    {
        #requires -Version 2
        NETSTAT.EXE -anop tcp | Select-Object -Skip 4 | ForEach-Object -Process {
            [regex]::replace($_.trim(),'\s+',' ')
        } | ConvertFrom-Csv -d ' ' -Header 'proto', 'src', 'dst', 'state', 'pid' |
        Select-Object -Property `
        @{name = 'SourceIP'   ; expression = {($_.src.split(':'))[0]}},
        @{name = 'SourcePort' ; expression = {($_.src.split(':'))[1]}},
        State,
        @{name = 'ProcessID'  ; expression = {$_.pid}},
        @{name = 'Process'    ; expression = {(Get-Process -Id $_.pid).name}}
    }

    #EndRegion Generic functions

    ###############################################################################

    #Region AP functions
    function Get-APAppRoot
    {
        if ($env:AppRoot)
        {
            $appRoot = $env:AppRoot
        }
        else
        {
            $appRoot = 'd:\app'
            $env:AppRoot = 'D:\app'
        }

        $appRoot
    }

    function Get-APDataDir
    {
        if ($env:DataDir)
        {
            $dataDir = $env:DataDir
        }
        else
        {
            $dataDir = 'd:\data'
            $env:DataDir = 'D:\data'
        }

        $dataDir
    }

    function Get-APServiceStatus
    {
        param
        (
            [Parameter(Mandatory = $False, 
                Position = 1, 
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][string]$ServiceName,
            [Parameter(Mandatory = $False, 
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)][string]$MachineName,
            [switch]$ExcludeShared
        )
        Write-Host 'Get-APServiceStatus'

        if ($MachineName)
        {
            $serviceStatusCsv = join-path \\$MachineName "data\servicemanager\servicestatus.csv"
        }
        else
        {
            $dataDir = Get-APDataDir
            $serviceStatusCsv = join-path $dataDir "servicemanager\servicestatus.csv"
        }

        $serviceStatus = Import-CsvFieldsHeader -File $serviceStatusCsv
        Write-Host $serviceStatus

        if ($ServiceName)
        {
            $serviceStatus | where {$_.Service -match "^$ServiceName\."}
        }
        elseif($ExcludeShared)
        {
            $serviceStatus | where {$_.VE -ne "Shared" -and $_.VE -notmatch "Autopilot-AutopilotClient"}
        }
        else
        {
            $serviceStatus
        }
    }

    function Get-AutopilotServicePath
    {
        param
        (
            [string]$Name
        )
        Write-Host 'Get-AutopilotServicePath'

        $appRoot = Get-APAppRoot
        $service = Get-APServiceStatus | where {$_.Service -match "^$Name\."}

        if ($service)
        {
            # Combine the serviceName with the path contained in env:AppRoot
            $servicePath = join-path $appRoot $service.Service
            return $servicePath
        }
    }

    function Disable-APService
    {
        param
        (
            [Parameter(Mandatory=$True)][string]$Service,
            [Parameter(Mandatory=$True)][int]$DurationInSeconds
        )

        $servicePath = Get-AutopilotServicePath $Service

        if (-not $servicePath)
        {
            Write-Warning -message ('Error getting Service Path for {0}. Cannot disable service. `nError: {1}' -f $Service, $error[0])
        }
        else
        {
            $fullServiceName = (Get-Item $servicePath).name
            $overrideString = (@"
[ServiceManager]
Duration={0}

[OverrideService]
{1}=

"@ -f $DurationInSeconds, $fullServiceName)
            $servicelist_overridePath = Join-Path (Join-Path $dataDir 'ServiceManager') 'servicelist_override.ini'
            $overrideString | Out-File -FilePath $servicelist_overridePath -Encoding Ascii -Force
        }
    }

    function Remove-APServiceListOverride
    {
        $servicelist_overridePath = Join-Path (Join-Path $dataDir 'ServiceManager') 'servicelist_override.ini'

        if (Test-Path $servicelist_overridePath)
        {
            Remove-Item $servicelist_overridePath -Force
        }
    }

    function Get-APServiceListOverride
    {
        param
        (
            [switch]$ExcludeInactive
        )

        $sloPath = join-path $dataDir 'servicemanager\servicelist_override.ini'

        if (Test-Path $sloPath)
        {
            $slo = Convert-IniFile -File $sloPath
            $sloFileLastWriteTime = (dir $sloPath).LastWriteTime
            $results = @()

            foreach ($override in $slo.OverrideService.GetEnumerator())
            {
                $result = "" | Select ServiceName, SourceBuild, OverrideBuild, CurrentBuild, Expiration, FileLastWriteTime, Active
                $result.ServiceName = ($override.Name).split('.')[0]
                $result.SourceBuild = $override.Name
                $result.OverrideBuild = $override.Value
                $result.Expiration = $slo.ServiceManager.Expire
                $result.CurrentBuild = (Get-APServiceStatus | where {$_.service -like ('{0}*' -f $result.ServiceName)}).Service
                $result.FileLastWriteTime = $sloFileLastWriteTime

                if ($result.Expiration -lt (Get-Date))
                {
                    $result.Active = $false
                }
                elseif($result.OverrideBuild -ne $result.CurrentBuild)
                {
                    $result.Active = $false
                }
                else
                {
                    $true
                }

                $results += $result
            }

            if ($ExcludeInactive)
            {
                $results | where {$_.Active -eq $true}
            }
            else
            {
                $results
            }
        }
    }

    function Get-APCockpitServer
    {
        param
        (
            [string]$Cluster = $clusterName
        )

        ('cp.autopilot.{0}.ap.phx.gbl' -f $Cluster)
    }

    function Get-APCockpitData
    {
        param
        (
            [string]$Query,
            [switch]$UrlEncodeQuery,
            [switch]$UseTransparentPx,
            [string]$Environment = $envName,
            [string]$Cluster = $ClusterName
        )

        if ($UrlEncodeQuery)
        {
            $query = Get-URLEncode -Query $query
        }

        $cockpitServer = Get-APCockpitServer -Cluster $ClusterName

        if ($UseTransparentPx)
        {
            $tag = 'TransparentPX'
        }
        else
        {
            $tag = 'TransparentDM'
        }

        $uri = ('http://{0}:81/query?tag={1}&format=XmlParam&text={2}&Environment={3}' -f $cockpitServer, $tag, $query, $Environment)

        $results = ([xml](Invoke-WebRequest $uri -UseBasicParsing  -UseDefaultCredentials)).Cockpit.Row
        $results
    }

    function Get-APClusters
    {
        $query = 'select ClusterName from clusters'
        Get-APCockpitData -Query $query -UrlEncodeQuery -Environment Autopilot | select -ExpandProperty ClusterName
    }

    function Get-APMachinefunction
    {
        param
        (
            [string]$MachineName = $env:COMPUTERNAME,
            [switch]$AllProperties
        )

        $machinefunction = ''
        $machineList = Import-CsvFieldsHeader -File 'd:\app\MachineList.csv'

        if ($AllProperties)
        {
            $machinelist | where {$_.MachineName -eq $MachineName}
        }
        else
        {
            $machinefunction = ($machinelist | where {$_.MachineName -eq $MachineName}).Machinefunction
            $machinefunction
        }
    }

    function Get-APMachineProperty
    {
        param
        (
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [Alias('Name')]
                [Alias('ComputerName')][string]$MachineName,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [Alias('PropertyName')][string]$Property,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)][string]$Environment,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)][switch]$IncludeSystemProperties
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Get current path, then change to $APToolsPath
        pushd $APToolsPath

        $query = ''

        if ($MachineName)
        {
            $query += (' -s {0} ' -f $MachineName)
        }

        if ($Property)
        {
            $query += (' -p {0} ' -f $Property)
        }

        if ($Environment)
        {
            $query += (' -w {0} ' -f $Environment)
        }

        if ($IncludeSystemProperties)
        {
            $query += ' -t '
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c ('GetMachineProperties {0}' -f $query)
        # TODO - consider adding "| Out-Null" in the line above

        # Return to original path
        popd

        if($results)
        {
            Import-CsvFieldsHeader -Array $results
        }
        else
        {
            'No properties found.'
        }
    }

	function Get-APMachinePropertyByCluster
    {
	  Param (
		[Parameter(Mandatory=$True,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True)]
		[Alias('PropertyName')]
		[string]$Property
		,
		[Parameter(Mandatory=$False,
		ValueFromPipeline=$True,
		ValueFromPipelineByPropertyName=$True)]
		[Alias('Cluster')]
		[string]$ClusterName = $ClusterName
	  )

$query = @"
-- ******* MachinePropertyByCluster ********

Set Nocount On
declare @dbname sysname
declare @execstmt varchar(3100)
if(object_id('tempdb..#clusterTemp') is not null)
begin
 drop table #clusterTemp
end
-- MUST UPDATE THE TEMP TABLE DEFINITION --
create table #clusterTemp
(
 machineName varchar(max),
 Machinefunction varchar(max),
 Status varchar(max),
 Property varchar(max),
 LastUpdated datetime,
 Value varchar(max),
 PropertyLevel varchar(max),
 ScaleUnit varchar(max),
 StatusO varchar(max),
 LastError varchar(max),
 Environment VARCHAR(200),
 Cluster VARCHAR(256)
)

declare cur_dbs cursor static for
select name
 from master..sysdatabases
 where name like 'dmdata%'
open cur_dbs
 fetch next from cur_dbs into @dbname
while (@@fetch_status = 0)
begin
 declare @level varchar(20)

 SET @execStmt = '
USE '+@dbname+';
Declare @propertyName varchar(max)
Select @propertyName = ''{0}''

DECLARE @Environment Varchar(100);
SELECT @Environment = Environment from dataSyncSystem;
DECLARE @Cluster Varchar(100);
SELECT @Cluster = cluster from dataSyncSystem;

INSERT #clusterTemp
SELECT
 machineName,
 Machinefunction,
 Status,
 Property,
 lastUpdated,
 Value,
 PropertyLevel,
 ScaleUnit, StatusO, LastError,
 @Environment as Enviornment,
 @Cluster as Cluster

from (Select mt.machinename, mt.machinefunction, mt.Status, mt.StatusO, mt.lastError, mt.ScaleUnit,
	mpmt.property, mpmt.value, mpmt.lastUpdated,
	mpmt.propertyLevel

	from machines mt (nolock)
	 Join machinePropertyMap mpmt (nolock)
	 on mt.machineName = mpmt.machineName
	 and mpmt.property like @propertyName
	LEFT Join serviceList sl (nolock)
		on sl.machinefunction = mt.machinefunction
	) a
	where machinefunction not in (''coreSwitch'',''coreTS'',''podPower'',''podSwitch'',''podTS'')
'

 DECLARE @Tries tinyint
 SET @Tries = 1
 WHILE @Tries <= 3
 BEGIN
 BEGIN TRY
 exec(@execstmt)
 BREAK
 END TRY
 BEGIN CATCH
 SET @Tries = @Tries + 1
 CONTINUE
 END CATCH;
 END
 fetch next from cur_dbs into @dbname
end
close cur_dbs
deallocate cur_dbs

-- SELECT * from #clusterTemp

SELECT *
FROM #clusterTemp

drop table #clusterTemp
"@ -f $Property

	  Get-APCockpitData -cluster $ClusterName -query $query -UrlEncodeQuery -Environment Autopilot
	}

    function Get-APMachineAudit
    {
        Param (
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [Alias('ComputerName')]
        [string]$MachineName = $env:COMPUTERNAME
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Status
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [int]$SinceDaysAgo
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [int]$MaxAuditCountPerMachine
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [switch]$IncludeSystemProperties
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        $query = ""

        If ($MachineName)
        {
            $query += " -s $MachineName "
        }

        If ($Environment)
        {
            $query += " -w $Environment "
        }

        If ($Status)
        {
            $query += " -f $Status "
        }

        If ($SinceDaysAgo)
        {
            $query += " -a $SinceDaysAgo "
        }

        If ($MaxAuditCountPerMachine)
        {
            $query += " -c $MaxAuditCountPerMachine "
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetMachineAudit $query"
        # TODO - consider adding "| Out-Null" in the line above

        # Return to original path
        cd $PWD

        If($results)
        {
            Import-CsvFieldsHeader -array $results
        }
        Else
        {
            "No properties found."
        }
    }

    function Get-APToolsPath
    {
        Write-Host 'Get-APToolsPath'
        Get-AutopilotServicePath 'APTools'
    }

    function Get-APEnvironmentIni
    {
        Write-Host 'Get-APEnvironmentIni'
        Convert-IniFile -File (join-path $dataDir 'autopilotdata\environment.ini.flattened.ini')
    }

    function Get-APAutopilotIni
    {
        Write-Host 'Get-APAutopilotIni'
        Convert-IniFile -File (join-path $appRoot 'autopilot.ini')
    }

    function Get-APSharedIni
    {
        Write-Host 'Get-APSharedIni'
        Convert-IniFile -File (join-path $dataDir 'autopilotdata\shared.ini.flattened.ini')
    }

    function Get-APServiceList
    {
        Param (
        [Parameter(Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
            [Alias('Name')]
            [Alias('ComputerName')]
            [string]$MachineName = $env:COMPUTERNAME,
        [Parameter(Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
            [string]$Environment
        )
        Write-Host 'Get-APServiceList'

        # Get location of dmclient.exe
        $APToolsPath = Get-AutopilotServicePath "APTools"

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        $query = ""
        If ($MachineName)
        {
            $query += " -s $MachineName "
        }

        If ($Environment)
        {
            $query += " -w $Environment "
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetServiceList $query"
        # TODO - consider adding "| Out-Null" in the line above

        # Return to original path
        cd $PWD

        If ($results)
        {
            Convert-IniText -Text $results
        }
        Else
        {
            "No service list info found."
        }
    }

    function Invoke-APCustomServiceScript
    {
        Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('InServiceScript','OutOfServiceScript')]
        [string]$serviceType
        )

        $appName    = $envINI.SecurityPatching.AppName
        $scriptName = $envINI.SecurityPatching.$($serviceType)

        If ($appName)
        {
            If ($scriptName)
            {
                $scriptPath = Join-Path (Get-AutopilotServicePath $appName) $scriptName
                Write-DebugInfo "Custom $($serviceType): $scriptPath"

                If (Test-Path $scriptPath)
                {
                    [ref]$tokenizeErrors = $null
                    $tokens = [System.Management.Automation.PSParser]::Tokenize($scriptPath, $tokenizeErrors)

                    If ($tokenizeErrors.Value.Count -eq 0)
                    {
                        # Run the Script
                        Try
                        {
                            $result = &$scriptPath | select -Last 1
                        }
                        Catch
                        {
                            $result = 1
                        }

                        If ($result -eq 0)
                        {
                            Write-DebugInfo "Custom $serviceType [$scriptPath] completed successfully. Returned [$result]"
                        }
                        Else
                        {
                            $message = "Error calling custom $serviceType [$scriptPath]. Exiting without patching. `nError: $($error[0])"
                            Update-APMachineProperty -Level Warning -Property "$auditCategory" -Value $message
                            Write-ErrorInfo -message $message
                            SleepAndExit
                        }
                    }
                    Else
                    {
                        $message = "Custom $serviceType specified in Environment.ini [$scriptPath] is not a valid PowerShell script. Exiting without patching. `nError: $($tokenizeErrors.Value) "
                        Update-APMachineProperty -Level Warning -Property "$auditCategory" -Value $message
                        Write-ErrorInfo -message $message
                        SleepAndExit
                    }
                }
                Else
                {
                    $message = "Custom $serviceType specified in Environment.ini [$scriptPath] does not exist. Exiting without patching."
                    Update-APMachineProperty -Level Warning -Property "$auditCategory-CustomInServiceScript" -Value $message
                    Write-ErrorInfo -message $message
                    SleepAndExit
                }
            }
            Else
            {
                Write-DebugInfo "No $serviceType specified. Proceeding as usual."
            }
        }
        Else
        {
            Write-DebugInfo "No AppName specified. Proceeding as usual."
        }
    }

    function Update-APMachineProperty
    {
        Param (
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [string]$MachineName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateSet('OK','Information','Warning','Error')]
        [Alias('PropertyLevel')]
        [string]$Level,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('PropertyName')]
        [string]$Property,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('ValueText')]
        [string]$Value,

        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment,

        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$TempFileName,

        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [switch]$Append,

        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [switch]$NoSubmit
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-AutopilotServicePath APTools

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        # Get Temp file
        If ($TempFileName)
        {
            If (-not (Test-Path $TempFileName -ErrorAction SilentlyContinue))
            {
                $tempFileName = [System.IO.Path]::GetTempFileName()
            }
        }
        Else
        {
            $tempFileName = [System.IO.Path]::GetTempFileName()
        }

        # Save inputs into an ASCII csv file
        [string]::join(",", ($MachineName, $Level, $Property, $Value)) | Out-File -Encoding ASCII -FilePath $tempFileName -Force -Append:$Append

        If (-not $NoSubmit)
        {
            $query = ""
            If ($Environment)
            {
                $query += " -w $Environment "
            }

            # Call dmclient
            .(Join-Path $APToolsPath dmclient.exe) -c "UpdateMachineProperty $query" -i $tempFileName | Out-Null

            # Delete temp file
            del $tempFileName
        }
        # Return to original path
        cd $PWD
    }

    function New-APAudit {
        Param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [string]$MachineName = $env:COMPUTERNAME
        ,
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Category
        ,
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Parameters')]
        [string]$ParameterList
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Details
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment
        )
        # Get location of dmclient.exe
        $APToolsPath = Get-AutopilotServicePath APTools

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        # Replace instances of " -" in $ParameterList because the audit command
        # interprets those as command line switches
        If ($ParameterList -match " -")
        {
            $ParameterList = $ParameterList -replace (" -", " =")
            $ParameterList += "[Cleanup:'-' chars replaced with '=']"
        }

        $command = ""
        $command += " -category $Category"
        $command += " -parameterlist $MachineName,$ParameterList"

        If ($Environment)
        {
            $command += " -w $Environment"
        }

        If ($Details)
        {
            $command += " -details $Details"
        }

        .(Join-Path $APToolsPath dmclient.exe) -c "Audit $command" | Out-Null

        # Return to original path
        cd $PWD
    }

    function Restart-APComputer
    {
        Param ($AuditCategory, $rebootDelaySec = 13)

        Write-DebugInfo "Enter: Restart-APComputer"

        # Disable chkdsk to accelerate reboot
        Write-DebugInfo "Preventing chkdsk during the reboot."
        Set-RegValue -keyName "HKLM:\system\CurrentControlSet\control\Session Manager" -valueName BootExecute -value {autocheck autochk *} -type MultiString

        # TODO - remove this code after the hard reboots are complete (May 2015 Patching cycle)
        $forceHardReboot = $false
        If (($forceHardRebootMSNPatchVersion -eq $TargetMSNPatchVersion) -and (-not $newMachine))
        {
            If ($machineSKU -match "ApVm.*")
            {
                $message = "Forcing a hard reboot. ForceHardRebootMSNPatchVersion{0} = TargetMSNPatchVersion and SKU matches ApVm.*" -f $forceHardRebootMSNPatchVersion
                Write-DebugInfo $message
                Update-APMachineProperty -Level Error -Property autopilotini -Value "Machine is unreachable via network or too low on resources (Reboot to update Hyper-V configuration)"
                # pushd $APToolsPath
                # .\ManualRepair.exe -m $env:COMPUTERNAME -a HardReboot -r "Update Hyper-V settings to allow graceful shtudown" -p 30 -l
                # popd
                $forceHardReboot = $true

                Write-DebugInfo "Calling Shutdown.exe /s with timeout of $rebootDelaySec seconds"
                shutdown /s /t $rebootDelaySec /f /c "$AuditCategory Required Reboot in [$rebootDelayTime] seconds"
            }
        }

        # TODO - remove If wrapper code after the hard reboots are complete (May 2015 Patching cycle)
        If (-not $forceHardReboot)
        {
            Write-DebugInfo "Calling Shutdown.exe /r with timeout of $rebootDelaySec seconds"
            shutdown /r /t $rebootDelaySec /f /c "$AuditCategory Required Reboot in [$rebootDelayTime] seconds"
        }

        Write-DebugInfo "Stopping APSvcMgr"
        Stop-Service -Name APSvcMgr -Force
    }

    function Restart-APService
    {
        Param (
        [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('Service')]
        [string]$ServiceName,

        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName="Machine")]
        [Alias('Machine')]
        [string]$MachineName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$True , ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName="Machinefunction")]
        [string]$Machinefunction,

        [Parameter(Mandatory=$True , ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName="Machinefunction")]
        [Alias('Delay')]
        [int]$DelaySeconds,

        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [switch]$ForceRestart,

        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ParameterSetName="Machinefunction")]
        [string]$Environment = $envName
        )

        # Get location of svcmgrclient.exe
        $APToolsPath = Get-AutopilotServicePath APTools

        # Change to $APToolsPath
        pushd $APToolsPath

        If ($Machinefunction)
        {
            $machines = @(Get-APMachineInfo -Environment $Environment -Machinefunction $Machinefunction | select -ExpandProperty machine)
        }
        Else
        {
            $machines = @($MachineName)
        }

        Write-Verbose ("Machines found: {0}" -f [string]::Join(",",$machines))

        If ($ForceRestart)
        {
            $time = "-t 0"
        }
        Else
        {
            $time = ""
        }

        $i=0
        Foreach ($machine in $machines)
        {
            $i += 1
            Write-Verbose ("Attempting to restart $ServiceName on $machine ({0} of {1} machines)" -f $i, $machines.count)
            # Call svcmgrclient
            .(Join-Path $APToolsPath svcmgrclient.exe) -s $machine -c "stopservice -s $ServiceName $time" 2>&1>$null

            If ($Machinefunction)
            {
                Write-Verbose "Sleeping for $delaySeconds before proceeding with next machine."
                Start-Sleep -Seconds $DelaySeconds
            }
        }

        # Return to original path
        popd
    }

	<#
	.SYNOPSIS
	Restarts specified AP service on multiple machines, one scale unit at a time.
	.DESCRIPTION
	Restarts (kicks) the specified AP service with a -force on each of the machines found in the specified Environment and Machine function.
	.PARAMETER ServiceName
	The name of the AP service to be restarted on each machine.
	Note: Do not include the build label.
	  Correct:   XboxLogUploader
	  Incorrect: XboxLogUploader.XboxLogUploader_20151019_1
	.PARAMETER Machinefunction
	The name of the machine fuction containing the machines.
	.PARAMETER MachineFilter
	An optional list of machines to be included. If MachineFilter is provided, services will only be restarted on machines specified by this parameter.
	The parameter can be an array of machines, a file containing a list of machines, or a string containing a comma separated list of machines.
	.PARAMETER MinMachineHealthyPercent
	This is the minimum percent of machines in the scale unit that must be healthy after the service has been restarted before the cmdlet will move on to the next scale unit.
	Default: 95
	Note: This parameter takes an int (95), not a decimal (.95) or a percent (95%)
	.PARAMETER DontWaitForServiceToRestart
	If this switch paramater is specified, the cmdlet will move on from one machine to the next in the same scale unit without waiting for the service to enter a running state.
	.PARAMETER ScaleUnit
	An optional parameter that restricts the restarts to only the scale unit specified.
	.PARAMETER MachineDelayInSeconds
	The amount of time to wait between machines in the same scale unit.
	Default: 5 seconds
	.PARAMETER ScaleUnitDelayInSeconds
	The amount of time to wait between scale units.
	Default: 1200 seconds
	.PARAMETER Environment
	The name of the environment where the machines are located. This is only needed if the cmdlet is being run from a different environment.
	Note: This cmdlet will not run against remote environments unless it is being run in the Autopilot environment, and cannot be run across clusters.
	.EXAMPLE
	Restart-APServiceByScaleUnit -ServiceName PlatformHealthMonitor -Environment APVMTesting-Test-CY1PPE -Machinefunction APVMTest
	Attempts to restart all of the machines in the APVMTest machine function. It will wait until the service is running on each machine, then wait for 5 seconds before proceeding to the next machine. It will wait 1200 seconds before proceeding from one scale unit to the next.
	.EXAMPLE
	Restart-APServiceByScaleUnit -ServiceName PlatformHealthMonitor -Environment APVMTesting-Test-CY1PPE -Machinefunction APVMTest -ScaleUnit 0 -MachineFilter "C1PVM020011127A","C1PVM020011127E"
	Attempts to restart only the machines in scale unit 0 in the APVMTest machine function, and limits the restarts to only 2 of the machines in that scale unit (C1PVM020011127A,C1PVM020011127E). It will wait until the service is running on each machine, then wait for 5 seconds before proceeding to the next machine. It will wait 1200 seconds before proceeding from one scale unit to the next.
	#>
    function Restart-APServiceByScaleUnit {
        Param(
        [Parameter(Mandatory=$True, Position=1, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('Service')]
        [string]$ServiceName
        ,
        [Parameter(Mandatory=$True, Position=2, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('MF')]
        [string]$Machinefunction
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        $MachineFilter
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('MinHealthy')]
        [int]$MinMachineHealthyPercent = 95
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [switch]$DontWaitForServiceToRestart
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('SU')]
        $ScaleUnit
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [int]$MachineDelayInSeconds = 5
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [int]$ScaleUnitDelayInSeconds = 1200
        ,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [string]$Environment = $envName
        )

        $scaleUnits = @()

        If ($scaleUnit -eq $null){
            $machines = Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment
            If ($machines){
                $scaleUnits = @($machines | select -Unique -ExpandProperty Row)
            }
            Else {
                Write-Error ("No machines found to process for {0}\{1}." -f $environment,$Machinefunction)
                Return
            }
        }
        Else {
            $scaleUnits = @($ScaleUnit)
        }

        If ($scaleUnits -or $scaleUnit -eq 0){
            Write-Host ("ScaleUnits to be processed: {0}" -f [string]::Join(", ",$scaleUnits))
            Write-Host ("DontWaitForServiceRestart before proceeding to next machine in same scale unit: {0}" -f $DontWaitForServiceToRestart)
            Write-Host ("MinMachineHealthyPercent before moving to next scale unit: {0}" -f $MinMachineHealthyPercent)
            Write-Host ("ScaleUnitDelayInSeconds between scale units AFTER machines are healthy: {0}" -f $ScaleUnitDelayInSeconds)
            Write-Host ("MachineDelayInSeconds between machines: {0}" -f $MachineDelayInSeconds)
        }
        Else {
            Write-Error ("No scale units found to process for {0}\{1}." -f $environment,$Machinefunction)
            Return
        }
        $results = @()

        $lastScaleUnit = $scaleUnits | select -last 1

        If ($MachineFilter){
            If ($MachineFilter.GetType().IsArray){
                # Do nothing this is what we want
                Write-Host "MachineFilter appears to be an array of machines."
            }
            ElseIf ((Test-Path $MachineFilter)){
                Write-Host ("Getting list of machines to filter from the file: {0}" -f {$MachineFilter})
                $MachineFilter = gc $MachineFilter | where {$_}
            }
            ElseIf (($MachineFilter.GetType().IsString) -and $MachineFilter -match ";|," ){
                Write-Host ("Getting the list of machines to filter from the provided string.")
                $MachineFilter = $MachineFilter.Split(",;") | where {$_}
            }
            Else {
                Write-Error ("MachineFilter does not appear to be a valid array, file, or comma separated list of machines.")
                Return
            }

            $MachineFilter = $MachineFilter.Trim() | Where {$_} | select -Unique

            Write-Host ("Number of unique machines to include found in MachineFilter: {0}" -f $MachineFilter.count)
        }

        If ($ServiceName -match "\."){
            $message = @"
    The ServiceName specified {0} contains a period '.', you are probably not using the correct name for the service.

    ServiceName parameter
    The name of the AP service to be restarted on each machine.
    Note: Do not include the build label.
    Correct:   XboxLogUploader
    Incorrect: XboxLogUploader.XboxLogUploader_20151019_1

"@
            Write-Warning ($message -f $ServiceName )
        }

        Foreach ($su in $scaleUnits){
            $machines = @(get-apmachineinfo -machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})

            If ($machines.count -eq 0){
                Write-Error ("No machines found in specified scale unit: {0}." -f $su)
                Return
            }

            If ($MachineFilter){
                $machines = $machines | foreach {If ($MachineFilter -contains $_.machine){$_}}
                Write-Host ("Machines after applying MachineFilter: {0}" -f [string]::Join("; ", $machines.machine))
            }

            Write-Host "`n`nStarting ScaleUnit: $su"
            Write-Host ("Machine count: {0}" -f $machines.count)
            $lastMachineName = ($machines | select -last 1).machine

            Foreach ($machine in $machines){
                $tryRestart = $true

                $machineName = $machine.machine
                Write-Host ("`nConnecting to {0} ..." -f $machineName)

                $machineInfo = "" | Select Environment, Machinefunction, ScaleUnit, MachineName, ServiceName, MachineStatusStart, MachineStatusEnd, ServiceStatusStart, ServiceStatusEnd, RestartTime, Result
                $machineInfo.Environment = $Environment
                $machineInfo.Machinefunction = $Machinefunction
                $machineInfo.ScaleUnit = $su
                $machineInfo.MachineName = $machineName
                $machineInfo.ServiceName = $ServiceName
                $machineInfo.MachineStatusStart = $machine.Status

                If (Test-Connection $machineName -Count 2 -quiet){
                    $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName
                }
                Else {
                    Write-Warning ("Could not connect to machine {0}." -f $machineName)
                    $machineInfo.Result = "Offline"
                    $tryRestart = $false
                }

                If ($machineInfo.Result -ne "Offline"){
                    If (-not $service){
                        Write-Warning ("Service {0} not found on {1}." -f $ServiceName,$machineName)
                        $machineInfo.Result = "Service Not Found"
                        $tryRestart = $false
                    }
                    ElseIf ($service.Status -eq "disabled"){
                        Write-Warning ("Service {0} disabled on {1}." -f $ServiceName,$machineName)
                        $machineInfo.Result = "Service Disabled"
                        $tryRestart = $false
                    }
                    ElseIf (-not ($service.Status -eq "running")){
                        Write-Warning ("Service {0} not running on {1}. Will try to start it." -f $ServiceName,$machineName)
                    }

                    If ($tryRestart){
                        $machineInfo.ServiceStatusStart = $service.Status
                        Write-Host ("Restarting {0} on {1}..." -f $ServiceName,$machineName)
                        $machineInfo.RestartTime = Get-Date
                        Restart-APService -ServiceName $ServiceName -MachineName $machineName -ForceRestart

                        $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName

                        If (-not $DontWaitForServiceToRestart){
                            Write-Host "Waiting for service to start." -NoNewline
                            While ($service.status -ne "running" ){
                                start-sleep 5
                                Write-Host "." -NoNewline

                                $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName
                            }
                            $machineInfo.Result = "Service Restarted Successfully"
                        }
                        Else {
                            $machineInfo.Result = "Service Restart Called"
                        }
                        $machineInfo.ServiceStatusEnd = $service.status
                        $machineInfo.MachineStatusEnd = (Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment | Where {$_.machine -eq $machineName} ).Status
                    }
                }

                If ($machineName -ne $lastMachineName){
                    Write-Host "`nSleeping for $MachineDelayInSeconds seconds before next machine..."
                    Start-Sleep $MachineDelayInSeconds
                }

                $results += $machineInfo
            }

            If ($su -ne $lastScaleUnit){
                Write-Host " `nSleeping for $ScaleUnitDelayInSeconds seconds before next scale unit..."
                Start-Sleep $ScaleUnitDelayInSeconds
            }

            If ($MinMachineHealthyPercent -ne 0){
                $suStatus = @(get-apmachineinfo -machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})
                $healthyCount = @($suStatus | where {$_.status -eq "H"}).count
                $HealthyPercent = [math]::Floor([Decimal]($healthyCount/$suStatus.count*100))

                If ($healthyPercent -lt $MinMachineHealthyPercent){
                    While ($healthyPercent -lt $MinMachineHealthyPercent){
                        Write-Host ("Waiting for machines in scale unit {0} to get healthy. Currently {1}% of minimum {2}%." -f $su,$healthyPercent,$MinMachineHealthyPercent)
                        Start-Sleep 15
                        $suStatus = @(get-apmachineinfo -machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})
                        $healthyCount = @($suStatus | where {$_.status -eq "H"}).count
                        $HealthyPercent = [math]::Floor([Decimal]($healthyCount/$suStatus.count*100))
                    }
                }
                foreach ($s in $suStatus){
                    # update the machine status in $results
                    $m = $s | where {$_.MachineName -eq $s.machine}
                    $m.MachineStatusEnd = $s.status
                }
            }
            Write-Host "Proceeding to next scale unit"
        }
        Write-Host "***********************"
        Write-Host "*** Summary Results ***"
        Write-Host "***********************"
        $results
    }

    function Get-APMachineInfo
    {
        param
        (
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [string]$Status,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [Alias('function')]
                [string]$Machinefunction,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [string]$Environment
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Change to $APToolsPath
        pushd $APToolsPath

        $query = ''

        if ($status)
        {
            $query += (' -s {0} ' -f $Status)
        }

        if ($Machinefunction)
        {
            $query += (' -f {0} ' -f $Machinefunction)
        }

        if ($Environment)
        {
            $query += (' -w {0} ' -f $Environment)
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c ('GetMachineInfo  {0}' -f $query)

        # Return to original path
        popd

        if ($results)
        {
            $newResults = Import-CsvFieldsHeader -array $results
            $newResults
        }
        else
        {
            'No properties found.'
        }
    }

    function Get-APMachineEnvironmentMapping
    {
        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        pushd $APToolsPath

        $map = Import-CsvFieldsHeader -Array (.\dmclient.exe -c 'GetMachineEnvironmentMapping')
        $hash = @{}
        $map | sort MachineName | %{$hash[$_.MachineName.trim()]=$_.EnvironmentName.trim()}
        $hash

        popd
    }

    function Get-APMachineEnvironmentName
    {
        param
        (
            [Parameter(Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [Alias('Machine')]
                [string]$MachineName
        )

        if (-not $machineEnvironmentMapping)
        {
            $machineEnvironmentMapping = Get-APMachineEnvironmentMapping
        }

        $environment = $machineEnvironmentMapping[$MachineName]

        if ($environment)
        {
            $environment
        }
        else
        {
            Write-Warning ('No environment found for {0}.' -f $MachineName)
        }
    }

    function Get-APMachinefunctionName
    {
        param
        (
            [Parameter(Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [Alias('Machine')]
                [string]$MachineName,
            [Parameter(Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
                [string]$Environment
        )

        if (-not $Environment)
        {
            if (-not $machineEnvironmentMapping)
            {
                $machineEnvironmentMapping = Get-APMachineEnvironmentMapping
            }

            $Environment = $machineEnvironmentMapping[$MachineName]
        }

        if ($Environment)
        {
            $info = Get-APMachineInfo -Environment $Environment | where {$_.machine -eq $MachineName}
            $info.function
        }
        else
        {
            Write-Warning ('No environment found for {0}.' -f $MachineName)
        }
    }

<#
    function Start-APManualRepair
    {
        Param(
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$MachineName
        ,
        [Parameter(Mandatory=$True)]
        [ValidateSet("Query","ServiceRestart","SoftReboot","HardReboot","OSUpgrade","SoftImage","HardImage","SoftImageBurnin","HardImageBurnin","SoftWipe","HardWipe","ForceFromTriage","ForceToTriage","DestructiveUpdateMachine","Reassign")]
        [string]$RepairAction
        ,
        [Parameter(Mandatory=$True)]
        [string]$Reason
        ,
        [Alias('l')]
        [switch]$SkipLocalLimits
        ,
        [Alias('g')]
        [switch]$SkipGlobalLimits
        ,
        [Parameter(Mandatory=$False)]
        [int]$WaitInSec
        ,
        [Parameter(Mandatory=$False)]
        [int]$NumberOfRetries
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment
        )

        Begin
        {
            # Get location of dmclient.exe
            $APToolsPath = Get-APToolsPath

            # Change to $APToolsPath
            pushd $APToolsPath
        }
        Process
        {
            Foreach ($m in $MachineName)
            {
                Write-Host ("`nProcessing {0}\{1}" -f $Environment, $m )
                $query =  " -m $MachineName "
                $query += " -a $RepairAction "
                $query += ' -r "{0}" ' -f $Reason

                If ($SkipLocalLimits)
                {
                    $query += " -l "
                }

                If ($SkipGlobalLimits)
                {
                    $query += " -g "
                }

                If ($WaitInSec)
                {
                    $query += " -p $WaitInSec "
                }

                If ($NumberOfRetries)
                {
                    $query += " -n $NumberOfRetries "
                }

                If ($Environment)
                {
                    $query += " -e $Environment "
                }

                $command = ".\manualrepair.exe $query"

                $results = Invoke-Expression $command
            }
        }
        End
        {
            # Return to original path
            popd

            If ($results)
            {
                $results
            }
            Else
            {
                "No results returned."
            }
        }
    }
#>

    function Get-APLogicalDevices
    {
        $path = Join-Path $dataDir 'AutopilotData\LogicalDevices.csv'
        Import-CsvFieldsHeader -File $path
    }

    function Get-APHostedVMInfo
    {
        param
        (
            [array]$HostedMachines,
            [switch]$ReturnOnlyHealthyMachines
        )

        $vms = $HostedMachines
        $results = @()

        foreach ($vmName in $vms)
        {
            $vm = '' | select Name, Environment, Machinefunction, Status
            $vm.Name = $vmName
            $vm.Environment = Get-APMachineEnvironmentName $vmName
            $vm.Machinefunction = Get-APMachinefunctionName -MachineName $vmName -Environment $vm.Environment
            $vm.Status = (Get-APMachineInfo -Machinefunction $vm.Machinefunction -Environment $vm.Environment | where {$_.machine -eq $vmName}).Status
            $results += $vm
        }

        $results
    }

    #EndRegion AP functions

    ###############################################################################

    #EndRegion functions

    #Region Variables
    if ($env:DataDir)
    {
        $dataDir = $env:DataDir
    }
    else
    {
        $dataDir = 'd:\data'
        $env:DataDir = 'D:\data'
    }

    if ($env:AppRoot)
    {
        $appRoot = $env:AppRoot
    }
    else
    {
        $appRoot = 'd:\app'
        $env:AppRoot = 'D:\app'
    }

    $autopilotIni = Get-APAutopilotIni

    if ($env:cluster)
    {
        $clusterName = $env:cluster
    }
    else
    {
        $clusterName = $autopilotINI.Files.Cluster
    }

    if ($env:Environment)
    {
        $envName = $env:Environment
    }
    else
    {
        $envName = $autopilotINI.Files.Environment
    }

    $apToolsPath = Get-APToolsPath

    Write-Host ('`Data Dir: {0}' -f $dataDir)
    Write-Host ('App Root: {0}' -f $appRoot)
    Write-Host ('Cluster Name: {0}' -f$clusterName)
    Write-Host ('Env Name: {0}' -f $envName)
    Write-Host ('APTools Path: {0}' -f $apToolsPath)
    Get-Uptime
    # Get-APMachinefunctionName
    # Get-APMachineEnvironmentName
    # Get-APMachineInfo

    # $lbFileWarning = join-path $dataDir 'OOS_Patch_Warning.txt'
    # $lbFileError   = join-path $dataDir 'OOS_Patch_Error.txt'

    #EndRegion Variables

    If (-not (Test-Admin))
    {
        Write-Warning 'Some functions in Autopilot module require Admin privileges.`nIt is recommended that you start your PowerShell session as Administrator.`n'
    }

    #EndRegion Common Initialize     **************************

# $WriteInfoLogFile = 'd:\data\logs\local\AutopilotModule.log'

# Export-ModuleMember - leave this at the end **************************
# Export-ModuleMember -function * -Variable *
# Export-ModuleMember - leave this at the end **************************
