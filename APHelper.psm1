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
            [int]$EventID = 50,
            [string]$Severity = 'i',
            [string]$Message,
            [switch]$NoApAudit
        )

        # To write to a log file, make sure that $WriteInfoLogFile is set to a valid path
        # for AP, use "D:\data\logs\local\[YourLogFileName].log

        $functionName = (Get-PSCallStack)[2].command

        if ($WriteInfoLogFile)
        {
            $time = Get-Date -Format s
            $Severity = $Severity.Substring(0,1).ToLower()
            $auditMessage = [string]::Format('{0}, {1}, {2}, [{3}], {4}', $Severity, $time, $EventID, $functionName, $Message)
            $auditMessage | Out-File -Append -FilePath $WriteInfoLogFile
        }

        switch ($Severity)
        {
            'i' {
                if ($Verbose -or $force)
                {
                    Write-Host ('{0}: {1}' -f $Severity, $Message)
                }
            }
            'w' {
                Write-Host ('{0}: {1}' -f $Severity, $Message) -BackgroundColor DarkBlue -ForegroundColor Yellow
            }
            'e' {
                Write-Host ('{0}: {1}' -f $Severity, $Message) -BackgroundColor DarkBlue -ForegroundColor Red
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
            Write-Info -EventID $Id -Severity 'i' -Message $Message -NoApAudit:$NoApAudit
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

        Write-Info -EventID $Id -Severity 'w' -Message $Message -NoApAudit:$NoApAudit
    }

    function Write-ErrorInfo
    {
        param
        (
            [string]$Message,
            [int]$Id = 300,
            [switch]$NoApAudit
        )

        Write-Info -EventID $Id -Severity 'e' -Message $Message -NoApAudit:$NoApAudit
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
            $File,
            $String,
            $Array
        )

        if ($String -is [string])
        {
            $content = $String.split("`r`n")
        }
        elseif ($array -is [array])
        {
            $content = $Array
            # Write-Host $content
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
            Write-Host 'Import-CsvFieldsHeader found no valid content in the file, string or array specified.'
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
                Write-Host ('Found {0}' -f $HostParam)
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
            $msg = ('Cannot create folder [{0}]. Network locations are not supported.' -f $path)
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
            $msg = ('Cannot create folder. Root folder [{0}] is missing.' -f $rootFolder)
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
            [string]$Computer = $env:COMPUTERNAME
        )

        if ($Computer -eq $env:COMPUTERNAME)
        {
            $OS = Get-WmiObject -Class Win32_OperatingSystem -Computer $Computer
            $osInstallDate = $OS.ConvertToDateTime($OS.Installdate)
            Write-Info -Message ('{0} OSInstallDate: {1}' -f $Computer, $osInstallDate)
        }
        elseif (Test-Connection -ComputerName $Computer -Count 1 -ErrorAction 0)
        {
            $OS = Get-WmiObject -Class Win32_OperatingSystem -Computer $Computer
            $osInstallDate = $OS.ConvertToDateTime($OS.Installdate)
            Write-Info -Message ('{0} OSInstallDate: {1}' -f $Computer, $osInstallDate)
        }
        else
        {
            Write-Host ('{0} is offline' -f $Computer)
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
                ValueFromPipelineByPropertyName = $True)]$ServiceName,
            [Parameter(Mandatory = $False, 
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]$MachineName,
            [switch]$ExcludeShared
        )

        if ($MachineName)
        {
            $serviceStatusCsv = join-path \\$MachineName 'data\servicemanager\servicestatus.csv'
        }
        else
        {
            $dataDir = Get-APDataDir
            $serviceStatusCsv = join-path $dataDir 'servicemanager\servicestatus.csv'
        }

        $serviceStatus = Import-CsvFieldsHeader -File $serviceStatusCsv
        # Write-Host $serviceStatus

        if ($ServiceName)
        {
            $serviceStatus | where {$_.Service -match "^$ServiceName\."}
        }
        elseif($ExcludeShared)
        {
            $serviceStatus | where {$_.VE -ne 'Shared' -and $_.VE -notmatch 'Autopilot-AutopilotClient'}
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

        $appRoot = Get-APAppRoot
        $service = Get-APServiceStatus | where {$_.Service -match "^$Name\."}

        if ($service)
        {
            # Combine the serviceName with the path contained in env:AppRoot
            $servicePath = join-path $appRoot $service.Service
            return $servicePath
        }
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

    function Get-APToolsPath
    {
        Get-AutopilotServicePath -Name 'APTools'
    }

    function Get-APEnvironmentIni
    {
        Convert-IniFile -File (join-path $dataDir 'autopilotdata\environment.ini.flattened.ini')
    }

    function Get-APAutopilotIni
    {
        Convert-IniFile -File (join-path $appRoot 'autopilot.ini')
    }

    function Get-APSharedIni
    {
        Convert-IniFile -File (join-path $dataDir 'autopilotdata\shared.ini.flattened.ini')
    }

    function Get-APServiceList
    {
        param
        (
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

        # Get location of dmclient.exe
        $APToolsPath = Get-AutopilotServicePath 'APTools'

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        $query = ''
        If ($MachineName)
        {
            $query += (' -s {0} ' -f $MachineName)
        }

        If ($Environment)
        {
            $query += (' -w  {0} ' -f $Environment)
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c ('GetServiceList {0}' -f $query)
        # TODO - consider adding "| Out-Null" in the line above

        # Return to original path
        cd $PWD

        If ($results)
        {
            Convert-IniText -Text $results
        }
        Else
        {
            'No service list info found.'
        }
    }

    function Update-APMachineProperty
    {
        param
        (
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
        $APToolsPath = Get-AutopilotServicePath 'APTools'

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        # Get Temp file
        if ($TempFileName)
        {
            if (-not (Test-Path $TempFileName -ErrorAction SilentlyContinue))
            {
                $tempFileName = [System.IO.Path]::GetTempFileName()
            }
        }
        else
        {
            $tempFileName = [System.IO.Path]::GetTempFileName()
        }

        # Save inputs into an ASCII csv file
        [string]::join(',', ($MachineName, $Level, $Property, $Value)) | Out-File -Encoding ASCII -FilePath $tempFileName -Force -Append:$Append

        if (-not $NoSubmit)
        {
            $query = ''
            if ($Environment)
            {
                $query += (' -w {0} ' -f $Environment)
            }

            # Call dmclient
            .(Join-Path $APToolsPath dmclient.exe) -c ('UpdateMachineProperty {0}' -f $query) -i $tempFileName | Out-Null

            # Delete temp file
            del $tempFileName
        }

        # Return to original path
        cd $PWD
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

        if ($Status)
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
            $newResults = Import-CsvFieldsHeader -Array $results
            $newResults
        }
        else
        {
            'No properties found.'
        }
    }

    <#
    Does not work.
    Returns "The client identity 'BN1SCH010104238,API.ODCOR000P001-Prod-Bn1.BN1,API.onedrive\ODProductionCore.BN1,API.onedrive\ODProd
    uctionDeployMgr.BN1,API.onedrive\ODProductionSimsPrm.BN1' does not satisfy the default ACL 'APMF\*.Autopilot.*'. For thi
    s command, no additional permissions can be configured by the target environment.
    Bad Status code returned by server: 4, http response: 401"
    #>
    function Get-APMachineEnvironmentMapping
    {
        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        pushd $APToolsPath

        $map = Import-CsvFieldsHeader -Array (.\dmclient.exe -c "GetMachineEnvironmentMapping")
        Write-Host $map

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

    function Get-APLogicalDevices
    {
        $path = Join-Path $dataDir 'AutopilotData\LogicalDevices.csv'
        Import-CsvFieldsHeader -File $path
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

    function Restart-APService
    {
        param
        (
            [Parameter(Mandatory = $True,
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [Alias('Service')]
                [string]$ServiceName,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName = 'Machine')]
                [Alias('Machine')]
                [string]$MachineName = $env:COMPUTERNAME,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName = 'Machinefunction')]
                [string]$Machinefunction,
            [Parameter(Mandatory = $True,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName = 'Machinefunction')]
                [Alias('Delay')]
                [int]$DelaySeconds,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [switch]$ForceRestart,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                ParameterSetName = 'Machinefunction')]
                [string]$Environment = $envName
        )

        # Get location of svcmgrclient.exe
        $APToolsPath = Get-AutopilotServicePath 'APTools'

        # Change to $APToolsPath
        pushd $APToolsPath

        if ($Machinefunction)
        {
            $machines = @(Get-APMachineInfo -Environment $Environment -Machinefunction $Machinefunction | select -ExpandProperty machine)
        }
        else
        {
            $machines = @($MachineName)
        }

        Write-Host ('Machines found: {0}' -f [string]::Join(',', $machines))

        if ($ForceRestart)
        {
            $time = '-t 0'
        }
        else
        {
            $time = ''
        }

        $i=0

        foreach ($machine in $machines)
        {
            $i += 1
            Write-Host ('Attempting to restart {0} on {1} ({2} of {3} machines)' -f $ServiceName, $machine, $i, $machines.count)
            
            # Call svcmgrclient
            .(Join-Path $APToolsPath svcmgrclient.exe) -s $machine -c "stopservice -s $ServiceName $time" 2>&1>$null

            if ($Machinefunction)
            {
                Write-Host ('Sleeping for {0} before proceeding with next machine.' -f $delaySeconds)
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
    function Restart-APServiceByScaleUnit
    {
        param
        (
            [Parameter(Mandatory = $True,
                Position = 1,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [Alias('Service')]
                [string]$ServiceName,
            [Parameter(Mandatory = $True,
                Position = 2,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [Alias('MF')]
                [string]$Machinefunction,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                $MachineFilter,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [Alias('MinHealthy')]
                [int]$MinMachineHealthyPercent = 95,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [switch]$DontWaitForServiceToRestart,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [Alias('SU')]
                $ScaleUnit,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [int]$MachineDelayInSeconds = 5,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [int]$ScaleUnitDelayInSeconds = 1200,
            [Parameter(Mandatory = $False,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True)]
                [string]$Environment = $envName
        )

        $scaleUnits = @()

        if ($scaleUnit -eq $null)
        {
            $machines = Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment
            
            if ($machines)
            {
                $scaleUnits = @($machines | select -Unique -ExpandProperty Row)
            }
            else
            {
                Write-Error ('No machines found to process for {0}\{1}.' -f $environment,$Machinefunction)
                return
            }
        }
        else
        {
            $scaleUnits = @($ScaleUnit)
        }

        if ($scaleUnits -or $scaleUnit -eq 0)
        {
            Write-Host ('ScaleUnits to be processed: {0}' -f [string]::Join(', ',$scaleUnits))
            Write-Host ('DontWaitForServiceRestart before proceeding to next machine in same scale unit: {0}' -f $DontWaitForServiceToRestart)
            Write-Host ('MinMachineHealthyPercent before moving to next scale unit: {0}' -f $MinMachineHealthyPercent)
            Write-Host ('ScaleUnitDelayInSeconds between scale units AFTER machines are healthy: {0}' -f $ScaleUnitDelayInSeconds)
            Write-Host ('MachineDelayInSeconds between machines: {0}' -f $MachineDelayInSeconds)
        }
        else
        {
            Write-Error ('No scale units found to process for {0}\{1}.' -f $environment,$Machinefunction)
            Return
        }

        $results = @()

        $lastScaleUnit = $scaleUnits | select -last 1

        if ($MachineFilter)
        {
            if ($MachineFilter.GetType().IsArray)
            {
                # Do nothing this is what we want
                Write-Host 'MachineFilter appears to be an array of machines.'
            }
            elseif ((Test-Path $MachineFilter))
            {
                Write-Host ('Getting list of machines to filter from the file: {0}' -f {$MachineFilter})
                $MachineFilter = gc $MachineFilter | where {$_}
            }
            elseif (($MachineFilter.GetType().IsString) -and $MachineFilter -match ';|,')
            {
                Write-Host 'Getting the list of machines to filter from the provided string.'
                $MachineFilter = $MachineFilter.Split(',;') | where {$_}
            }
            else
            {
                Write-Error 'MachineFilter does not appear to be a valid array, file, or comma separated list of machines.'
                return
            }

            $MachineFilter = $MachineFilter.Trim() | where {$_} | select -Unique

            Write-Host ('Number of unique machines to include found in MachineFilter: {0}' -f $MachineFilter.count)
        }

        if ($ServiceName -match '\.')
        {
            $message = @"
    The ServiceName specified {0} contains a period '.', you are probably not using the correct name for the service.
    ServiceName parameter
    The name of the AP service to be restarted on each machine.
    Note: Do not include the build label.
    Correct:   WLS_Colorado
    Incorrect: WLS_Colorado.BL__ship_onedrive_hotfix_19_047_0707_5004_20160808172718812
"@
            Write-Warning ($message -f $ServiceName)
        }

        foreach ($su in $scaleUnits)
        {
            $machines = @(get-apmachineinfo -machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})

            if ($machines.count -eq 0)
            {
                Write-Error ('No machines found in specified scale unit: {0}.' -f $su)
                return
            }

            if ($MachineFilter)
            {
                $machines = $machines | foreach {if ($MachineFilter -contains $_.machine){$_}}
                Write-Host ('Machines after applying MachineFilter: {0}' -f [string]::Join('; ', $machines.machine))
            }

            Write-Host ('`n`nStarting ScaleUnit: {0}' -f $su)
            Write-Host ('Machine count: {0}' -f $machines.count)
            $lastMachineName = ($machines | select -last 1).machine

            foreach ($machine in $machines)
            {
                $tryRestart = $true

                $machineName = $machine.machine
                Write-Host ('`nConnecting to {0} ...' -f $machineName)

                $machineInfo = '' | Select Environment, Machinefunction, ScaleUnit, MachineName, ServiceName, MachineStatusStart, MachineStatusEnd, ServiceStatusStart, ServiceStatusEnd, RestartTime, Result
                $machineInfo.Environment = $Environment
                $machineInfo.Machinefunction = $Machinefunction
                $machineInfo.ScaleUnit = $su
                $machineInfo.MachineName = $machineName
                $machineInfo.ServiceName = $ServiceName
                $machineInfo.MachineStatusStart = $machine.Status

                if (Test-Connection $machineName -Count 2 -quiet)
                {
                    $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName
                }
                else
                {
                    Write-Warning ('Could not connect to machine {0}.' -f $machineName)
                    $machineInfo.Result = 'Offline'
                    $tryRestart = $false
                }

                if ($machineInfo.Result -ne 'Offline')
                {
                    if (-not $service)
                    {
                        Write-Warning ('Service {0} not found on {1}.' -f $ServiceName, $machineName)
                        $machineInfo.Result = 'Service Not Found'
                        $tryRestart = $false
                    }
                    elseif ($service.Status -eq 'disabled')
                    {
                        Write-Warning ('Service {0} disabled on {1}.' -f $ServiceName, $machineName)
                        $machineInfo.Result = 'Service Disabled'
                        $tryRestart = $false
                    }
                    elseif (-not ($service.Status -eq 'running'))
                    {
                        Write-Warning ('Service {0} not running on {1}. Will try to start it.' -f $ServiceName, $machineName)
                    }

                    if ($tryRestart)
                    {
                        $machineInfo.ServiceStatusStart = $service.Status
                        Write-Host ('Restarting {0} on {1}...' -f $ServiceName, $machineName)
                        $machineInfo.RestartTime = Get-Date
                        Restart-APService -ServiceName $ServiceName -MachineName $machineName -ForceRestart

                        $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName

                        if (-not $DontWaitForServiceToRestart)
                        {
                            Write-Host 'Waiting for service to start.' -NoNewline
                            while ($service.status -ne 'running')
                            {
                                start-sleep 5
                                Write-Host '.' -NoNewline

                                $service = Get-APServiceStatus -ServiceName $ServiceName -MachineName $machineName
                            }

                            $machineInfo.Result = 'Service Restarted Successfully'
                        }
                        else
                        {
                            $machineInfo.Result = 'Service Restart Called'
                        }

                        $machineInfo.ServiceStatusEnd = $service.status
                        $machineInfo.MachineStatusEnd = (Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment | where {$_.machine -eq $machineName} ).Status
                    }
                }

                if ($machineName -ne $lastMachineName)
                {
                    Write-Host ('`nSleeping for {0} seconds before next machine...' -f $MachineDelayInSeconds)
                    Start-Sleep $MachineDelayInSeconds
                }

                $results += $machineInfo
            }

            if ($su -ne $lastScaleUnit)
            {
                Write-Host ('`nSleeping for {0} seconds before next scale unit...' -f $ScaleUnitDelayInSeconds)
                Start-Sleep $ScaleUnitDelayInSeconds
            }

            if ($MinMachineHealthyPercent -ne 0)
            {
                $suStatus = @(Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})
                $healthyCount = @($suStatus | where {$_.status -eq "H"}).count
                $HealthyPercent = [math]::Floor([Decimal]($healthyCount / $suStatus.count * 100))

                if ($healthyPercent -lt $MinMachineHealthyPercent)
                {
                    while ($healthyPercent -lt $MinMachineHealthyPercent)
                    {
                        Write-Host ('Waiting for machines in scale unit {0} to get healthy. Currently {1}% of minimum {2}%.' -f $su, $healthyPercent, $MinMachineHealthyPercent)
                        Start-Sleep 15
                        $suStatus = @(Get-APMachineInfo -Machinefunction $Machinefunction -Environment $Environment | where {$_.row -eq $su})
                        $healthyCount = @($suStatus | where {$_.status -eq "H"}).count
                        $HealthyPercent = [math]::Floor([Decimal]($healthyCount / $suStatus.count * 100))
                    }
                }

                foreach ($s in $suStatus)
                {
                    # update the machine status in $results
                    $m = $s | where {$_.MachineName -eq $s.machine}
                    $m.MachineStatusEnd = $s.status
                }
            }

            Write-Host 'Proceeding to next scale unit'
        }

        Write-Host '***********************'
        Write-Host '*** Summary Results ***'
        Write-Host '***********************'
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
    
    #EndRegion Variables

    If (-not (Test-Admin))
    {
        Write-Warning 'Some functions in Autopilot module require Admin privileges.`nIt is recommended that you start your PowerShell session as Administrator.`n'
    }

#EndRegion Common Initialize     **************************

#Region Test calls

$Verbose = $true
Write-Host
Write-Info -Message ('Data Dir: {0}' -f $dataDir) -Severity 'i'
Write-Info -Message ('App Root: {0}' -f $appRoot)
Write-Info -Message ('Cluster Name: {0}' -f$clusterName)
Write-Info -Message ('Env Name: {0}' -f $envName)
Write-DebugInfo -Message 'Test Debug info' -Id 20
Write-WarningInfo -Message 'Test Warning info' -Id 100
Write-ErrorInfo -Message 'Test Error info' -Id 200
    # Convert-IniFile
    # Convert-IniText
    # Get-IniSetting
    # Update-VariablesFromIni
    # Get-RegValue
    # New-RegKey
    # Set-RegValue
    # Remove-RegValue
    # Get-MyFileInfo
# Import-CsvFieldsHeader
    # Get-DNSHost
    # New-Folder
# WMIDateStringToDate
Get-Uptime
Get-OSInstallDate
Test-Admin
    # Get-URLDecode
    # Get-URLEncode
# Get-APAppRoot
# Get-APDataDir
# Get-APServiceStatus
Get-AutopilotServicePath
Get-APMachinefunction
Write-Info -Message ('APTools Path: {0}' -f $apToolsPath)
# Get-APEnvironmentIni
# Get-APAutopilotIni
# Get-APSharedIni
# Get-APServiceList  -MachineName $env:COMPUTERNAME -Environment $envName
    # Update-APMachineProperty
# Get-APMachineInfo -Status 'H'
    # NO WORKIE: Get-APMachineEnvironmentMapping
    # NO WORKIE: Get-APMachineEnvironmentName -MachineName $env:COMPUTERNAME
Get-APMachinefunctionName -MachineName $env:COMPUTERNAME -Environment $envName
# Get-APLogicalDevices
    # Get-APCockpitData

#EndRegion Test calls

# $WriteInfoLogFile = 'd:\data\logs\local\AutopilotModule.log'

# Export-ModuleMember - leave this at the end **************************
# Export-ModuleMember -function * -Variable *
# Export-ModuleMember - leave this at the end **************************
