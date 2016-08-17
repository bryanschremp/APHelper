    function Update-APSecurityPatchingOK
    {
        Param($endTime, $releaseName, $exitCode, $version, $installPatchScriptVersion)

        $propertyValue = [string]::Format("Status=OK;Version={0};ExitCode={1};InstallPatchScriptVersion={2};ReleaseName={3};EndTime={4}",$version,$exitCode,$installPatchScriptVersion,$releaseName,$endTime)
        Write-DebugInfo "Writing machine property: $propertyValue"
        Update-APMachineProperty -MachineName $env:COMPUTERNAME -Property $AuditCategory -PropertyLevel OK -Value $propertyValue
    }

    function Get-APMasterMachines
    {
        Param ([Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][string]$Machinefunction,
            [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][string]$Environment,
            [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][switch]$ReturnSlavefunction
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        $query = ''
        if ($Machinefunction)
        {
            $query += " -f $Machinefunction "
        }

        if ($Environment)
        {
            $query += " -w $Environment "
        }

        if ($ReturnSlavefunction)
        {
            $query += " -returnSlavefunction "
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetMasterMachines $query"

        # Return to original path
        cd $PWD

        if ($results)
        {
            Import-CsvFieldsHeader -array $results
        }
        else
        {
            "No properties found."
        }
    }

    function Set-APMasterMachine
    {
        Param(
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [Alias('ComputerName')]
        [string]$MachineName
        ,
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('function')]
        [string]$Machinefunction
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Get current path, then change to $APToolsPath
        $PWD = (Get-Location).path
        cd $APToolsPath

        $query = ""
        If ($Machinefunction)
        {
            $query += " -f $Machinefunction "
        }

        If ($MachineName)
        {
            $query += " -s $MachineName "
        }

        If ($Environment)
        {
            $query += " -w $Environment "
        }

        $results = .(Join-Path $APToolsPath dmclient.exe) -c "SetMasterMachine $query"

        # Return to original path
        cd $PWD
    }


    function Get-APFailingLimitSettings {
        [CmdletBinding(DefaultParametersetName="Machinefunction")]
        Param (
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        ParameterSetName="Machinefunction")]
        [string]$Machinefunction
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        ParameterSetName="LocalPartition")]
        [string]$LocalPartition
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,
        ParameterSetName="GlobalPartition")]
        [string]$GlobalPartition
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Environment
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        pushd $APToolsPath

        $query = ""
        If ($Environment)
        {
            $query += " -w $Environment "
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetFailingLimitSettings $query"

        # Return to original path
        popd

        If($results)
        {
            $return = Import-CsvFieldsHeader -array $results

            foreach ($r in $return)
            {
                If ($r.MachineList)
                {
                    $r.MachineList = @($r.MachineList.toString().split("|"))
                }

                $r | Add-Member -Name UnhealthyMachineCount -Value $($r.MachineList.Count - $r.NumberOfMachinesHealthyForFailingLimits) -MemberType NoteProperty -Force
            }

            If ($Machinefunction)
            {
                $return | where {$_.Kind -eq "Machinefunction" -and $_.Partition -eq $Machinefunction}
            }
            ElseIf ($LocalPartition)
            {
                $return | where {$_.Kind -eq "LocalPartition"  -and $_.Partition -eq $LocalPartition}
            }
            ElseIf ($GlobalPartition)
            {
                $return | where {$_.Kind -eq "GlobalPartition" -and $_.Partition -eq $GlobalPartition}
            }
            Else
            {
                $return
            }
        }
        Else
        {
            Write-Warning "No FailingLimitSettings found for specified parameters."
        }
    }
    

    function Get-APRepairList
    {
        Param(
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [ValidateSet("Recover","NoOp","Reboot","OSUpgrade","BIOSUpgrade","FirmwareUpgrade","SoftRebootRollout","Image","ImageBurnin","Triage","RMA","ConfigurationProvision","DIPDeploy","WipeAndRMA","SoftWipe","HardWipe","AcceptanceTest")][string]$RepairAction,
        [Parameter(Mandatory=$False, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)][string]$Environment
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath

        # Change to $APToolsPath
        pushd $APToolsPath

        $query = ""
        If ($RepairAction)
        {
            $query += " -r $RepairAction "
        }

        If ($Environment)
        {
            $query += " -w $Environment "
        }

        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetRepairList $query"

        # Return to original path
        popd

        If($results)
        {
            Import-CsvFieldsHeader -array $results
        }
        Else
        {
            "No properties found."
        }
    }


<#
    function Get-APDeadTriageMachines
    {
        Param ([switch]$IncludeNonStdHWSKUs)
        $query = @"
--  ******* Cluster-Machine ********
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
  Cluster           VARCHAR(256),
  Environment       VARCHAR(200),
  Machinefunction   VARCHAR(512)  NOT NULL,
	MachineName       VARCHAR(512)  NOT NULL,
  SKU               VARCHAR(50)   NULL,
  Status            CHAR(1)       NULL,
	Repair            VARCHAR(512)  NULL,
  RepairRequestedAt DateTime
)

declare cur_dbs cursor static for
select name
  from master..sysdatabases
  where name like 'dmdata%'
open cur_dbs
  fetch next  from cur_dbs into @dbname
while (@@fetch_status = 0)
begin
  declare @level varchar(20)

  SET @execStmt = '
USE '+@dbname+';
DECLARE @Environment Varchar(100)
SELECT  @Environment = Environment from dataSyncSystem
DECLARE @Cluster Varchar(100)
SELECT  @Cluster = cluster from dataSyncSystem

INSERT #clusterTemp
Select
	 @Cluster as Cluster
	,@Environment as Environment
	,m.machinefunction
	,m.machineName
	,m.SKU
	,m.status
	,m.repair
	,m.repairRequestedAt
from machines m (nolock)
where
	  m.status = ''D''
  and m.repair = ''triage''
  and m.machinefunction not in (''coreSwitch'',''coreTS'',''podPower'',''podSwitch'',''podTS'')
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
	fetch next  from cur_dbs into @dbname
end
close cur_dbs
deallocate cur_dbs

SELECT *
FROM #clusterTemp
Order By Cluster, Environment, machinefunction, machineName

drop table #clusterTemp
"@
        $results = Get-APCockpitData -Cluster $clusterName -Environment Autopilot -Query $query -UrlEncodeQuery

        foreach ($r in $results)
        {
            $r | add-member -Name RepairRequestedAt -MemberType NoteProperty -Value $(Get-Date $r.RepairRequestedAt) -Force
        }

        if ($IncludeNonStdHWSKUs)
        {
            $results
        }
        else
        {
            $results | Where {$_.SKU -ne 'NonStdHW'}
        }
    }

    function Repair-APDeadTriageMachines
    {
    }
#>

    function Get-APRolloutProgress
    {
        Param (
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [Alias('n')]
        [string]$RolloutName
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('f')]
        [string]$Machinefunction
        ,
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('w')]
        [string]$Environment
        )

        # Get location of dmclient.exe
        $APToolsPath = Get-APToolsPath
        pushd $APToolsPath

        $query = ""
        If ($RolloutName)
        {
            $query += " -n $RolloutName "
        }

        If ($Machinefunction)
        {
            $query += " -f $Machinefunction "
        }

        If ($Environment)
        {
            $query += " -w $Environment "
        }

        # Call dmclient
        $results = .(Join-Path $APToolsPath dmclient.exe) -c "GetRolloutProgress $query"

        # Return to original path
        popd

        If ($results)
        {
            $rollout = Import-CsvFieldsHeader -array $results
            If ($rollout)
            {
                $rollout
            }
            Else
            {
                Write-Verbose "No rollout in progress."
            }
        }
        Else
        {
            "No rollouts found."
        }
    }

    function Test-APInRollout
    {
        Param(
        [Parameter(Mandatory=$False,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [Alias('Name')]
        [Alias('ComputerName')]
        [string]$MachineName = $env:COMPUTERNAME
        ,
        [switch]$Shared
        )

        $Machinefunction  = (Get-APMachinefunction -MachineName $MachineName)
        $scaleUnit        = (Get-APMachinefunction -MachineName $MachineName -AllProperties).ScaleUnit
        $rolloutProgress  =  Get-APRolloutProgress -Machinefunction $machinefunction

        $myRolloutProgress = $rolloutProgress | Where {$_.scaleunit -eq $scaleUnit}

        If ($myRolloutProgress.rolloutStatus -eq "inRollout" -and $myRolloutProgress.rolloutAction -eq "SwitchService")
        {
            $inRollout = $true
        }

        If ($Shared)
        {
            If (($myRolloutProgress.rolloutName -like "Shared.*") -and $inRollout)
            {
                $true
            }
        }
        ElseIf ($inRollout)
        {
            $true
        }
    }

    function Get-APHostedMFInfo
    {
        Param ([array]$HostedMachines, [int]$MinProductionMFSize, [string]$MachineProperty, [string]$PropertyLevel)

        $hostedVMs = @(Get-APHostedVMInfo -HostedMachines $hostedMachines)
        $groupedMFs = @($hostedVMs | group Environment, Machinefunction)
        $results = @()

        Foreach ($mf in $groupedMFs)
        {
            $healthyVMs,$unhealthyVMs = @(), @()

            $env          = (($mf.Name).split(",").trim())[0]
            $mfName       = (($mf.Name).split(",").trim())[1]
            $allVMs       = @($mf.Group | select -ExpandProperty Name)
            $healthyVMs   = @($mf.group | ? {$_.Status -eq "H"} | select -ExpandProperty Name)
            $unhealthyVMs = @($mf.group | ? {$_.Status -ne "H"} | select -ExpandProperty Name)
            $deadVMs      = @($mf.group | ? {$_.Status -eq "D"} | select -ExpandProperty Name)

            $NumberOfHealthyMachinesAffectedByThisMaintenance = $healthyVMs.Count

            $mfFLS = Get-APFailingLimitSettings -Environment $env -Machinefunction $mfName

            $CurrentFailingPercent = 100 * ([int]$mfFLS.UnhealthyMachineCount/([int]$mfFLS.MachineList.count))
            $CurrentFailingPercent = [math]::Round($CurrentFailingPercent, [midpointrounding]::AwayFromZero )

            $ProposedFailingPercent = 100 * (($NumberOfHealthyMachinesAffectedByThisMaintenance + [int]$mfFLS.UnhealthyMachineCount)/([int]$mfFLS.MachineList.count))
            $ProposedFailingPercent = [math]::Round($ProposedFailingPercent, [midpointrounding]::AwayFromZero )

            $machinesWithMachineProperty = @(Get-APMachineProperty -Environment $env -Property $machineProperty | Where {$_.level -eq $PropertyLevel -and $mfFLS.MachineList -contains $_.MachineName } | select -ExpandProperty MachineName)

            $RepairsPossible = [int]$mfFLS.DestructivePercentage -ge [int]$ProposedFailingPercent

            # Allow repairs, one at a time, if the MF has small number of machines
            If ($RepairsPossible -or (($machinesWithMachineProperty.count -eq 0)-and ($mfFLS.MachineList.count -lt $MinProductionMFSize) ) )
            {
                $RepairsPossible = $true
            }

            # Allow repairs, if the current Machine is Dead
            If (-not (Compare-object $allVMs $deadVMs))
            {
                $RepairsPossible = $true
            }

            If (Get-APRolloutProgress -Environment $env -Machinefunction $mfName)
            {
                $inRollout = $true
                $RepairsPossible = $false
            }
            Else
            {
                $inRollout = $false
            }

            $mfInfo = "" | Select Name, Environment, Machinefunction, InRollout, `
            Count, TotalMachineCount, UnhealthyMachineCount, `
            Machines, DeadMachines, `
            HealthyMachines, UnhealthyMachines, `
            machinesWithMachineProperty, RepairsPossible, `
            CurrentFailingPercent, ProposedFailingPercent, `
            FailingMachineLimit, FlsKind, `
            NumberOfHealthyMachinesAffectedByThisMaintenance, `
            NumberOfMachinesBeingRepairedForFailingLimits, `
            NumberOfMachinesHealthyForFailingLimits

            $mfInfo.Name                    = $mf.Name.replace(", ","\")
            $mfInfo.Environment             = $env
            $mfInfo.Machinefunction         = $mfName
            $mfInfo.InRollout               = $inRollout
            $mfInfo.Count                   = $mf.count
            $mfInfo.TotalMachineCount       = $mfFLS.MachineList.Count
            $mfInfo.UnhealthyMachineCount   = $mfFLS.UnhealthyMachineCount
            $mfInfo.Machines                = $allVMs
            $mfInfo.DeadMachines            = $deadVMs
            $mfInfo.machinesWithMachineProperty  = $machinesWithMachineProperty
            $mfInfo.HealthyMachines         = $healthyVMs
            $mfInfo.UnHealthyMachines       = $unhealthyVMs
            $mfInfo.RepairsPossible         = $RepairsPossible
            $mfInfo.CurrentFailingPercent   = $CurrentFailingPercent
            $mfInfo.ProposedFailingPercent  = $ProposedFailingPercent
            $mfInfo.FailingMachineLimit     = $mfFLS.DestructivePercentage
            $mfInfo.FlsKind                 = $mfFLS.Kind
            $mfInfo.NumberOfHealthyMachinesAffectedByThisMaintenance = $NumberOfHealthyMachinesAffectedByThisMaintenance
            $mfInfo.NumberOfMachinesBeingRepairedForFailingLimits    = $mfFLS.NumberOfMachinesBeingRepairedForFailingLimits
            $mfInfo.NumberOfMachinesHealthyForFailingLimits          = $mfFLS.NumberOfMachinesHealthyForFailingLimits

            $results += $mfInfo
        }

        return $results
    }
    function Set-APInService {
        Param (
        $AuditCategory
        , [switch]$SkipCustomServiceScript
        )
        $machineProperty = "$($AuditCategory)LBProbeStatus"
        $serviceType = "InServiceScript"

        If ($SkipCustomServiceScript)
        {
            Write-DebugInfo "Skipping Invoke-APCustomServiceScript"
        }
        Else
        {
            Try
            {
                Invoke-APCustomServiceScript -serviceType $serviceType
            }
            Catch
            {
                $message = "Error while calling $serviceType. Exiting without performing custom InService. `nError: $($error[0])"
                Update-APMachineProperty -Level Warning -Property "$auditCategory-CustomInServiceScript" -Value $message
                Write-ErrorInfo -message $message
            }
        }

        If (Test-Path $lbFileWarning -ErrorAction SilentlyContinue)
        {
            $lbFileWarningCheck = Select-String -path "$lbFileWarning" -pattern $AuditCategory
            If ($lbFileWarningCheck)
            {
                #Remove as it is ours
                Write-DebugInfo "Deleting LBw file to force PlatformHealthMonitor to return HTTP 200 response and resume connections to this server"
                del $lbFileWarning -Force -ErrorAction SilentlyContinue
            }
            Else
            { #Leave because it is not ours
                Write-DebugInfo "Not Deleting LB Warning file as it was set by another service"
            }
        }

        If (Test-Path $lbFileError -ErrorAction SilentlyContinue)
        {
            $lbFileErrorCheck = Select-String -path $lbFileError -pattern $AuditCategory
            If ($lbFileErrorCheck)
            {
                #Remove as it is ours
                Write-DebugInfo "Deleting LBe file to force PlatformHealthMonitor to return HTTP 200 response and resume connections to this server"
                del $lbFileError -Force -ErrorAction SilentlyContinue
            }
            Else
            {
                #Leave because it is not ours
                Write-DebugInfo "Not Deleting LB Error file as it was set by another service"
            }
        }

        Write-DebugInfo "Updating $machineProperty machine property in DM to 'In Service' (IS)"
        Update-APMachineProperty -Property $machineProperty -PropertyLevel OK -value IS
    }

    function Set-APOutOfService
    {
        Param(
        $newMachine
        , $AuditCategory
        , [switch]$skipCustomServiceScript
        )

        $machineProperty = "$($AuditCategory)LBProbeStatus"
        $serviceType = "OutOfServiceScript"

        If ($skipCustomServiceScript)
        {
            Write-DebugInfo "Skipping Invoke-APCustomServiceScript"
        }
        Else
        {
            Try
            {
                Invoke-APCustomServiceScript -serviceType $serviceType
            }
            Catch
            {
                $message = "Error while calling $serviceType. Exiting without patching. `nError: $($error[0])"
                Update-APMachineProperty -Level Warning -Property "$auditCategory-CustomOutOfServiceScript" -Value $message
                Write-ErrorInfo -message $message
                SleepAndExit
            }
        }

        If ($newMachine)
        {
            If (-not (Test-Path $lbFileWarning))
            {
                If (-not (Test-Path $lbFileError))
                {
                    Write-DebugInfo "Draining machine to prep for first Maintenance run"
                    $oosText = (Get-Date).toString()
                    $oosText += " - $AuditCategory - Writing file to force PlatformHealthMonitor to return HTTP 600 response and force connection draining to this server"
                    Set-Content -Path $lbFileWarning -Value $oosText -Force
                }
            }

            Write-DebugInfo "Updating $machineProperty DM machine property to 'Out Of Service' with Warning Level"
            Update-APMachineProperty -PropertyLevel Warning -Property $machineProperty -Value OOS
        }
        Else
        {
            If (-not (Test-Path $lbFileWarning))
            {
                If (-not (Test-Path $lbFileError))
                {
                    Write-DebugInfo "Setting Error MachineProperty $machineProperty and Draining machine to prep for next Maintenance run"
                    $oosText = (Get-Date).toString()
                    $oosText += " - $AuditCategory - Writing file to force PlatformHealthMonitor to return HTTP 600 response and force connection draining to this server"
                    Set-Content -Path $lbFileError -Value $oosText -Force
                }
            }

            Write-DebugInfo "Updating $machineProperty DM machine property to 'Out Of Service' with Error Level"
            Update-APMachineProperty -PropertyLevel Error -Property $machineProperty -Value OOS
        }

        $script:DrainTimeStart = Get-Date
    }

    function Add-functionToRemoteSessions
    {
        [CmdletBinding()]
        param([Parameter( Mandatory = $true, Position = 0 )][ValidateNotNullOrEmpty()][System.Management.Automation.Runspaces.PSSession[]] $Sessions,
            [Parameter( Mandatory = $true, Position = 1, ValueFromPipeline = $true )][ValidateNotNull()][System.Management.Automation.functionInfo] $functionInfo
        )

        begin
        {
        }
        end
        {
        }
        process
        {
            try
            {
                $fName = $functionInfo.Name
                $fDef = $functionInfo.Definition
                Invoke-Command -Session $Sessions -ErrorAction Stop -ScriptBlock {
                    Set-Item -Path function:\$using:fName -Value $using:fDef | Out-Null
                }
            }
            finally
            {
            }
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

    function Get-VMHost
    {
        try
        {
            $item = get-item 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction SilentlyContinue
            $vmHost = $item.GetValue('PhysicalHostName').split('.')[0]
            return $vmHost
        }
        catch
        {
            return 0
        }
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
