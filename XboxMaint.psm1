
	<#
	.SYNOPSIS
	Returns the encoding type of the file
	From http://poshcode.org/3252
	.DESCRIPTION
	Returns the encoding type of the file.  It first attempts to determine the
	encoding by detecting the Byte Order Marker using Lee Holmes' algorithm
	(http://poshcode.org/2153).  However, if the file does not have a BOM
	it makes an attempt to determine the encoding by analyzing the file content
	(does it 'appear' to be UNICODE, does it have characters outside the ASCII
	range, etc.).  If it can't tell based on the content analyzed, then
	it assumes it's ASCII. I haven't checked all editors but PowerShell ISE and
	PowerGUI both create their default files as non-ASCII with a BOM (they use
	Unicode Big Endian and UTF-8, respectively).  If your file doesn't have a
	BOM and 'doesn't appear to be Unicode' (based on my algorithm*) but contains
	non-ASCII characters after index ByteCountToCheck, the file will be incorrectly
	identified as ASCII.  So put a BOM in there, would ya!

	For more information and sample encoding files see:
	http://danspowershellstuff.blogspot.com/2012/02/get-file-encoding-even-if-no-byte-order.html
	And please give me any tips you have about improving the detection algorithm.

	*For a full description of the algorithm used to analyze non-BOM files,
	see "Determine if Unicode/UTF8 with no BOM algorithm description".
	.PARAMETER Path
	Path to file
	.PARAMETER ByteCountToCheck
	Number of bytes to check, by default check first 10000 character.
	Depending on the size of your file, this might be the entire content of your file.
	.PARAMETER PercentageMatchUnicode
	If pecentage of null 0 value characters found is greater than or equal to
	PercentageMatchUnicode then this file is identified as Unicode.  Default value .5 (50%)
	.EXAMPLE
	Get-FileEncoding -Path .\SomeFile.ps1 1000
	Attempts to determine encoding using only first 1000 characters
	BodyName          : unicodeFFFE
	EncodingName      : Unicode (Big-Endian)
	HeaderName        : unicodeFFFE
	WebName           : unicodeFFFE
	WindowsCodePage   : 1200
	IsBrowserDisplay  : False
	IsBrowserSave     : False
	IsMailNewsDisplay : False
	IsMailNewsSave    : False
	IsSingleByte      : False
	EncoderFallback   : System.Text.EncoderReplacementFallback
	DecoderFallback   : System.Text.DecoderReplacementFallback
	IsReadOnly        : True
	CodePage          : 1201
	#>
	function Get-FileEncoding
    {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("FullName")][string]$Path,
        [Parameter(Mandatory = $false)][int]$ByteCountToCheck = 10000,
        [Parameter(Mandatory = $false)][decimal]$PercentageMatchUnicode = .5)

        process
        {
            # minimum number of characters to check if no BOM
            [int]$MinCharactersToCheck = 400

            #region Parameter validation
            if (-not (Test-Path -Path $Path))
            {
                Write-Error -Message "$($MyInvocation.MyCommand.Name) :: Path does not exist: $Path"
                return
            }

            if ($ByteCountToCheck -lt $MinCharactersToCheck)
            {
                Write-Error -Message "$($MyInvocation.MyCommand.Name) :: ByteCountToCheck should be at least $MinCharactersToCheck : $ByteCountToCheck"
                return
            }
            #endregion Parameter validation

            #region Determine file encoding based on BOM - if exists
            # the code in this section is mostly Lee Holmes' algorithm: http://poshcode.org/2153
            # until we determine the file encoding, assume it is unknown
            $Unknown = "UNKNOWN"
            $result = $Unknown

            # The hashtable used to store our mapping of encoding bytes to their
            # name. For example, "255-254 = Unicode"
            $encodings = @{}

            # Find all of the encodings understood by the .NET Framework. For each,
            # determine the bytes at the start of the file (the preamble) that the .NET
            # Framework uses to identify that encoding.
            $encodingMembers = [System.Text.Encoding] | Get-Member -Static -MemberType Property
            $encodingMembers | ForEach-Object {
                $encodingBytes = [System.Text.Encoding]::($_.Name).GetPreamble() -join '-'
                $encodings[$encodingBytes] = $_.Name
            }

            # Find out the lengths of all of the preambles.
            $encodingLengths = $encodings.Keys | Where-Object { $_ } | ForEach-Object { ($_ -split "-").Count }

            $file = Get-Item $Path

            # Go through each of the possible preamble lengths, read that many
            # bytes from the file, and then see if it matches one of the encodings
            # we know about.
            foreach ($encodingLength in $encodingLengths | Sort-Object -Descending)
            {
                $bytes = (Get-Content -Path $Path -Encoding byte -ReadCount $encodingLength)[0]
                $encoding = $encodings[$bytes -join '-']

                # If we found an encoding that had the same preamble bytes,
                # save that output and break.
                if ($encoding)
                {
                    $result = $encoding
                    break
                }
            }

            # if encoding determined from BOM, then return it
            if ($result -ne $Unknown)
            {
                $output = [System.Text.Encoding]::$result
                $file = $file | Add-Member -Name Encoding -MemberType NoteProperty -Force -PassThru -Value $output.EncodingName
                $file
                return
            }
            #endregion

            #region No BOM on file, attempt to determine based on file content
            <#
            Looking at the content of many code files, most of it is code or
            spaces.  Sure, there are comments/descriptions and there are variable
            names (which could be double-byte characters) or strings but most of
            the content is code - represented as single-byte characters.  If the
            file is Unicode but the content is mostly code, the single byte
            characters will have a null/value 0 byte as either as the first or
            second byte in each group, depending on Endian type.
            My algorithm uses the existence of these 0s:
                - look at the first ByteCountToCheck bytes of the file
                - if any character is greater than 127, note it (if any are found, the
                file is at least UTF8)
                - count the number of 0s found (in every other character)
                - if a certain percentage (compared to total # of characters) are
                    null/value 0, then assume it is Unicode
                - if the percentage of 0s is less than we identify as a Unicode
                    file (less than PercentageMatchUnicode) BUT a character greater
                    than 127 was found, assume it is UTF8.
                - Else assume it's ASCII.
            Yes, technically speaking, the BOM is really only for identifying the
            byte order of the file but c'mon already... if your file isn't ASCII
            and you don't want it's encoding to be confused just put the BOM in
            there for pete's sake.
            Note: if you have a huge amount of text at the beginning of your file which
            is not code and is not single-byte, this algorithm may fail.  Again, put a
            BOM in.
            #>

            $Content = (Get-Content -Path $Path -Encoding byte -ReadCount $ByteCountToCheck -TotalCount $ByteCountToCheck)
            # get actual count of bytes (in case less than $ByteCountToCheck)
            $ByteCount = $Content.Count
            [bool]$NonAsciiFound = $false
            # yes, the big/little endian sections could be combined in one loop
            # sorry, crazy busy right now...

            #region Check if Big Endian
            # check if big endian Unicode first - even-numbered index bytes will be 0)
            $ZeroCount = 0
            for ($i = 0; $i -lt $ByteCount; $i += 2)
            {
                if ($Content[$i] -eq 0)
                {
                    $ZeroCount++
                }
                if ($Content[$i] -gt 127)
                {
                    $NonAsciiFound = $true
                    }
            }

            if (($ZeroCount / ($ByteCount / 2)) -ge $PercentageMatchUnicode)
            {
                # create big-endian Unicode with no BOM
                $output = New-Object System.Text.UnicodeEncoding $true,$false
                $file = $file | Add-Member -Name Encoding -MemberType NoteProperty -Force -PassThru -Value $output.EncodingName
                $file
                return
            }
            #endregion

            #region Check if Little Endian
            # check if little endian Unicode next - odd-numbered index bytes will be 0)
            $ZeroCount = 0

            for ($i = 1; $i -lt $ByteCount; $i += 2)
            {
                if ($Content[$i] -eq 0)
                {
                    $ZeroCount++
                }

                if ($Content[$i] -gt 127)
                {
                    $NonAsciiFound = $true
                }
            }

            if (($ZeroCount / ($ByteCount / 2)) -ge $PercentageMatchUnicode)
            {
                # create little-endian Unicode with no BOM
                $output = New-Object System.Text.UnicodeEncoding $false,$false
                $file = $file | Add-Member -Name Encoding -MemberType NoteProperty -Force -PassThru -Value $output.EncodingName
                $file
                return
            }
            #endregion

            #region Doesn't appear to be Unicode; either UTF8 or ASCII
            # Ok, at this point, it's not a Unicode based on our percentage rules
            # if not Unicode but non-ASCII character found, call it UTF8 (no BOM, alas)
            if ($NonAsciiFound -eq $true)
            {
                $output = New-Object System.Text.UTF8Encoding $false
                $file = $file | Add-Member -Name Encoding -MemberType NoteProperty -Force -PassThru -Value $output.EncodingName
                $file
                return
            }
            else
            {
                # if made it this far, I'm calling it ASCII; done deal pal
                $output = [System.Text.Encoding]::"ASCII"
                $file = $file | Add-Member -Name Encoding -MemberType NoteProperty -Force -PassThru -Value $output.EncodingName
                $file
                return
            }
            #endregion

            #endregion
        }
	}

#Region XboxMaintenance Alert Suppression functions

# Note, if you extend this set, make sure you update AutopilotClient-Alerts.xml
Add-Type -TypeDefinition @"
 public enum ValidMaintenanceServices {TestDB,BanDB,DeviceDB,NPDB,UODB,UserDB,XDocDB,ProfileDB,AvatarDB,FitnessDB,UserCommerceDB,TokenDB}
"@

function Start-XboxMaintenance {
Param (
	[Parameter(Mandatory=$True,
	ValueFromPipeline=$True,
	ValueFromPipelineByPropertyName=$True)]
	[ValidMaintenanceServices]$Service
	,
	[Parameter(Mandatory=$True,
	ValueFromPipeline=$True,
	ValueFromPipelineByPropertyName=$True)]
	[ValidateSet("BN1Prod","CO1bProd","CO1Prod","CY1PPE","CY1Prod")]
	[array]$Cluster
	,
	[string]$Machinefunction = "WD"
  )

  foreach ($clu in $Cluster){
	$mf = "{0}.autopilot.{1}.ap.phx.gbl" -f $Machinefunction,$clu
	$target = Get-DNSHost $mf | where {$_ -notmatch "xxx"} | select -first 1
	$target = $target.Split(".")[0]

	If ($clu -eq "BLULab"){
	  $targetFQDN = "{0}.nonprod.live" -f $target
	}
	Else {
	  $targetFQDN = "{0}.prod.live" -f $target
	}

	$property = "XboxMaintenance_"+$Service
	$value = "Maintenance on [{0}] started at [{1}] by [{2}] from [{3}]" -f $service,(Get-Date -uformat "%Y-%m-%d %H:%M:%S"),$env:USERNAME,$env:COMPUTERNAME

	Write-Host ""
	Write-Host "Cluster:    $clu"
	Write-Host "Target:     $target"
	Write-Host "TargetFQDN: $targetFQDN"
	Write-Host "Property:   $property"
	Write-Host "Value:      $value"

$scriptBlockString = @"
	  `$appRoot = Get-APAppRoot
	  Update-APMachineProperty -Level Warning -MachineName $target -Property '$property' -Value '$value'
	  New-APAudit -Category XBOXMaintenance -MachineName $target -Environment 'Autopilot' -ParameterList '$value'
"@

	$scriptBlock = $executioncontext.invokecommand.NewScriptBlock($scriptBlockString)

	$functions = "Get-APToolsPath","Get-AutopilotServicePath","Update-APMachineProperty","New-APAudit","Get-APMachineProperty","Import-CsvFieldsHeader","Get-APServiceStatus","Get-APDataDir","Get-APAppRoot"

	$session = New-PSSession -ComputerName $targetFQDN

	foreach ($function in $functions){
	  $command = Get-Command $function
	  Add-functionToRemoteSessions -Sessions $session -functionInfo $command
	}

	Invoke-Command -session $session -ScriptBlock $scriptBlock
	Remove-PSSession -Session $session
  }
}

function Stop-XboxMaintenance {
Param (
	[Parameter(Mandatory=$True,
	ValueFromPipeline=$True,
	ValueFromPipelineByPropertyName=$True)]
	[ValidMaintenanceServices]$Service
	,
	[Parameter(Mandatory=$True,
	ValueFromPipeline=$True,
	ValueFromPipelineByPropertyName=$True)]
	[ValidateSet("BN1Prod","CO1bProd","CO1Prod","CY1PPE","CY1Prod")]
	[array]$Cluster
	,
	[string]$Machinefunction = "WD"
  )

  foreach ($clu in $Cluster){
	$mf = "{0}.autopilot.{1}.ap.phx.gbl" -f $Machinefunction,$clu
	$target = Get-DNSHost $mf | where {$_ -notmatch "xxx"} | select -first 1
	$target = $target.Split(".")[0]

	If ($clu -eq "BLULab"){
	  $targetFQDN = "{0}.nonprod.live" -f $target
	}
	Else {
	  $targetFQDN = "{0}.prod.live" -f $target
	}

	$property = "XboxMaintenance_"+$Service
	$value = "Maintenance on [{0}] stopped at [{1}] by [{2}] from [{3}]" -f $service,(Get-Date -uformat "%Y-%m-%d %H:%M:%S"),$env:USERNAME,$env:COMPUTERNAME

	Write-Host ""
	Write-Host "Cluster:    $clu"
	Write-Host "Target:     $target"
	Write-Host "TargetFQDN: $targetFQDN"
	Write-Host "Property:   $property"
	Write-Host "Value:      $value"

$scriptBlockString = @"
	  `$appRoot = Get-APAppRoot
	  `$machineProps = Get-APMachineProperty -Property $property | Where {`$_.Level -ne 'OK' }
	  foreach (`$machineProp in `$machineProps){
		Update-APMachineProperty -Level OK -MachineName `$machineProp.MachineName -Property '$property' -Value '$value'
	  }
	  New-APAudit -Category XBOXMaintenance -MachineName $target -Environment 'Autopilot' -ParameterList '$value'
"@

	$scriptBlock = $executioncontext.invokecommand.NewScriptBlock($scriptBlockString)

	$functions = "Get-APToolsPath","Get-AutopilotServicePath","Update-APMachineProperty","New-APAudit","Get-APMachineProperty","Import-CsvFieldsHeader","Get-APServiceStatus","Get-APDataDir","Get-APAppRoot"

	$session = New-PSSession -ComputerName $targetFQDN

	foreach ($function in $functions){
	  $command = Get-Command $function
	  Add-functionToRemoteSessions -Sessions $session -functionInfo $command
	}

	Invoke-Command -session $session -ScriptBlock $scriptBlock
	Remove-PSSession -Session $session
  }
}

#EndRegion XboxMaintenance Alert Suppression functions
