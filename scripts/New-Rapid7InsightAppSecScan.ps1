<#
    .SYNOPSIS 
    This script executes a new scan for a given Rapid7 InsightAppSec App, and provides 
    a JSON output to a specified directory. 

    .DESCRIPTION
    This script requires 6 parameters (pathToRapid7FunctionLibrary, gitHubToken,
    rapid7rapid7ApiKey, appName, scanConfigName, outputDirectory) to execute a scan of a
    given Rapid7 InsightAppSec app and identify vulnerabilities. Results are output as
    JSON file in the directory specified in the 'outputDirectory' parameter. 2 optional
    parameters (allVulnerabilities, timeOutInHours) can be used to adjust output and limit
    the runtime of the script.

    .PARAMETER pathToRapid7FunctionLibrary
    This parameter expects a string value corresponding to the full GitHub path to 
    the functions.ps1 file.
    
    .PARAMETER gitHubToken
    This parameter expects a string value corresponding to the API token to use when 
    accessing the GitHub organization.
    
    .PARAMETER rapid7ApiKey
    This parameter expects a string value corresponding to the API key to use when 
    accessing the Rapid7 InsightAppSec platform.

    .PARAMETER appName
    This parameter expects a string value corresponding to the name of the Rapid7
    InsighAppSec App.

    .PARAMETER scanConfigName
    This parameter expects a string value corresponding to the name of the desired
    scan config to be used with the initiated scan.

    .PARAMETER outputDirectory
    This parameter expects a string value corresponding to the full path of the directory
    where the JSON output of the scan should be saved.

    .PARAMETER timeOutInHours
    This is an optional parameter that expects an integer value corresponding to the number
    of hours the scan should be allowed to run before timing out. If the time out limit is 
    reached, the scan is Stopled and the script is ended. 

    .PARAMETER allVulnerabilities
    This is an optional parameter that is a switch that indicates whether or not all the 
    InsightAppSec's App vulnerabilities should be returned. If not included, results that
    are written to the JSON output are limited to only the vulnerabilities identified
    by the scan initiated by this script.
    
    .OUTPUTS
    This script outputs a JSON file that details the output of the scan. The file
    is written to the directory that is specified in the 'outputDirectory' parameter.
    The JSON file name follows the following convention: <appName>_<scanConfigName>_appsec.json.

    .EXAMPLE
    $splat = @{
        rapid7ApiKey = <omitted>
        appName = 'tsg-web-webscantest-dev'
        scanConfigName = 'Login page'
        outputDirectory = '/tmp'
    }
    .\New-Rapid7InsightAppSecScan.ps1 @splat
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $rapid7ApiKey,
    [Parameter(Mandatory = $True)] [string] $appName,
    [Parameter(Mandatory = $True)] [string] $scanConfigName,
    [Parameter(Mandatory = $True)] [string] $outputDirectory,
    [Parameter(Mandatory = $False)] [int] $timeOutInHours,
    [Parameter(Mandatory = $False)] [switch] $allVulnerabilities
)

function Get-GitHubRepositoryFileContent {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $True)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $gitHubToken
    )

    $uri = "https://api.github.com/repos/$gitHubRepository/contents/$path`?ref=$branch" # Need to escape the ? that indicates an http query
    $uri = [uri]::EscapeUriString($uri)
    if ($PSBoundParameters.ContainsKey('gitHubtoken')) {
        $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
        $headers = @{'Authorization' = "Basic $base64Token"}
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
    } else {
        $splat = @{
            Method = 'Get'
            Uri = $uri
            ContentType = 'application/json'
        }
    } 
    
    try {
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get file content."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}

#Dot source Rapid7 function library
$dotSourceFilePath = 'functions/functions.ps1'
$splat = @{
    gitHubRepository = 'awshole/rapid-power'
    path = $dotSourceFilePath
    branch = 'main'
}
$dotSourceFileData = Get-GitHubRepositoryFileContent @splat
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($dotSourceFileData.content)) | Out-File -FilePath $dotSourceFilePath.Split('/')[-1] -Force
$dotSourceFile = Get-Item -Path $dotSourceFilePath.Split('/')[-1]
if (Test-Path -Path $dotSourceFilePath.Split('/')[-1]) {
    try {
        . $dotSourceFile.FullName
        Remove-Item -Path $dotSourceFilePath.Split('/')[-1] -Recurse -Force
    } catch {
        Write-Warning "Unable to dot source file: $dotSourceFilePath."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
} else {
    Write-Warning "Could not find path to file: $dotSourceFilePath."
    $ErrorMessage = $_.Exception.Message
    Write-Warning "$ErrorMessage"
    break
}

# Stop and disregard results from any scan if any are currently in the Running or Queued state
$currentScans = Get-Rapid7AppSecAppScans -rapid7ApiKey $rapid7ApiKey -appName $appName
foreach ($scan in ($currentScans | Where-Object {$_.status -like 'RUNNING' -or $_.status -like 'QUEUED'})) {
    Write-Warning "Stopping scan $($scan.id)."
    Stop-Rapid7AppSecScan -rapid7ApiKey $rapid7ApiKey -scanId $scan.id    
}   

# Start a new scan 
Write-Output "Starting scan."
$splat = @{
    rapid7ApiKey = $rapid7ApiKey
    appName = $appName
    scanConfigName = $scanConfigName
}
New-Rapid7AppSecAppScan @splat  | Out-Null

# Wait for API call to start backend process
Start-Sleep -Seconds 10

# Wait until the scan completes
if (!$PSBoundParameters.ContainsKey('timeOutInHours')) {
    $timeOutInHours = 4
}
$timeOut = (Get-Date).AddHours($timeOutInHours)
$timeOutWarning = "The scan has been running for $timeOutInHours hour(s). Manually investigate why the scan is taking so long."
do {
    $scan = Get-Rapid7AppSecAppScans -rapid7ApiKey $rapid7ApiKey -appName $appName | Select-Object -First 1 # The default sort for Scans is "submit_time" (descending)
    if ($scan.status -like 'RUNNING' -or $scan.status -like 'QUEUED' -or $scan.status -like 'PROVISIONING' -or $scan.status -like 'STOPPING') {
        Write-Output "Waiting for scan to complete."
        Start-Sleep -Seconds 30
    }
    if ((Get-Date) -ge $timeOut) {
        Write-Warning "$timeOutWarning"
        end
    }
} until ($scan.status -like 'COMPLETE')

# Get all the vulnerabilities for a given app
Write-Output "Getting vulnerabilities for the App."
$vulnerabilities = Get-Rapid7AppSecAppVulnerabilities -rapid7ApiKey $rapid7ApiKey -appName $appName

# Get the vulnerabilities that are part of the scan that was executed during this script; otherwise vulnerabilities from all scans, including previous ones are included in the results
Write-Output "Determining which vulnerabilities belong to the current scan."
foreach ($vulnerability in $vulnerabilities) {
    [array]$vulnerabilityDiscoveries += Get-Rapid7AppSecVulnerabilityDiscoveries -rapid7ApiKey $rapid7ApiKey -vulnerabilityId $vulnerability.id
}
if ($allVulnerabilities) {
    $scanVulnerabilityIds = $vulnerabilityDiscoveries.vulnerability.id | Select-Object -Unique
} else {
    # Return only vulnerabilities that were newly identified as part of this scan
    [array]$scanVulnerabilityIds = ($vulnerabilityDiscoveries | Where-Object {$_.scan.id -like $scan.id}).vulnerability.id
}
foreach ($scanVulnerabilityId in $scanVulnerabilityIds) {
    [array]$scanVulnerabilities += Get-Rapid7AppSecVulnerability -rapid7ApiKey $rapid7ApiKey -vulnerabilityId $scanVulnerabilityId
}

# Get details of vulnerabilities to enrich output
Write-Output "Getting vulnerability details."
foreach ($vulnerability in $scanVulnerabilities) {
    foreach ($attackModuleId in $vulnerability.variances.module.id) {
        $attackModule = Get-Rapid7AppSecAttackModule -rapid7ApiKey $rapid7ApiKey -moduleID $attackModuleId
        foreach ($attackId in $vulnerability.variances.attack.id) {
            $splat = @{
                rapid7ApiKey = $rapid7ApiKey
                moduleId = $attackModule.id
                attackId = $attackId
            }
            [array]$attackDetails += Get-Rapid7AppSecAttackDetails @splat
        }                                            
    }
    $attackDetails = $attackDetails | Select-Object -Unique
    $vulnerability | Add-Member -MemberType NoteProperty -Name attackModule -Value $attackModule
    $vulnerability | Add-Member -MemberType NoteProperty -Name attackDetails -Value $attackDetails

    # Reset variable as it is declared as an array and is appended to in this loop
    $attackDetails = $null
}

# Transform PSCustomObject to JSON and create output file
Write-Output "Creating JSON output."
$path = $("$outputDirectory/$appName`_$scanConfigName`_appsec.json").Split([IO.Path]::GetInvalidPathChars()) -join ''
$scanVulnerabilities | ConvertTo-Json -Depth 100 | Out-File -FilePath $path -Force
