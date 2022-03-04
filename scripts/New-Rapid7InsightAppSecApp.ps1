<#
    .SYNOPSIS
    This script creates a new Rapid7 InsightAppSec App with a baseline configuration.
    However, no schedule is created, and scans must be executed manually to gather
    results on potential vulnerablities.

    .DESCRIPTION
    This script requires 7 base parameters (githubUser,
    githubUser, rapid7ApiKey, appName, domain, attackTemplate, engineType),  and 1 
    optional parameter (engineGroupName) 

    The scan engine type must be specified using the 'engineType' paramter. Accepted
    values are either 'cloud' (scan executes from Rapid7 cloud infrastructure) or 
    'on-premises' (scan executes from infrastructure specified in the 'engineGroup'
    parameter that is required when 'on-premises' is used).
    
    .PARAMETER gitHubToken
    This parameter expects a string value corresponding to the API token to use when 
    accessing the GitHub organization.
    
    .PARAMETER rapid7ApiKey
    This parameter expects a string value corresponding to the API key to use when 
    accessing the Rapid7 InsightAppSec platform.

    .PARAMETER appName
    This parameter expects a string value corresponding to the name of the App that
    is to be created.

    .PARAMETER domain
    This parameter expects a string value corresponding to the root domain of the App 
    that is to be created. It should be in the form of 'google.com' or 'msn.com'.
    
    .PARAMETER attackTemplateName
    This parameter expects a string value corresponding to the name of the attack template
    that the to be created scan config is should use as a base configuration.
    
    .PARAMETER engineType
    This parameter expects a string value corresponding to the name of the type of scan
    engine that should be used. Accepted values are 'cloud' (to run the scan on Rapid7 cloud
    infrastructure) and 'on-premises'. If 'on-premises' is specified, the 'engineGroupName'
    parameter must also be specified.

    .PARAMETER engineGroupName
    This parameter is optional (required when the 'engineType' parameter is 'on-premises) 
    and expects a string value corresponding to the name of the engine group that should
    be used when conducting scans.

    .OUTPUTS
    N/A

    .EXAMPLE
    $splat = @{
        rapid7ApiKey = <omitted>
        appName = 'MyTestApp'
        domain = 'webscantest.com'
        attackTemplateName = 'All Modules'
        engineType = 'on-premises'
        engineGroupName = 'On-premises Engine Group'
    }
    .\New-Rapid7InsightAppSecApp.ps1 @splat

#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)]  [string]$rapid7ApiKey,
    [Parameter(Mandatory = $True)]  [string]$appName,
    [Parameter(Mandatory = $True)]  [string]$domain,
    [Parameter(Mandatory = $True)]  [string]$attackTemplateName,
    [Parameter(Mandatory = $True)]  [string]$engineType,
    [Parameter(Mandatory = $False)] [string]$engineGroupName
)

# Dot source Rapid7 function library
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

$dotSourceFilePath = 'functions/functions.ps1'
$splat = @{
    gitHubToken = $gitHubToken
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

# Define variables based on supplied parameters
$scanConfigName = "$appName`_$domain`_$attackTemplateName`_$engineType"
$scanScopeUrl = "https://$domain"

# Create the App
New-Rapid7AppSecApp -rapid7ApiKey $rapid7ApiKey -appName $appName | Out-Null

# Create the Target. A Target is required to specify a scan scope within a scan config
New-Rapid7AppSecTarget -rapid7ApiKey $rapid7ApiKey -domain $domain | Out-Null

# Wait until App has been provisioned
do {
    $rapid7AppSecApps = Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey
} until ($rapid7AppSecApps.name -contains $appName)

# Create the scan config for the App
$splat = @{
    rapid7ApiKey = $rapid7ApiKey
    appName = $appName 
    scanConfigName = $scanConfigName
    attackTemplateName = $attackTemplateName 
    engineType = $engineType 
    engineGroupName = $engineGroupName
}
New-Rapid7AppSecScanConfig @splat | Out-Null

# Wait until the scan config has been provisioned
do {
    $rapid7AppSecApps = Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey
    $rapid7AppSecScanConfigs = Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey
} until ($rapid7AppSecApps.name -contains $appName -and ($rapid7AppSecScanConfigs.app.id -contains ($rapid7AppSecApps | Where-Object {$_.name -like $appName}).id))

# Set the scope for the App (i.e., the URL that the scan should target)
$splat = @{
    rapid7ApiKey = $rapid7ApiKey 
    appName = $appName 
    scanConfigName = $scanConfigName 
    scanScopeUrl = $scanScopeUrl
}
Set-Rapid7AppSecScanConfigScanScope @splat | Out-Null
