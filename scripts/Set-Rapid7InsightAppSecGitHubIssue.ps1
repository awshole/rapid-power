<#
    .SYNOPSIS 
    This script is to be run as part of a set of GitHub Action steps. It creates
    a GitHub issue for vulnerabilities identified by a Rapid7 InsightAppSec scan
    (prior step in GitHub Action workflow). If a GitHub issue currently exists for 
    vulnerabilities identified by Rapid7 InsightAppSec, that issue will be closed
    in order to keep only one active open issue. Additionally, that issue will 
    have a comment that references the issues that this script creates. 

    .DESCRIPTION
    This script requires 4 parameters (pathToRapid7AppSecIssues, gitHubToken, 
    gitHubRepository, minimumSeverity) and one optional parameter (githubIssueAssignee) 
    to post a GitHub Issue with a summary of the Rapid7 InsightAppSec scan. 

    
    .PARAMETER pathToRapid7AppSecIssues
    This parameter expects a string value that corresponds to the path of the json
    output from the Rapid7 InsightAppSec scan (prior step in the GitHub Actions 
    workflow). It is typically output to the working directory.
    
    .PARAMETER gitHubToken
    This parameter expects a string value corresponding to the API token to use when 
    accessing the GitHub organization.

    .PARAMETER gitHubRepository
    This parameter expects a string value corresponding to the full name of the GitHub
    repository to post a GitHub Issue to (i.e., including the owner). For example, 
    awshole/rapid-power. 

    .PARAMETER minimumSeverity
    This parameter expects a string value corresponding to the level of verbosity that the 
    GitHub Issue should contain. This value must be one of: High, Medium, Low, or Informational.
    
    .PARAMETER githubIssueAssignee
    This is an optional parameter that expects a GitHub username that should be assigned to
    the issues that may be created.   
    
    .OUTPUTS
    Text is output to the screen to display progress, and GitHub Issues are created. No
    native PowerShell objects are returned.

    .EXAMPLE
    $splat = @{
        gitHubToken = <omitted>
        pathToRapid7AppSecIssues = 'scan_details.json'
        gitHubRepository = 'aws/rapid-power'
        gitHubIssueAssignee = 'awshole'
        minimumSeverity = 'Low'
        labels = @('security', 'rapid7')
    }
    .\Set-Rapid7InsightAppSecGitHubIssue.ps1 @splat
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $pathToRapid7AppSecIssues,
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $gitHubRepository,
    [Parameter(Mandatory = $False)] [string] $gitHubIssueAssignee,
    [Parameter(Mandatory = $False)] [string] $minimumSeverity,
    [Parameter(Mandatory = $False)] [array] $labels
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

# Dot source GitHub function library
$dotSourceFilePath = 'functions/functions.ps1'
$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepository = 'awshole/git-power'
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

# Parse 'gitHubrepository' parameter for more clear variable names. This also allows for the $GITHUB_REPOSITORY GitHub Actions environment variable to be leveraged
$gitHubRepositoryName = $gitHubRepository.Split('/')[-1]
$gitHubRepositoryOwner = $gitHubRepository.Split('/')[0]

# Parse Rapid7 InsightAppSec App name from scan results file name
$rapid7InsighAppSecAppName = (Split-Path -Path $pathToRapid7AppSecIssues -Leaf).Split('_')[0]

# Get content from scan output and create filter based on severity specified in the minimumSeverity parameter
$appSecScanContent = Get-Content -Path $pathToRapid7AppSecIssues | ConvertFrom-Json
if ($minimumSeverity -like 'High') {
    [array]$issues = $appSecScanContent | Where-Object {$_.severity -like "High"}
}
elseif ($minimumSeverity -like 'Medium') {
    [array]$issues = $appSecScanContent | Where-Object {$_.severity -like "High" -or $_.severity -like "Medium"}
}
elseif ($minimumSeverity -like 'Low') {
    [array]$issues = $appSecScanContent | Where-Object {$_.severity -like "High" -or $_.severity -like "Medium" -or $_.severity -like "Low"}
}
elseif ($minimumSeverity -like 'Informational') {
    [array]$issues = $appSecScanContent | Where-Object {$_.root_cause.url -like "$uniqueUrl"}
}
else {
    Write-Warning "The severity specified in the 'minimumSeverity' parameter is not one of: High, Medium, Low, or Informational."   
    break
}

# Identify each unique URL that contains a vulnerability and create summary table
Write-Output "Creating GitHub Issue content."
$uniqueUrlsWithIssues = $issues.root_cause.url | Select-Object -Unique
foreach ($uniqueUrl in $uniqueUrlsWithIssues) {
    # Get all vulnerabilities for the given URL
    [array]$urlIssues = $issues | Where-Object {$_.root_cause.url -like "$uniqueUrl"}

    # Determine the maximum severity of a vulnerability for a given URL
    if ($urlIssues.severity -contains 'HIGH') {
        $maxSeverity = 'HIGH'    
    }
    elseif ($urlIssues.severity -contains 'MEDIUM' -and $urlIssues.severity -notcontains 'HIGH' ) {
        $maxSeverity = 'MEDIUM'    
    }
    elseif ($urlIssues.severity -contains 'LOW' -and $urlIssues.severity -notcontains 'HIGH' -and $urlIssues.severity -notcontains 'MEDIUM' ) {
        $maxSeverity = 'LOW'    
    }
    elseif ($urlIssues.severity -contains 'INFORMATIONAL' -and $urlIssues.severity -notcontains 'HIGH' -and $urlIssues.severity -notcontains 'MEDIUM' -and $urlIssues.severity -notcontains 'LOW') {
        $maxSeverity = 'INFORMATIONAL'    
    }
    
    # Define the 'click to expand' markdown for the given URL
    $issueContentToAdd = "<summary>The following $($urlIssues.Count) vulnerabilities were identified at: $uniqueUrl</summary>"
    
    # Define the 'click to expand' markdown for the table element
    $urlContentToAdd = "<summary>$uniqueUrl</summary>`n`r"
    foreach ($urlIssue in $urlIssues) {
        [array]$severities = $urlIssues.severity
        [array]$attackModuleNames = $urlIssues.attackModule.name
        $urlContentToAdd = $urlContentToAdd + "* [$($severities[$urlIssues.IndexOf($urlIssue)])] $($attackModuleNames[$urlIssues.IndexOf($urlIssue)])`n"
    }
    $urlContentToAdd = "<details>`n$urlContentToAdd`n</details>"

    # Create markdown for the content that is displayed when the given URL is expanded. When a given URL has more than one issue they will all be listed
    foreach ($issue in $urlIssues) {
        $issueData = [PSCustomObject][ordered]@{
            'Root Cause URL' = $urlContentToAdd
            'Number of Issues' = $urlIssues.count
            'Max Vulnerability Severity' = $maxSeverity
        }

        if ($null -ne $issue.root_cause.parameter) {
            $heading = "## Issue $($urlIssues.IndexOf($issue)+1) ($($issue.severity)): $($issue.attackModule.name) (Parameter: $($issue.root_cause.parameter)) "
        }
        else {
            $heading = "## Issue $($urlIssues.IndexOf($issue)+1) ($($issue.severity)): $($issue.attackModule.name)  "
        }
        $issueContentToAdd = $issueContentToAdd + "

$heading  

### Overview 
$($issue.attackDetails.description.Trim())    

### Additional Details  
Vulnerable URL: $uniqueUrl  
Vulnerability Severity: $($issue.severity)  
Attack Module Description: $($issue.attackModule.description.Trim())  

### Recommendation  
$($issue.attackDetails.recommendation.Trim())  "

        if ($null -ne $issue.attackDetails.references) {
            $referenceNames = ($issue.attackDetails.references | Get-Member | Where-Object {$_.MemberType -like 'NoteProperty'}).Name
            $references = $null
            foreach ($referenceName in $referenceNames) {
                $references = $references + "- [$referenceName]($($issue.attackDetails.references.$referenceName.Trim()))`n"
            }
            $issueContentToAdd = $issueContentToAdd + "`n`n### References`n`n$references"
        }
    }

    $issueContent += "`n`n<details>`n$issueContentToAdd`n</details>"
    [array]$allIssueData += $issueData
}

# Create an HTML table to summarize the unique URLs with vulnerabilities. Place detailed summary of results using 'click to expand' markdown below
Add-Type -AssemblyName System.Web
$table = [System.Web.HttpUtility]::HtmlDecode(($allIssueData | Select-Object -Property * | ConvertTo-Html -Fragment))
$issueContent = $issueContent -replace '<\/p[^>a-z]', '</p>' # Fix typos from output that leave orphan </p tags (i.e., they are not </p>)
$issueContent = "$table<br>`n`n---`n`n### Additional details`n`n$issueContent"
$issueContent = "## Overview 

Rapid7 InsightAppSec is a tool that allows you to automatically crawl and assess web applications to identify vulnerabilities like SQL Injection, XSS, CSRF, and more. The below table is a summary of the URLs that were found to have vulnerabilities greater than or equal to **$($minimumSeverity.ToLower())** severity. 

## Summary of results
$issueContent"

# Determine if there is a current GitHub issue for Rapid7 InsightAppSec
Write-Output "Getting current GitHub Issues."
$splat = @{
    gitHubToken = $gitHubToken
    gitHubRepositoryOwner = $gitHubRepositoryOwner
    gitHubRepositoryName = $gitHubRepositoryName
}
$currentGitHubIssues = Get-GitHubIssues @splat 

# If there is a current issue, create a new issue, then comment on the old issue with a link to the new issue and close the old issue
$title = "[Rapid7] InsightAppSec scan results ($rapid7InsighAppSecAppName)"
if ($currentGitHubIssues.title -contains $title) {
    $currentGitHubIssue = $currentGitHubIssues | Where-Object {$_.title -eq $title -and $_.state -like 'open'}
    Write-Output "Creating GitHub Issue."
    if ($PSBoundParameters.ContainsKey('githubIssueAssignee')) {
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            title = "$title" 
            issueContent = $issueContent 
            assignee = $gitHubIssueAssignee
        }
        $issue = New-GitHubIssue @splat  
    }        
    else {
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            title = "$title" 
            issueContent = $issueContent 
        }
        $issue = New-GitHubIssue @splat
    }

    if ($PSBoundParameters.ContainsKey('labels')) {
        Write-Output "Adding labels to GitHub Issue."
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName
            issueNumber = $issue.number 
            labels = $labels
        }
        New-GitHubIssueLabel @splat | Out-Null
    }

    $content = "A subsequent scan was executed, as well as [GitHub issue posted]($($issue.html_url)). Closing automatically to ensure that only one issue remains open."
    Write-Output "Commenting before closing issue."
    $splat = @{
        gitHubToken = $gitHubToken 
        gitHubRepositoryOwner = $gitHubRepositoryOwner 
        gitHubRepositoryName = $gitHubRepositoryName
        issueNumber = $currentGitHubIssue.number
        content = $content
    }
    New-GitHubIssueComment @splat | Out-Null

    Write-Output "Closing GitHub Issue."
    $splat = @{
        gitHubToken = $gitHubToken 
        gitHubRepositoryOwner = $gitHubRepositoryOwner 
        gitHubRepositoryName = $gitHubRepositoryName
        issueNumber = $currentGitHubIssue.number
    }
    Close-GitHubIssue @splat | Out-Null
}
else {
    Write-Output "Creating GitHub Issue."
    if ($PSBoundParameters.ContainsKey('githubIssueAssignee')) {
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            title = "$title" 
            issueContent = $issueContent 
            assignee = $gitHubIssueAssignee
        }
        $issue = New-GitHubIssue @splat 
    }        
    else {
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName 
            title = "$title" 
            issueContent = $issueContent 
        }
        $issue = New-GitHubIssue @splat
    }

    if ($PSBoundParameters.ContainsKey('labels')) {
        Write-Output "Adding labels to GitHub Issue."
        $splat = @{
            gitHubToken = $gitHubToken 
            gitHubRepositoryOwner = $gitHubRepositoryOwner 
            gitHubRepositoryName = $gitHubRepositoryName
            issueNumber = $issue.number 
            labels = $labels
        }
        New-GitHubIssueLabel @splat | Out-Null  
    }
}
