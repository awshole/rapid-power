<#
    .SYNOPSIS 

    .DESCRIPTION
    
    .PARAMETER pathToRapid7InsightVMContainerIssues
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
    
    .PARAMETER githubIssueAssignee
    This is an optional parameter that expects a GitHub username that should be assigned to
    the issues that may be created.   

    .PARAMETER labels
    
    
    .OUTPUTS
    Text is output to the screen to display progress, and GitHub Issues are created. No
    native PowerShell objects are returned.

    .EXAMPLE
    $splat = @{
        gitHubToken = $githubToken
        pathToRapid7InsightVMContainerIssues = 'C:\Users\51368\Desktop\local_tsg-sae-javascript-vulnerable-demo-scan.json'
        gitHubRepository = 'awshole/rapid-power'
        branchName = 'main'
        gitHubIssueAssignee = 'awshole'
        labels = @('security', 'rapid7')
    }
    .\Set-Rapid7InsightVMContainerImageGitHubIssue.ps1 @splat
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $pathToRapid7InsightVMContainerIssues,
    [Parameter(Mandatory = $True)] [string] $branchName,
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $gitHubRepository,
    [Parameter(Mandatory = $False)] [string] $gitHubIssueAssignee,
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

# Get content from scan output and create filter based on severity specified in the minimumSeverity paramete
$containerImageScanContent = Get-Content -path $pathToRapid7InsightVMContainerIssues | ConvertFrom-Json
if ($containerImageScanContent.layers.assessment.findings.Count -gt 0 ) {
    foreach ($finding in $containerImageScanContent.layers.assessment.findings) {
        $references = $null
        foreach ($reference in $finding.vulnerability.references) {
            if ($null -ne $reference.url) {
                [string]$references = $references + "`n`n[$($reference.id)]($($reference.url))`n`n"
            }
        }
        
        [array]$findings += [PSCustomObject][ordered]@{
            'Vulnerability Title' = $finding.vulnerability.title.Split(':')[-1]
            Instances = $finding.instances
            'CVSS Score' = $finding.vulnerability.cvss_v3.score
            Summary = "<details>
    <summary>Summary</summary>
    $($finding.results.proof | Select-Object -Unique)
    </details>"
            References = "<details>
    <summary>References</summary>
    $references
    </details>"
            Description = "<details>
    <summary>Description</summary>
    $($finding.vulnerability.description.html)
    </details>"
        }
    }
    
    $findings | Group-Object -Property 'Vulnerability Title' | ForEach-Object {[array]$uniqueFindings += $_.Group | Select-Object -First 1}  
    $uniqueFindings = $uniqueFindings | Sort-Object -Property 'CVSS Score' -Descending
    Add-Type -AssemblyName System.Web
    $findingsTable = [System.Web.HttpUtility]::HtmlDecode(($uniqueFindings | Select-Object -Property * | ConvertTo-Html -Fragment))
    $issueContent = "## Overview 
    
    Rapid7 InsightVM contains support for scanning container images to identify vulnerabilities. The below table is a summary of identified vulnerabilies. 
    
    ## Summary of results
    $findingsTable"
    
    # Determine if there is a current GitHub issue for Rapid7 InsightAppSec
    Write-Output "Getting current GitHub Issues."
    $splat = @{
        gitHubToken = $gitHubToken
        gitHubRepositoryOwner = $gitHubRepositoryOwner
        gitHubRepositoryName = $gitHubRepositoryName
    }
    $currentGitHubIssues = Get-GitHubIssues @splat 
    
    # If there is a current issue, create a new issue, then comment on the old issue with a link to the new issue and close the old issue
    $title = "[Rapid7] Container image scan results ($branchName)"
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
} else {
    Write-Output "No issues found."
}
