<#
    .SYNOPSIS 
    This script initiates a new scan for a given container image, and provides 
    a JSON output. 

    .DESCRIPTION
    This script requires 3 parameters (rapid7rapid7ApiKey, imageName, repositoryName)
    to execute a scan of a given container image to identify vulnerabilities. The
    scan is initiated by executing a docker image that acts as the scanning engine. 
    Results are output as JSON file. 

    .PARAMETER rapid7ApiKey
    This parameter expects a string value corresponding to the API key to use when 
    accessing the Rapid7 InsightVM platform.

    .PARAMETER imageName
    This parameter expects a string value corresponding to the name of the image being
    scanned. 

    .PARAMETER imageRepositoryName
    This parameter expects a string value corresponding to the name of the repository 
    that hosts the image being scanned. 

    .OUTPUTS
    This script outputs a JSON file that details the output of the image scan.
    The JSON file name follows the following convention: <repositoryName>_<imageName>-scan.json.

    .EXAMPLE
    $splat = @{
        rapid7ApiKey = <omitted>
        imageName = 'web-dvwa'
        repositoryName = 'vulnerables'
    }
    .\New-Rapid7InsightVMContainerScan.ps1 @splat

    .NOTES
    Requires                : Running on a host with docker installed
                              The rapid7/container-image-scanner docker image is available
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $True)] [string] $rapid7ApiKey,
    [Parameter(Mandatory = $True)] [string] $imageName,
    [Parameter(Mandatory = $True)] [string] $imageRepositoryName
)

$imageRepositoryName = $imageRepositoryName.ToLower()
$imageName = $imageName.ToLower()
$imageFileName = "$($imageName.Split(':')[0].Split('/')[-1]).tar"

# Save the docker image to be mounted
try {
    Write-Output "Saving docker image for $imageRepositoryName/$imageName."
    sudo docker save "$imageRepositoryName/$imageName" -o "/tmp/$imageFileName"
    Write-Output "Saved docker image for $imageRepositoryName/$imageName."
} catch {
    Write-Warning "Unable to save docker image for $imageRepositoryName/$imageName."
    $ErrorMessage = $_.Exception.Message
    Write-Warning "$ErrorMessage"
    break
}

# Execute the scan and create output
try {
    Write-Output "Starting scan."
    sudo docker run -t --rm -v "/tmp/$imageFileName`:/$imageFileName" rapid7/container-image-scanner:latest -f="$imageFileName" -k="$rapid7ApiKey" > "rapid7-container-image-scan.json"
    Write-Output "Scan finished."
} catch {
    Write-Warning "Unable to start scan."
    $ErrorMessage = $_.Exception.Message
    Write-Warning "$ErrorMessage"
}

sudo rm "/tmp/$imageFileName" -f
