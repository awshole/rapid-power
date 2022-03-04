function New-Rapid7AppSecApp {
    <#
        .SYNOPSIS
        This function creates a new App in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, appName) and one optional parameter
        (description) in order to create a new App in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the App that
        is to be created.

        .PARAMETER description
        This parameter is optional and expects a string value that is an extended description
        of the App that is to be created.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'MyTestApp'
            description = 'This app was created using the Rapid7 InsightAppSec REST API.'
        }
        $return = New-Rapid7AppSecApp @splat
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $false)] [string]$description
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/apps"
    if ($PSCmdlet.ShouldProcess("$uri with App name, $appName", "Create new Rapid7 InsightAppSec App")) {
        $body = @{
            name = "$appName"
            description = "$description"
        } | ConvertTo-Json
        try {
            $splat = @{
                Uri = $uri
                Method = 'Post'
                Headers = $headers
                Body = $body
                ContentType = 'application/Json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to create new Rapid7 AppSec app."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    }
}

function Get-Rapid7AppSecApps {
    <#
        .SYNOPSIS
        This function get all the Apps in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameter (rapid7ApiKey) in order to get all the Apps in 
        Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id          : a37c7097-3ad5-4c9c-bf84-7c7013173b03
        name        : MyTestApp
        description : This app was created using the Rapid7 InsightAppSec REST API.
        links       : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/apps/a37c7097-3ad5-4c9c-bf84-7c7013173b03}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/apps"
    do {   
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$apps += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]    
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec Apps."   
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $apps
}

function Get-Rapid7AppSecAttackTemplates {
    <#
        .SYNOPSIS
        This function get all the attack templates in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (rapid7ApiKey) in order to get all the attack
        templates in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id             : 11111111-0000-0000-0000-000000000000
        name           : All Modules
        system_defined : True
        links          : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/attack-templates/11111111-0000-0000-0000-000000000000}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecAttackTemplates -rapid7ApiKey $rapid7ApiKey
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $uri = "https://us.api.insight.rapid7.com/ias/v1/attack-templates"
    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$attackTemplates += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec attack templates."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $attackTemplates
}

function Get-Rapid7AppSecEngines {
    <#
        .SYNOPSIS
        This function get all the scan engines in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (rapid7ApiKey) in order to get all the scan
        engines in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id             : 1eed5579-9a12-4eb5-82d7-c70b6f792bcb
        name           : <omitted>
        engine_group   : @{id=076289b0-fec8-4e46-9b92-4acde519435e}
        status         : IDLE
        latest_version : True
        upgradeable    : True
        auto_upgrade   : True
        links          : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/engines/1eed5579-9a12-4eb5-82d7-c70b6f792bcb}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecEngines -rapid7ApiKey $rapid7ApiKey
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $uri = "https://us.api.insight.rapid7.com/ias/v1/engines"
    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$engines += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec engines."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $engines
}

function Get-Rapid7AppSecEngineGroups {
    <#
        .SYNOPSIS
        This function get all the scan engine groups in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (rapid7ApiKey) in order to get all the scan
        engine groups in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id          : 076289b0-fec8-4e46-9b92-4acde519435e
        name        : On-premises Engine Group
        description : This group contains engines that are running on-premises 
        links       : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/engine-groups/076289b0-fec8-4e46-9b92-4acde519435e}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecEngineGroups -rapid7ApiKey $rapid7ApiKey
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $uri = "https://us.api.insight.rapid7.com/ias/v1/engine-groups"

    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$engineGroups += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec engines."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)

    $engineGroups
}

function New-Rapid7AppSecScanConfig {
    <#
        .SYNOPSIS
        This function will create a new scan config for a given Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 5 parameters (rapid7ApiKey, scanConfigName, appName, attackTemplate,
        engineType) and 2 optional parameters (engineGroupName, description) in order to
        create a new scan config for a given InsightAppSec App.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER scanConfigName
        This parameter expects a string value corresponding to the name of the scan config
        that is to be created.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the Rapid7 AppSec
        App that the to be created scan config is associated with.

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

        .PARAMETER description
        This parameter is optional and expects a string value that is an extended description
        of the scan config that is to be created.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            scanConfigName = 'MyScanConfig'
            appName = 'MyTestApp'
            attackTemplateName = 'All modules'
            engineType = 'on-premises'
            engineGroupName = 'On-premises Engine Group'
            description = 'This scan config was created with the Rapid7 InsightAppSec REST API.'
        }
        New-Rapid7AppSecScanConfig @splat

        .NOTES
        Author                  : David Wiggs - dwiggs4@gmail.com
        Initial draft date      : September 2020
        Requires                : Get-Rapid7AppSecApps
                                  Get-Rapid7AppSecAttackTemplates
                                  Get-Rapid7AppSecEngineGroups
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$scanConfigName,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $True)] [string]$attackTemplateName,
        [Parameter(Mandatory = $True)] [string]$engineType,
        [Parameter(Mandatory = $False)] [string]$engineGroupName,
        [Parameter(Mandatory = $False)] [string]$description
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }

    # POST body is different depending on whether a 'cloud' or 'on-premises' engine is used
    if ($engineType -like "cloud") {
        $body = [pscustomobject]@{
            name = "$scanConfigName"
            description = "$description"
            app = @{
                id = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $appName }).id
            }
            attack_template = @{
                id = (Get-Rapid7AppSecAttackTemplates -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $attackTemplateName }).id
            }

            assignment = @{
                type = "ENGINE_GROUP"
                environment = "CLOUD"
            }
        } | ConvertTo-Json -Depth 100
    } elseif ($engineType -like "on-premises") {
        $body = [pscustomobject]@{
            name = "$scanConfigName"
            description = "$description"
            app = @{
                id = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $appName }).id
            }
            attack_template = @{
                id = (Get-Rapid7AppSecAttackTemplates -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $attackTemplateName }).id
            }

            assignment = @{
                type = "ENGINE_GROUP"
                id = (Get-Rapid7AppSecEngineGroups -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $engineGroupName }).id
                environment = "ON_PREMISE" # Intentional mis-spelling
            }
        } | ConvertTo-Json -Depth 100
    } else {
        Write-Warning "engineType is not either 'cloud' or 'on-premises'."
        break
    }

    if ($PSCmdlet.ShouldProcess("$uri with App name, $appName and scan config name, $scanConfigName", "Create new Rapid7 InsightAppSec App scan config")) {
        try {
            $uri = "https://us.api.insight.rapid7.com/ias/v1/scan-configs"
            $splat = @{
                Uri = $uri
                Method = 'Post'
                Headers = $headers
                Body = $body
                ContentType = 'application/json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to create new Rapid7 AppSec app scan config."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    }
}

function Get-Rapid7AppSecAppVulnerabilities {
    <#
        .SYNOPSIS
        This function gets all the vulnerabilities for a given App in Rapid7
        InsightAppSec.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, appName) in order to get all 
        the vulnerabilities for a given App in Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the App that 
        vulnerabilities are to be retrieved for.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id         : 048ecd05-5239-4577-a641-e3047f6c1e91
        app        : @{id=31d15212-1fbc-4c98-85d9-b6df3ba0274e}
        root_cause : @{url=https://adc3.xzy.com/; method=GET}
        severity   : HIGH
        status     : UNREVIEWED
        variances  : {@{original_exchange=; module=; attack=; message=CookieName=session; CookieDomain=adc3.xzy.com; CookiePath=/; CookieSecure=false; CookieHttpOnly=true; 
                    SessionStrengthCookieCount=512; Entropy=0; Strength=768.091}}
        links      : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/vulnerabilities/048ecd05-5239-4577-a641-e3047f6c1e91}}

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'MyTestApp'
        }
        $return = Get-Rapid7AppSecAppVulnerabilities @splat

        .NOTES
        Author                  : David Wiggs - dwiggs4@gmail.com
        Initial draft date      : September 2020
        Requires                : Get-Rapid7AppSecVulnerabilities
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName
    )

    $appId = "$((Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.name -like $appName}).id)"
    Get-Rapid7AppSecVulnerabilities -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.app.id -like $appId}
}

function Get-Rapid7AppSecScanConfigs {   
    <#
        .SYNOPSIS
        This function gets all the scan configs in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (rapid7ApiKey) in order to get all the vulnerabilities
        in Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id              : c95241a5-9e2d-4bf5-9de9-9ff230222876
        name            : MyScanConfig
        description     : This scan config was created with the Rapid7 InsightAppSec REST API.
        app             : @{id=a37c7097-3ad5-4c9c-bf84-7c7013173b03}
        attack_template : @{id=11111111-0000-0000-0000-000000000000}
        assignment      : @{type=ENGINE_GROUP; id=076289b0-fec8-4e46-9b92-4acde519435e; environment=ON_PREMISE}
        errors          : {Scan config contains no valid URLs}
        links           : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/scan-configs/c95241a5-9e2d-4bf5-9de9-9ff230222876}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scan-configs?size=1000"
    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                Body = $body
                ContentType = 'application/Json'
            }
            $return = Invoke-RestMethod @splat
            [array]$scanConfigs += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]    
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec scan configs."   
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $scanConfigs
}

function Get-Rapid7AppSecScanConfigOptions {
    <#
        .SYNOPSIS
        This function get all the detailed settings for a given scan config for a given
        Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 3 parameters (rapid7ApiKey, appName, scanConfigName) in order to
        get the detailed settings for a given scan config for a given Rapid7 InsightAppSec
        App.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the App that
        vulnerabilities are to be retrieved for.

        .PARAMETER scanConfigName
        This parameter expects a string value corresponding to the name of the scan config
        that is to be created.

        .OUTPUTS
        The output type of this function is of type System.Object (PSCustomObject), and has
        a structure like the below. Note that there may be additional object properties that
        are returned based on the complexity of the scan config. In general all of the object
        properties mentioned below will be returned.

        crawl_config            : @{seed_url_list=System.Object[]; scope_constraint_list=System.Object[]}
        attacker_config         : @{scope_constraint_list=System.Object[]}
        auth_config             : @{adal_config=}
        network_settings_config : @{secure_protocols=System.Object[]}

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'MyTestApp'
            scanConfigName = 'MyScanConfig'
        }
        $return = Get-Rapid7AppSecScanConfigOptions @splat

        .NOTES
        Author                  : David Wiggs - dwiggs4@gmail.com
        Initial draft date      : October 2020
        Requires                : Get-Rapid7AppSecScanConfigs
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $True)] [string]$scanConfigName
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $appId = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $appName }).id
    $scanConfigId = (Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like "$scanConfigName" -and $_.app.id -like $appId }).Id
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scan-configs/$scanConfigId/options"
    try {
        $splat = @{
            Uri = $uri
            Method = 'Get'
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get Rapid7 AppSec App scan config options."
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-Rapid7AppSecVulnerabilities {
    <#
        .SYNOPSIS
        This function get all the vulnerabilities in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (apiKey) in order to get all the vulnerabilities
        in Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id         : 048ecd05-5239-4577-a641-e3047f6c1e91
        app        : @{id=31d15212-1fbc-4c98-85d9-b6df3ba0274e}
        root_cause : @{url=https://adc3.xyz.com/; method=GET}
        severity   : HIGH
        status     : UNREVIEWED
        variances  : {@{original_exchange=; module=; attack=; message=CookieName=session; CookieDomain=adc3.xyz.com; CookiePath=/; CookieSecure=false; CookieHttpOnly=true; 
                    SessionStrengthCookieCount=512; Entropy=0; Strength=768.091}}
        links      : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/vulnerabilities/048ecd05-5239-4577-a641-e3047f6c1e91}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecVulnerabilities -rapid7ApiKey $rapid7ApiKey
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/vulnerabilities?size=1000"
    do {
        try {
            $splat = @{
                Method = 'Get' 
                Uri = $uri 
                Headers = $headers 
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$vulnerabilities += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]    
        } catch {
            Write-Warning "Unable to getRapid7 AppSec vulnerabilities."   
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $vulnerabilities
}

function Set-Rapid7AppSecScanConfigScanScope {
    <#
        .SYNOPSIS
        This function sets the URL that will be scanned for a given scan config on a given
        Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 4 parameters (rapid7ApiKey, appName, scanConfigName, scanScopeUrl)
        in order to set the scan scope URL (e.g., the URL that will be scanned)

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the App that
        vulnerabilities are to be retrieved for.

        .PARAMETER scanConfigName
        This parameter expects a string value corresponding to the name of the scan config
        that is to be created.

        .PARAMETER scanScopeUrl
        This parameter expects a string value corresponding to the URL that will be scanned.
        It must begin with either 'https://' or 'http://'.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'MyTestApp'
            scanConfigName = 'MyScanConfig'
            clientId = '54293c32-3fc3-4fc5-a511-3af8e12f4fe8'
            clientSecret = 'A Base64 string'
        }
        Set-Rapid7AppSecScanConfigScanScope -rapid7ApiKey $rapid7ApiKey `
                                            -appName $appName `
                                            -scanConfigName $scanConfigName `
                                            -scanScopeUrl $scanScopeUrl
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $True)] [string]$scanConfigName,
        [Parameter(Mandatory = $True)] [string]$scanScopeUrl
    )

    if ($scanScopeUrl[-1] -like '/') {
        $baseScanScopeUrl = $scanScopeUrl.TrimEnd('/')
    } else {
        $baseScanScopeUrl = $scanScopeUrl
    }

    $body = [PSCustomObject]@{
        crawl_config = @{
            seed_url_list = @(
                @{
                    value = $scanScopeUrl
                }
            )
            scope_constraint_list = @(
                @{
                    exclusion = 'INCLUDE'
                    match_criteria = 'WILDCARD'
                    method = 'ALL'
                    url = "$baseScanScopeUrl/*"
                }
            )
        }
        attacker_config = @{
            scope_constraint_list = @(
                @{
                    exclusion = 'INCLUDE'
                    match_criteria = 'WILDCARD'
                    method = 'ALL'
                    url = "$baseScanScopeUrl/*"
                }
            )
        }
    } | ConvertTo-Json -Depth 100
    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    if ($PSCmdlet.ShouldProcess("$uri with App name, $appName and $scanScopeUrl", "Set scan scope for Rapid7 InsightAppSec App")) {
        try {
            $appId = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $appName }).id
            $scanConfigId = (Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like "$scanConfigName" -and $_.app.id -like $appId }).Id
            $uri = "https://us.api.insight.rapid7.com/ias/v1/scan-configs/$scanConfigId/options"
            $splat = @{
                Uri = $uri
                Method = 'Put'
                Body = $body
                Headers = $headers
                ContentType = 'application/json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to set the scan scope on Rapid7 AppSec app scan config, $scanConfigName for App, $appName."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }   
}

function New-Rapid7AppSecTarget {
    <#
        .SYNOPSIS
        This function will create a new target in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 1 parameters (rapid7ApiKey) in order to get all the scan
        engine groups in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id          : 076289b0-fec8-4e46-9b92-4acde519435e
        name        : On-premises Engine Group
        description : This group contains engines that are running on-premises
        links       : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/engine-groups/076289b0-fec8-4e46-9b92-4acde519435e}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecEngineGroups -rapid7ApiKey $rapid7ApiKey
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$domain
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $body = @{
        domain = $domain
        enabled = $true
    } | ConvertTo-Json

    $uri = "https://us.api.insight.rapid7.com/ias/v1/targets"
    if ($PSCmdlet.ShouldProcess("$uri with target domain, $domain", "Create Rapid7 InsightAppSec target")) {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Post'
                Headers = $headers
                Body = $body
                ContentType = 'application/Json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to create Insight AppSec target."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    }
}

function New-Rapid7AppSecAppScan {
    <#
        .SYNOPSIS
        This function initiates a new scan for a given Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 3 parameters (rapid7ApiKey, appName, scanConfigName)
        in order to initiate a new scan for a given Rapid7 InsightAppSec App.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER scanConfigName
        This parameter expects a string value corresponding to the name of the scan config
        that is to be used for the scan.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the Rapid7 AppSec
        App that the scan is to be initiated on.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'My test app'
            scanConfigName = 'My scan config'
        }
        New-Rapid7AppSecAppScan @splat

        .NOTES
        Author                  : David Wiggs - dwiggs4@gmail.com
        Initial draft date      : October 2020
        Requires                : Get-Rapid7AppSecApps
                                  Get-Rapid7AppSecScanConfigs
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $True)] [string]$scanConfigName
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scans"
    $appId = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.name -like $appName}).id
    $scanConfigId = (Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.name -like $scanConfigName -and $_.app.id -like $appId}).id
    $body = @{
        scan_config = @{
            id = $scanConfigId
        }
    } | ConvertTo-Json -Depth 100
    
    try {
        $splat = @{
            Uri = $uri
            Method = 'Post'
            Headers = $headers
            Body = $body
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to start new Rapid7 InsightAppSec scan."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-Rapid7AppSecScans {
    <#
        .SYNOPSIS
        This function gets all the scans found in Rapid7 InsightAppSec

        .DESCRIPTION
        This function requires 1 parameter (rapid7ApiKey) to get the scans found in
        Rapid7 InsightAppSec

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id              : 60ba56c2-5f66-4734-a0c5-ac7fb05e73b8
        app             : @{id=e367b47e-a7dd-46d0-8bda-02a7c515c164}
        scan_config     : @{id=cfc7c5db-8acc-4f82-b645-109e3914f891}
        submitter       : @{type=ORGANIZATION; id=531e53a4-7fc7-4b8a-9749-53302377c622}
        submit_time     : 2020-10-15T20:33:07.445821
        completion_time : 2020-10-15T20:51:55.592459
        status          : COMPLETE
        links           : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/scans/60ba56c2-5f66-4734-a0c5-ac7fb05e73b8}}

        .EXAMPLE
        $rapid7ApiKey = <omitted>
        $return = Get-Rapid7AppSecScans -rapid7ApiKey $rapid7ApiKey
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scans"
    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$scans += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]    
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec scans."   
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
            break
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)

    $scans
}

function Get-Rapid7AppSecAppScans {
    <#
        .SYNOPSIS
        This function gets the currently running and historical scans for a given
        Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, appName) in order to return the 
        currently running and historical scans for a given Rapid7 InsightAppSec App.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER appName
        This parameter expects a string value corresponding to the name of the Rapid7 AppSec
        App that scans are to be returned for.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id              : 0f7b71bd-37e5-4461-8586-ba9267a31a05
        app             : @{id=58d4ca12-3d12-4cf1-81e7-20826815a7f2}
        scan_config     : @{id=339f053e-7f45-4f63-8ac3-d10788b5af42}
        submitter       : @{type=ORGANIZATION; id=531e53a4-7fc7-4b8a-9749-53302377c622}
        submit_time     : 2020-10-09T15:05:59.077703
        completion_time : 2020-10-09T15:21:55.462627
        status          : COMPLETE
        links           : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/scans/0f7b71bd-37e5-4461-8586-ba9267a31a05}}

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            appName = 'MyTestApp'
        }
        $return = Get-Rapid7AppSecAppScans  @splat

        .NOTES
        Author                  : David Wiggs - dwiggs4@gmail.com
        Initial draft date      : October 2020
        Requires                : Get-Rapid7AppSecApps
                                  Get-Rapid7AppSecScans
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName
    )

    $appId = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.name -like $appName}).id
    Get-Rapid7AppSecScans -rapid7ApiKey $rapid7ApiKey | Where-Object {$_.app.id -like $appId}
}

function Get-Rapid7AppSecAttackModule {
    <#
        .SYNOPSIS
        This function gets an attack module found in Rapid7 InsightAppSec. 

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, moduleId) to get an attack 
        module found in Rapid7 InsightAppSec

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER moduleId
        This parameter expects a string value corresponding to the module ID of the module
        that is being gathered.

        .OUTPUTS
        The output type of this function is of type System.Object (PSCustomObject), and 
        has a structure like the below.

        id          : 615d72f4-01bc-447a-b4a2-139654bc9945
        name        : X-XSS-Protection
        description : Checks for X-XSS-Protection HTTP header that enables Cross-site scripting (XSS) filter built into the browsers.

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            moduleId = '615d72f4-01bc-447a-b4a2-139654bc9945'
        }
        $return = Get-Rapid7AppSecAttackModule @splat 
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$moduleID
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/modules/$moduleId"
    try {
        $splat = @{
            Uri = $uri
            Method = 'Get'
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get Rapid7 AppSec attack module."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Get-Rapid7AppSecAttackDetails {
    <#
        .SYNOPSIS
        This function gets the attack details, including sumamry and recommendation
        for a given attack in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 3 parameters (rapid7ApiKey, moduleId, attackId) in order to 
        get the attack details, including summary and recommendation for a given attack
        in Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER moduleId
        This parameter expects a string value corresponding to the module ID of the
        vulnerabilty data that is being gathered.

        .PARAMETER attackId
        This parameter expects a string value corresponding to the attack ID of the
        vulnerabilty data that is being gathered.

        .OUTPUTS
        The output type of this function is of type System.Object (PSCustomObject), and 
        has a structure like the below.

        description    : <p>Cross-Site Scripting (XSS) attacks occur when:
                                        Data enters a Web application through an untrusted source, most frequently a web request.
                                        The data is included in dynamic content that is sent to a web user without being validated for malicious code.
                                        The malicious content sent to the web browser often takes the form of a segment of JavaScript, but may also include HTML, Flash or any other type of code that the browser may     
                        execute. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data like cookies or other session information to the attacker, redirecting the 
                        victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.</p>

        recommendation : <p>X-XSS-Protection header is a mechanism that web sites have to communicate to the web browsers that XSS Filter enabled and can check a cross-site scripting attack in the URL.  It has neutered    
                        this attack as the identified script was replayed back into the response page.  In this way the filter is effective without modifying an initial request to the server or blocking an entire
                        response.</p>
        
        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            moduleId = '615d72f4-01bc-447a-b4a2-139654bc9945'
            attackId = 'XSSProtectionAttack_1'
        }
        $return = Get-Rapid7AppSecAttackDetails @splat
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$moduleID,
        [Parameter(Mandatory = $True)] [string]$attackId
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/modules/$moduleId/attacks/$attackId/documentation"
    try {
        $splat = @{
            Uri = $uri
            Method = 'Get'
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get Rapid7 AppSec attack details."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}

function Get-Rapid7AppSecVulnerabilityDiscoveries {
    <#
        .SYNOPSIS
        This function gets all the discoveries of a given vulnerability found in 
        Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, vulnerabilityId) in order to get
        all the discoveries of a given vulnerability found in Rapid7 InsightAppSec. 

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER vulnerabilityId
        This parameter expects a string value corresponding to the vulnerabilty ID of the
        vulnerabilty discoveries that are being gathered.

        .OUTPUTS
        The output type of this function is System.Array. Each element in the array
        is of type System.Object (PSCustomObject), and has a structure like the below.

        id            : 22945b6a-6bee-46fd-8c29-7eee0713127b
        vulnerability : @{id=9116ef2b-52f1-471f-81c2-ef835b24c34a}
        scan          : @{id=60ba56c2-5f66-4734-a0c5-ac7fb05e73b8}
        discovered    : 2020-10-15T20:51:48.525612
        links         : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/vulnerabilities/22945b6a-6bee-46fd-8c29-7eee0713127b}}

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            vulnerabilityId = '9116ef2b-52f1-471f-81c2-ef835b24c34a'
        }
        $return = Get-Rapid7AppSecVulnerabilityDiscoveries @splat
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$vulnerabilityId
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/vulnerabilities/$vulnerabilityId/discoveries/?size=1000"
    do {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Get'
                Headers = $headers
                ContentType = 'application/json'
            }
            $return = Invoke-RestMethod @splat
            [array]$vulnerabilityDiscoveries += $return.data
            $uri = $return.links.href[($return.links.rel.IndexOf('next'))]    
        } catch {
            Write-Warning "Unable to get Rapid7 AppSec vulnerability discoveries."   
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    } until (($return.links.rel.IndexOf('next')) -eq -1)
    $vulnerabilityDiscoveries
}

function Get-Rapid7AppSecVulnerability {
    <#
        .SYNOPSIS
        This function gets an individual vulnerability found in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, vulnerabilityId) to get a given
        vulnerability found in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER vulnerabilityId
        This parameter expects a string value corresponding to the vulnerabilty ID of the
        vulnerabilty that is being gathered.

        .OUTPUTS
        The output type of this function is of type System.Object (PSCustomObject), and 
        has a structure like the below.

        id         : 9116ef2b-52f1-471f-81c2-ef835b24c34a
        app        : @{id=e367b47e-a7dd-46d0-8bda-02a7c515c164}
        root_cause : @{url=http://webscantest.com/login.php; parameter=passwd; method=POST}
        severity   : HIGH
        status     : UNREVIEWED
        variances  : {@{original_value=x7pjj6fr%24; original_exchange=; module=; attack=; attack_value=Username=admin
                    and
                    Password=admin; message=Logged in state was detected with the regex match 'logout'; proof=logout; attack_exchanges=System.Object[]; proof_description=Logged in state was detected     
                    with the regex match 'logout'}}
        links      : {@{rel=self; href=https://us.api.insight.rapid7.com:443/ias/v1/vulnerabilities/9116ef2b-52f1-471f-81c2-ef835b24c34a}}

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            vulnerabilityId = '9116ef2b-52f1-471f-81c2-ef835b24c34a'
        }
        $return = Get-Rapid7AppSecVulnerability @splat
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$vulnerabilityId
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/vulnerabilities/$vulnerabilityId"
    try {
        $splat = @{
            Uri = $uri
            Method = 'Get'
            Headers = $headers
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to get Rapid7 AppSec vulnerability."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}

function Remove-Rapid7AppSecAppScan {
    <#
        .SYNOPSIS
        This function deletes a given App scan in Rapid7 InsightAppSec.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, scanId) in order to remove
        a given scan from Rapid7 InsightAppSec. Note that only failed scans can be
        removed.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER scanId
        This parameter expects a string value corresponding to the scan ID of the
        scan that is to be stopped.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            scanId = '934b9a58-6e9f-4824-9b81-f57bcd1f3145'
        }
        Remove-Rapid7AppSecAppScans @splat
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$scanId
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scans/$scanId"
    if ($PSCmdlet.ShouldProcess("$uri with App name, $appName and scan ID, $scanId", "Removing Rapid7 InsightAppSec App scan")) {
        try {
            $splat = @{
                Uri = $uri
                Method = 'Delete'
                Headers = $headers
                ContentType = 'application/json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to remove Rapid7 AppSec scan."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }
}

function Stop-Rapid7AppSecScan {
    <#
        .SYNOPSIS
        This function stops an a scan for a Rapid7 InsightAppSec App.

        .DESCRIPTION
        This function requires 2 parameters (rapid7ApiKey, scanId) to get a given
        vulnerability found in Rapid7 InsightAppSec.

        .PARAMETER rapid7ApiKey
        This parameter expects a string value corresponding to the API key to use when 
        accessing the Rapid7 InsightAppSec platform.

        .PARAMETER scanId
        This parameter expects a string value corresponding to the scan ID of the
        scan that is to be stopped.

        .OUTPUTS
        N/A

        .EXAMPLE
        $splat = @{
            rapid7ApiKey = <omitted>
            scanId = '9116ef2b-52f1-471f-81c2-ef835b24c34a'
        }
        Stop-Rapid7AppSecScan @splat
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$scanId
    )

    $headers = @{'X-Api-Key' = $rapid7ApiKey}
    $uri = "https://us.api.insight.rapid7.com/ias/v1/scans/$scanId/action"
    $body = @{
        action = 'Stop'
    } | ConvertTo-Json
    try {
        $splat = @{
            Uri = $uri
            Method = 'Put'
            Headers = $headers
            Body = $body
            ContentType = 'application/json'
        }
        Invoke-RestMethod @splat
    } catch {
        Write-Warning "Unable to stop Rapid7 AppSec scan."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
    }
}

function Set-Rapid7AppSecAppHttpHeadersConfig {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER rapid7ApiKey

        .PARAMETER appName

        .PARAMETER scanConfigName

        .PARAMETER headerName

        .PARAMETER headerValue
        
        .OUTPUTS

        .EXAMPLE
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param
    (
        [Parameter(Mandatory = $True)] [string]$rapid7ApiKey,
        [Parameter(Mandatory = $True)] [string]$appName,
        [Parameter(Mandatory = $True)] [string]$scanConfigName,
        [Parameter(Mandatory = $True)] [string]$headerName,
        [Parameter(Mandatory = $True)] [string]$headerValue
    )

    $body = [PSCustomObject]@{
        http_headers_config = @{
            custom_headers_list = @(
                "$headerName`:$headerValue"  
            )
        }
    } | ConvertTo-Json -Depth 100
    $headers = @{'X-Api-Key' = $rapid7ApiKey }
    if ($PSCmdlet.ShouldProcess("$uri with App name, $appName and $scanScopeUrl", "Set header config for Rapid7 InsightAppSec App")) {
        try {
            $appId = (Get-Rapid7AppSecApps -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like $appName }).id
            $scanConfigId = (Get-Rapid7AppSecScanConfigs -rapid7ApiKey $rapid7ApiKey | Where-Object { $_.name -like "$scanConfigName" -and $_.app.id -like $appId }).Id
            $uri = "https://us.api.insight.rapid7.com/ias/v1/scan-configs/$scanConfigId/options"
            $splat = @{
                Uri = $uri
                Method = 'Put'
                Body = $body
                Headers = $headers
                ContentType = 'application/json'
            }
            Invoke-RestMethod @splat
        } catch {
            Write-Warning "Unable to set HTTP header config on Rapid7 AppSec app scan config, $scanConfigName for App, $appName."
            $ErrorMessage = $_.Exception.Message
            Write-Warning "$ErrorMessage"
        }
    }   
}

function Get-Rapid7CloudSecInsights {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $domain
    )

    $headers = @{
        'api-key' = "$apiKey"
        'accept-encoding' = 'gzip'
        'accpet' = 'application/json'
        'content-type' = 'application/json'
    }
    $uri = "https://$domain/v2/public/insights/list"
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
    }
    Invoke-RestMethod @splat
}

function Get-Rapid7CloudSecFilterRegistry {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $domain
    )

    $headers = @{
        'api-key' = "$apiKey"
        'accept-encoding' = 'gzip'
        'accpet' = 'application/json'
        'content-type' = 'application/json'
    }
    $uri = "https://$domain/v2/public/insights/filter-registry"
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
    }
    $registry = Invoke-RestMethod @splat
    $members = $registry | Get-Member | Where-Object {$_.MemberType -like 'NoteProperty'}
    $members | ForEach-Object {[array]$filters += $registry."$($_.name)"}
    $filters
}

function Get-Rapid7CloudSecInsightPacks {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $domain
    )

    $headers = @{
        'api-key' = "$apiKey"
        'accept-encoding' = 'gzip'
        'accpet' = 'application/json'
        'content-type' = 'application/json'
    }
    $uri = "https://$domain/v2/public/insights/packs/list"
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
    }
    Invoke-RestMethod @splat
}

function New-Rapid7CloudSecIaCScan {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $terraformPlanJson,
        [Parameter(Mandatory = $True)] [string] $configName,
        [Parameter(Mandatory = $True)] [string] $domain
    )

    $headers = @{
        'Accept' = 'application/json'
        'Content-Type' = 'application/json'
    }
    $uri = "https://$domain/v3/iac/scan?readable=false"
    $uri = [uri]::EscapeUriString($uri)
    $body = @{
        iac_provider = 'terraform'
        scan_template = $terraformPlanJson
        config_name = $configName
        scan_name = "api-initiated-scan-$(New-Guid)"
        author_name = "api"
    }
    $splat = @{
        Method = 'Post'
        Uri = $uri
        Headers = $headers
        Body = $body | ConvertTo-Json -Depth 100
    }
    Invoke-RestMethod @splat
}

function Get-Rapid7CloudSecFindings {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $domain,
        [Parameter(Mandatory = $True)] [string] $insightPackName,
        [Parameter(Mandatory = $False)] [array] $scopes
    )

    $insightPacks = Get-Rapid7CloudSecInsightPacks -apiKey $apiKey -domain $domain 
    $insightPack = $insightPacks | Where-Object {$_.name -like "$insightPackName"}
    $insights = $insightPack.backoffice + $insightPack.custom
    
    $headers = @{
        'api-key' = "$apiKey"
        'accpet' = 'application/json'
        'content-type' = 'application/json'
    }
    $uri = "https://$domain/v2/public/resource/query"
    $uri = [uri]::EscapeUriString($uri)

    if ($PSBoundParameters.ContainsKey('scopes')) {
        $bodyScopes = $scopes
    } else {
        $bodyScopes = @()
    }

    foreach ($insight in $insights) {
        $detailedInsight = Get-Rapid7CloudSecInsight -apiKey $apiKey -domain $domain -insightId $insight -insightSource 'backoffice' | Select-Object -Property * -ExcludeProperty counts
        $offset = 0
        $limit = 50
        $body = @{
            resource_types = $detailedInsight.resource_types
            selected_resource_type = ($detailedInsight.resource_types -join ',' )
            scopes = $bodyScopes
            filters = @()
            offset = $offset
            limit = $limit
            order_by = ''
            insight = "$($detailedInsight.source):$insight"
            insight_exemptions = $false
        }

        $all = $null
        do {
            $body.offset = $offset
            $splat = @{
                Method = 'Post'
                Uri = $uri
                Headers = $headers
                Body = ($body | ConvertTo-Json -Depth 100)
            }
            [array]$resources = Invoke-RestMethod @splat
            [array]$all += $resources.resources.$($detailedInsight.resource_types)
            $offset = $offset + $limit
        } until ($resources.resources.Count -lt $limit)
        [array]$report += [PSCustomObject]@{
            insight = $detailedInsight
            resources = $all
        }
    }   

    # If the below is not done, the tags property of each resource is a PSCustomObject with a member for each tag rather than an array
    foreach ($resource in $report.resources) {
        if ($null -ne $resource.common.tags) {
            $oldTags = $resource.common.tags
            $newTags = $null
            foreach ($tag in ($oldTags | Get-Member | Where-Object {$_.MemberType -like 'NoteProperty'})) {
                [array]$newTags += [PSCustomObject]@{
                    TagName = $tag.name
                    TagValue = $oldTags.($tag.name)
                }
            }
            $resource.common.tags = $newTags
            $tagString = ($resource.common.tags | ForEach-Object {"$($_.TagName):$($_.TagValue)"}) -join ','
            $resource.common | Add-Member -MemberType NoteProperty -Name tag_string -Value $tagString -Force
        } else {
            if ($null -ne $resouce.common) {
                $resource.common | Add-Member -MemberType NoteProperty -Name tags -Value $null -Force
            }
        }
    }
    $report
}

function Get-Rapid7CloudSecInsight {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $apiKey,
        [Parameter(Mandatory = $True)] [string] $domain,
        [Parameter(Mandatory = $True)] [string] $insightId,
        [Parameter(Mandatory = $True)] [string] $insightSource
    )

    $headers = @{
        'api-key' = "$apiKey"
        'accept-encoding' = 'gzip'
        'accpet' = 'application/json'
        'content-type' = 'application/json'
    }
    $uri = "https://$domain/v2/public/insights/$insightId/$insightSource"
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
    }
    Invoke-RestMethod @splat
}