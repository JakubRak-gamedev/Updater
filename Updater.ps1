<#
.PARAMETER OutputFilePath
	This optional parameter allows an output directory to be specified. Default location is the current directory.
.PARAMETER AnalyzeDataOnly
    Switch to analyze the existing HealthChecker XML files. The results are displayed on the screen and an HTML report is generated.
.PARAMETER SkipVersionCheck
    No version check is performed when this switch is used.
.PARAMETER ScriptUpdateOnly
    Switch to check for the latest version of the script and perform an auto update. No elevated permissions or EMS are required.
.PARAMETER Verbose
	This optional parameter enables verbose logging.
#>

param(
    [Parameter(Mandatory = $false, HelpMessage = "Provide the location of where the output files should go.")]
    [ValidateScript( { Test-Path $_ })]
    [string]$OutputFilePath = ".",

    [Parameter(Mandatory = $false, HelpMessage = "Enable to reprocess the data that was previously collected and display to the screen")]
    [switch]$AnalyzeDataOnly,

    [Parameter(Mandatory = $false, HelpMessage = "Skip over checking for a new updated version of the script.")]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $false, HelpMessage = "Only attempt to update the script.")]
    [switch]$ScriptUpdateOnly
)

begin {

$ScriptDisplayName = "Script Updater"
$ScriptVersion = "0.0.0"
$VersionsUrl = "https://github.com/JakubRak-gamedev/Updater/releases/latest/download/Version.csv"
$ScriptUrl = "https://github.com/JakubRak-gamedev/Updater/releases/latest/download"

function Write-HostLog ($message) {
    if ($Script:OutputFullPath) {
        $message | Out-File ($Script:OutputFullPath) -Append
    }
}

function Write-Red($message) {
    Write-Host $message -ForegroundColor Red
    Write-HostLog $message
}

function Write-Yellow($message) {
    Write-Host $message -ForegroundColor Yellow
    Write-HostLog $message
}

function Write-Green($message) {
    Write-Host $message -ForegroundColor Green
    Write-HostLog $message
}

function Write-Grey($message) {
    Write-Host $message
    Write-HostLog $message
}

function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            Write-Verbose "Proxy server configuration detected"
            Write-Verbose $proxyObject.OriginalString
            return $true
        } else {
            Write-Verbose "No proxy server configuration detected"
            return $false
        }
    } catch {
        Write-Verbose "Unable to check for proxy server configuration"
        return $false
    }
}

function Invoke-WebRequestWithProxyDetection {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Default")]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [switch]
        $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = "ParametersObject")]
        [hashtable]
        $ParametersObject,

        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [string]
        $OutFile
    )

    Write-Verbose "Calling $($MyInvocation.MyCommand)"
    if ([System.String]::IsNullOrEmpty($Uri)) {
        $Uri = $ParametersObject.Uri
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Confirm-ProxyServer -TargetUri $Uri) {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell")
        $webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }

    if ($null -eq $ParametersObject) {
        $params = @{
            Uri     = $Uri
            OutFile = $OutFile
        }

        if ($UseBasicParsing) {
            $params.UseBasicParsing = $true
        }
    } else {
        $params = $ParametersObject
    }

    try {
        Invoke-WebRequest @params
    } catch {
        Write-VerboseErrorInformation
    }
}

function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl
    )

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $ScriptVersion
        LatestVersion  = ""
        LatestHash     = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "NotSigned") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection -Uri $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $latestHash = ($versionData | Where-Object { $_.File -eq $scriptName }).SHA256Hash
            $result.LatestVersion = $latestVersion
            $result.LatestHash = $latestHash
            if ($null -ne $latestVersion) {
                $result.UpdateFound = ($latestVersion -ne $ScriptVersion)
            } else {
                Write-Warning ("Unable to check for a script update as no script with the same name was found." +
                    "`r`nThis can happen if the script has been renamed. Please check manually if there is a newer version of the script.")
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Latest hash: $($result.LatestHash) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}

function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    $MicrosoftSigningRoot2010 = 'CN = PowerShellCA'
    $MicrosoftSigningRoot2011 = 'CN=Codegic Root CA G2, O=Codegic, C=PK'
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        if (-not $chain.Build($sig.SignerCertificate)) {
            Write-Warning "Signer certificate doesn't chain correctly."
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            Write-Warning "Certificate Chain shorter than expected."
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
            Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
            throw
        }

        Write-Verbose "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

<#
.SYNOPSIS
    Overwrites the current running script file with the latest version from the repository.
.NOTES
    This function always overwrites the current file with the latest file, which might be
    the same. Get-ScriptUpdateAvailable should be called first to determine if an update is
    needed.

    In many situations, updates are expected to fail, because the server running the script
    does not have internet access. This function writes out failures as warnings, because we
    expect that Get-ScriptUpdateAvailable was already called and it successfully reached out
    to the internet.
#>
function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionHash
    )

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection -Uri "$ScriptUrl/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }
        try {
            $tempFileHash = (Get-FileHash -Path $tempFullName -Algorithm SHA256).Hash
            if ($VersionHash -eq $tempFileHash) {
                Write-Host "AutoUpdate: File hash validated."
                if (Confirm-Signature -File $tempFullName) {
                    Write-Host "AutoUpdate: Signature validated."
                    if (Test-Path $oldFullName) {
                        Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                    }
                    Move-Item $scriptFullName $oldFullName
                    Move-Item $tempFullName $scriptFullName
                    Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                    Write-Host "AutoUpdate: Succeeded."
                    return $true
                } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
                }
            } else {
                Write-Warning "AutoUpdate: File hash is not valid: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

<#
    Determines if the script has an update available. Use the optional
    -AutoUpdate switch to make it update itself. Pass -Confirm:$false
    to update without prompting the user. Pass -Verbose for additional
    diagnostic output.

    Returns $true if an update was downloaded, $false otherwise. The
    result will always be $false if the -AutoUpdate switch is not used.
#>
function Test-ScriptVersion {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Need to pass through ShouldProcess settings to Invoke-ScriptUpdate')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [switch]
        $AutoUpdate,
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl
    )

    $updateInfo = Get-ScriptUpdateAvailable $VersionsUrl
    if ($updateInfo.UpdateFound) {
        if ($AutoUpdate) {
            return Invoke-ScriptUpdate -VersionHash $updateInfo.LatestHash
        } else {
            Write-Warning "$($updateInfo.ScriptName) $ScriptVersion is outdated. Please download the latest, version $($updateInfo.LatestVersion)."
        }
    }

    return $false
}

function Confirm-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

    return $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}

function New-LoggerInstance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeServerName = $false
    )
    $endName = "_{0}.txt" -f $Script:dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "_{0}{1}" -f $Server, $endName
    }

    $Script:OutputFullPath = Join-Path -Path $Script:OutputFilePath -ChildPath ('{0}{1}' -f $FileName, $endName)
}


    $scriptFileName = $script:MyInvocation.MyCommand.Name

    $Script:VerboseEnabled = $false
    #this is to set the verbose information to a different color
    if ($PSBoundParameters["Verbose"]) {
        #Write verbose output in cyan since we already use yellow for warnings
        $Script:VerboseEnabled = $true
        $VerboseForeground = $Host.PrivateData.VerboseForegroundColor
        $Host.PrivateData.VerboseForegroundColor = "Cyan"
    }

    $Script:date = (Get-Date)
    $Script:dateTimeStringFormat = $date.ToString("yyyyMMddHHmmss")

    New-LoggerInstance -FileName $scriptFileName -Server $env:COMPUTERNAME -IncludeServerName $true
    Write-Green "$ScriptDisplayName version $ScriptVersion"

} process {

    if (-not (Confirm-Administrator) -and (-not $AnalyzeDataOnly -and -not $ScriptUpdateOnly)) {
        Write-Warning "The script needs to be executed in elevated mode. Starting the script as an Administrator."
        if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
            $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
            Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
            exit
        }
    }

    if ($ScriptUpdateOnly) {
        return Test-ScriptVersion -AutoUpdate -VersionsUrl $VersionsUrl -Confirm:$false
    }

    if ((-not $SkipVersionCheck) -and (Test-ScriptVersion -AutoUpdate -VersionsUrl $VersionsUrl)) {
        Write-Yellow "Script was updated. Please rerun the command."
        return $true
    }

} end {

    if ($Script:VerboseEnabled) {
        $Host.PrivateData.VerboseForegroundColor = $VerboseForeground
    }

}
