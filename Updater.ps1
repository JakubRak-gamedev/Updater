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


function Confirm-Signature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $File
    )

    $IsValid = $false
    # $MicrosoftSigningRoot2010 = 'CN=PowerShellCA, O=PowerShell Script - Jakub Rak'
    # $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File

        if ($sig.Status -ne 'Valid') {
            Write-Warning "Signature is not trusted by machine as Valid, status: $($sig.Status)."
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        # if (-not $chain.Build($sig.SignerCertificate)) {
        #     Write-Warning "Signer certificate doesn't chain correctly."
        #     throw
        # }

        # if ($chain.ChainElements.Count -le 1) {
        #     Write-Warning "Certificate Chain shorter than expected."
        #     throw
        # }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            Write-Warning "Top-level certificate in chain is not a root certificate."
            throw
        }

        # if ($rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2010 -and $rootCert.Certificate.Subject -ne $MicrosoftSigningRoot2011) {
        #     Write-Warning "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)."
        #     throw
        # }

        Write-Host "File signed by $($sig.SignerCertificate.Subject)"

        $IsValid = $true
    } catch {
        $IsValid = $false
    }

    $IsValid
}

function Get-ScriptUpdateAvailable {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]
        $VersionsUrl = "https://github.com/JakubRak-gamedev/Updater/releases/latest/download/Version.csv"
    )

    $BuildVersion = "0.0.0"

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $result = [PSCustomObject]@{
        ScriptName     = $scriptName
        CurrentVersion = $BuildVersion
        LatestVersion  = ""
        UpdateFound    = $false
        Error          = $null
    }

    if ((Get-AuthenticodeSignature -FilePath $scriptFullName).Status -eq "Signed") {
        Write-Warning "This script appears to be an unsigned test build. Skipping version check."
    } else {
        try {
            $versionData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequestWithProxyDetection -Uri $VersionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
            $latestVersion = ($versionData | Where-Object { $_.File -eq $scriptName }).Version
            $result.LatestVersion = $latestVersion
            if ($null -ne $latestVersion) {
                $result.UpdateFound = ($latestVersion -ne $BuildVersion)
            } else {
                Write-Warning ("Unable to check for a script update as no script with the same name was found." +
                    "`r`nThis can happen if the script has been renamed. Please check manually if there is a newer version of the script.")
            }

            Write-Verbose "Current version: $($result.CurrentVersion) Latest version: $($result.LatestVersion) Update found: $($result.UpdateFound)"
        } catch {
            Write-Verbose "Unable to check for updates: $($_.Exception)"
            $result.Error = $_
        }
    }

    return $result
}

function Invoke-ScriptUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([boolean])]
    param ()

    $scriptName = $script:MyInvocation.MyCommand.Name
    $scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
    $scriptFullName = (Join-Path $scriptPath $scriptName)

    $oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
    $oldFullName = (Join-Path $scriptPath $oldName)
    $tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

    if ($PSCmdlet.ShouldProcess("$scriptName", "Update script to latest version")) {
        try {
            Invoke-WebRequestWithProxyDetection -Uri "https://github.com/JakubRak-gamedev/Updater/releases/latest/download/$scriptName" -OutFile $tempFullName
        } catch {
            Write-Warning "AutoUpdate: Failed to download update: $($_.Exception.Message)"
            return $false
        }

        try {
            if (Confirm-Signature -File $tempFullName) {
                Write-Host "AutoUpdate: Signature validated."
                if (Test-Path $oldFullName) {
                    #Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                }
                Move-Item $scriptFullName $oldFullName
                Move-Item $tempFullName $scriptFullName
                #Remove-Item $oldFullName -Force -Confirm:$false -ErrorAction Stop
                Write-Host "AutoUpdate: Succeeded."
                return $true
            } else {
                Write-Warning "AutoUpdate: Signature could not be verified: $tempFullName."
                Write-Warning "AutoUpdate: Update was not applied."
            }
        } catch {
            Write-Warning "AutoUpdate: Failed to apply update: $($_.Exception.Message)"
        }
    }

    return $false
}

Invoke-ScriptUpdate

# SIG # Begin signature block
# MIIFiAYJKoZIhvcNAQcCoIIFeTCCBXUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMCiPFZTvdlbFBtPSLjtoOA2N
# exqgggMmMIIDIjCCAg6gAwIBAgIQ4+HT6HBtPLVOFZ+0C8SWxzAJBgUrDgMCHQUA
# MBcxFTATBgNVBAMTDFBvd2VyU2hlbGxDQTAeFw0yNTAyMDcxMjMxNDVaFw0zOTEy
# MzEyMzU5NTlaMCgxJjAkBgNVBAMTHVBvd2VyU2hlbGwgU2NyaXB0IC0gSmFrdWIg
# UmFrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2olY6Z/X8ssoBYR7
# irJoagU92gqNY1KO7jGX+ikzf/g1YeBGdEeRa5PqEJLOkwE4DkAt4Us6xEH5Tgp9
# U9Bqu9hJZULu9AAnrSzupJwrPMmXW5AiaZG257BBJZNIRmWNswoeQ+xsmo2G0bTS
# 2p/K7jsMhU2DeLVhto45XmAPga1cFBDBg0C0CEcgxwHrz2K8GTayq9gdm5TmOk0j
# 31j+1D3QGMq1HDFREHRcCKrQccsC3HuL69qpIV1cPWdbC40y+NeJ+cPhT31r6ArM
# Udf0KPt9caoJe/n9ARQ/2zWIIMhcELcSAadUxj/x8lZxIX4tNGYDHiArb0hrKYtA
# LSPXxQIDAQABo2EwXzATBgNVHSUEDDAKBggrBgEFBQcDAzBIBgNVHQEEQTA/gBBb
# aMuNWajk3GcB9qPfFLv8oRkwFzEVMBMGA1UEAxMMUG93ZXJTaGVsbENBghCkGMXy
# pe71lULXflDzW404MAkGBSsOAwIdBQADggEBAEfXFTpBjoTE8mcMYT+4QYOPphNy
# tPw6aL10CuTIY+jixccq0irlyZL9h7AVbAcBwkoTwYrZaI9N35ChwwDHbqYmmlbC
# P/R6PGnzutY684jozxmcpHQZKSLzZz3o2jMYAZsBeCVPy1YZVs94dYo73qFDJFeb
# /DSBMaDqOWKmJZtN7GHB/eEhkArYSFB8ik4IX/4Kwso+apoayV8BU9DOSrQYbOy/
# C6BqbfDswhS/5HnH4nspuexXFqZPCD1d+X4j2GEp1uYauB5F+WbeWQr0Fp2UsXQO
# byPCQMK73bMydXbJpz6kbYCY38O6HPcouyWDZrg+OPlCv+z7kouvM160/AcxggHM
# MIIByAIBATArMBcxFTATBgNVBAMTDFBvd2VyU2hlbGxDQQIQ4+HT6HBtPLVOFZ+0
# C8SWxzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQUP8MjP4x4wQ3Fq5nUihc8xnoRdm8wDQYJKoZI
# hvcNAQEBBQAEggEAA4DC57EM+J0/FcMLGkT007Cfy5lEKXf0PxojEBkA5eoxlSya
# Pl3hAcbVUYrnctlve79Hb6rc3M3+fKNG4AUpZfmuZaSykRCcT4ASaRsn317Z4+oQ
# cCevHBRZTOpmwFg1lT0485xQKUCX2aeDVK08MMpo1CucoTaQoeUKSudujjxbia1J
# LyUMX7Q/AFAPj0bydZLpK0jhvt98kUY9LvQYsE5IbFyyFZXUvpi6fUagIYYq9BVA
# ibO0oIgdXjEOuYg3Blkj3RWc+6SLVJeMuS+cN7zeBstPkgfZKv/ZDk/Vtg91pNss
# bTgDWHO2rVW9efjp0neDyV4zj60LEDYcw862ag==
# SIG # End signature block
