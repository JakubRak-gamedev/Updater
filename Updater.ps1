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

Invoke-WebRequestWithProxyDetection -Uri "https://github.com/JakubRak-gamedev/Updater/releases/latest/download/$scriptName" -OutFile $tempFullName
Confirm-Signature -File $tempFullName

# SIG # Begin signature block
# MIINxAYJKoZIhvcNAQcCoIINtTCCDbECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUoslGf3oJolNtrCg1QzEgsPNh
# Dcugggs+MIIFkTCCA3mgAwIBAgIUXLFVzgd31jXC7h7dxgMcN8IB4rUwDQYJKoZI
# hvcNAQELBQAwNzELMAkGA1UEBhMCUEsxEDAOBgNVBAoTB0NvZGVnaWMxFjAUBgNV
# BAMTDUNvZGVnaWMgQ0EgRzIwHhcNMjUwMjExMTEzNzIzWhcNMjUwNDEyMTAzNzIz
# WjBOMRwwGgYJKoZIhvcNAQkBFg1qYWt1YkBzaWl0LnBsMRIwEAYDVQQDEwlKYWt1
# YiBSYWsxDTALBgNVBAoTBFNJSVQxCzAJBgNVBAYTAlBMMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAxgEeGDCXhGqqxa9U70bI8OQc0e0fQHL6rJEikYVU
# Lino02O5UuX2Z2tfoxyqs0QtoDGr1rUzuyXw5wTC2AJPbMN8kYbI3/FYBW8tggAr
# Or+2kaqWOmUf+dsXN0I7shcGY+32E1L2S6xQhpPNU90SHydH5GUBeMdbjRRwHK3v
# ePjACCo+NMhYEl/M7iX50C1mAi1KgI1dKi1Uslmykdlu8+oByr4w0VjfGnoiaB5W
# H3jEOrzoZTWiFm5ZMjq8YSQsk9iEHEGPmGXOtzOKN0URU9dwxxXlJP2JfvYvIhAH
# 5/a9MTrSlEHzjLF0nWwXezra24wdQXzUulUrE7gub2AawQIDAQABo4IBfDCCAXgw
# FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQY
# MBaAFJXrz/R5EzTy3VAeQXtrcU5Q6BAIMIHFBgNVHSAEgb0wgbowgbcGCSsGAQQB
# g6hkATCBqTCBpgYIKwYBBQUHAgIwgZkMgZZBcyBwZXIgdGhpcyBwb2xpY3kgaWRl
# bnRpdHkgb2YgdGhlIHN1YmplY3QgaXMgbm90IGlkZW50aWZpZWQuIFlvdSBtdXN0
# IG5vdCB1c2UgdGhlc2UgY2VydGlmaWNhdGVzIGZvciB2YWx1YWJsZSB0cmFuc2Fj
# dGlvbnMuIE5PIExJQUJJTElUWSBJUyBBQ0NFUFRFRC4wCQYDVR0TBAIwADA7BgNV
# HR8ENDAyMDCgLqAshipodHRwczovL3BraS5jb2RlZ2ljLmNvbS9jcmxzL0NvZGVn
# aWNDQS5jcmwwHQYDVR0OBBYEFN4Q5d8nRYcB+4HTGEoVL/Oz9u2/MA0GCSqGSIb3
# DQEBCwUAA4ICAQBdalQdCfje9KzDn0UKQLt3zploRqhk3f42pyDmR+jfFFdg0Ueh
# WwlkaxZyvdeUffQw3OYnQjGjTfUDP1AcvCNxmRjgx4uv/NTTmG6f7mA8xqTz6ukb
# oTHR5EWaui44pTwOCOJ4CF6SOWztAYPm6Z6k5QGSE6CjsqTsRPHWXACJRjPKCcsD
# L5mlbEO6PmD2+7iDx3WJ3s7FZg5SgR0RezrcR/SQhXMc4/ue/5oOq8R0grHKjocx
# pCu2VO8Y1BvEi02S/U+LnwOQtzgFySInTfyNwS4WsKJlwmR5ofd/2xgrXjF4VFk/
# G1IBuWMuqVlxN0tpU4HSsXrzaOrsNOoYGS0oQ4FVNGbvglIFVcYzcKcHzsI2iumV
# Vl8iiSJA7o5Q1Ifh2P2j1JGDySJzHGgdQn0osMvZ3ef6A3yHP/uS6Gi9L7zffZJK
# JRdY0Yj6pgqWopcKN8XJavdcJbIEIYvVqTUhlFgVDYWRt1N6Owb2/iTKCbN/iueY
# rTYlUNwLVvgz/nxzZUPVXrmZBE0xUAG7JL77tXWZz0SigDHQ43LOShWdhpgZBWMC
# 88gyltD/kt0TbmSxEXfna6ZEeSDFmXhXJYgNQ1snh/BS2DV5cnjXDI1Ac+ukRE2V
# nRoCjtXFggKqNY+VsIY3US4Obdg/gmLHzAAeckYYtbOiTrbLfpGv7cOiRzCCBaUw
# ggONoAMCAQICFDowdofT+XUnwL7ki+mCzPL9Duc/MA0GCSqGSIb3DQEBDQUAMDwx
# CzAJBgNVBAYTAlBLMRAwDgYDVQQKEwdDb2RlZ2ljMRswGQYDVQQDExJDb2RlZ2lj
# IFJvb3QgQ0EgRzIwHhcNMjExMjA3MTAxOTU2WhcNNDkxMjA3MTAxOTU1WjA3MQsw
# CQYDVQQGEwJQSzEQMA4GA1UEChMHQ29kZWdpYzEWMBQGA1UEAxMNQ29kZWdpYyBD
# QSBHMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIxdsKkzlHrRPy58
# fVGka9JnRAC7Xb5Mn19MHMsCEz5ptVvdAJVFI3E1sVRR7C/jh4Wb2EE6+ngv1ABJ
# dNFjKQjUJatIBn/5TARPPQ4XZH4wvxlf+sEXQYts1A484nEjkkSTtsLE43NMZKPO
# jME/BHhvVi2i47t3Z6+SnIT6ucxXp5w7fIKHk5SpPCd4+Lq9EXI8PbmeL6MOmPQk
# w3925dMlkIBG7puElq/neVlOwA23sH8tJlTtHdqzOfch8+dAcj4S906ty7egsneg
# vHJ2iGY4ewqIfzuWK0Ym6NSxMXrmbBpgGBYPzFGTijSkqs9g1m7kzomkuK2hUNjP
# +4QjUBNnxm9qBpVdIrw26kYk8AuJa0GiTTpCxGs+Tt/L48961UPvQnwzMQLTYEG6
# gFZHQ2SLsAfEH7v4mbdhv1GHvv82t70MYpQZel/hCOaBzabaVV0qWf9vd7BLseq5
# HU9rp358G57KLo8Sg7auRSt5yx1Uu3u3uJFHq2XzZVv0IiZxttcHt9ZH2vqiSvFz
# KlD0WLiorF331XRf24zS0eOzGP1PNmSnNlMeKpW/mopsyGo/olGYjdm/qeUHqsTM
# fnm1oRm4IENfgfur/I+O8kbRnhJVUG+K4UcZnMgWH3gCtF0VbVE8sTSFkocjymlc
# ZI7UDdX3YsZ/brogDgPTjl3YUoDhAgMBAAGjgaMwgaAwDwYDVR0TAQH/BAUwAwEB
# /zAOBgNVHQ8BAf8EBAMCAQYwHwYDVR0jBBgwFoAUsL8sJ62K4SFQtz1Rq8JX5g0W
# ezowPQYDVR0fBDYwNDAyoDCgLoYsaHR0cHM6Ly9wa2kuY29kZWdpYy5jb20vY3Js
# cy9Db2RlZ2ljUm9vdC5jcmwwHQYDVR0OBBYEFJXrz/R5EzTy3VAeQXtrcU5Q6BAI
# MA0GCSqGSIb3DQEBDQUAA4ICAQANG37Y2KcjlJZ7Roc9hnJX5Sl+gklV0ziUwSAs
# Vzd3Zh3RNYnL0nAbQxirWzrSyDMy9pYILONejb/CU9EBGunFUP5W3IUjaX1uQcgg
# QcS8si0VbEMrX3WpzrRCLQveey95rqjwsSlUZLP+pYEqf+ssI9fPziHP8PdvbCen
# t8MxiFwiz0A0pWFioyk53dcua4bRFwHGzd0PdkmCH0KdsC17GWFfM1bdn3SLapQH
# Wzv3B+fl18xSYzGeDdTO4DIGOxRRUEJBRp7qtNr/lfYuotruPjm59h/NmzMsQ9NJ
# 2mJDcHObL69EiKFaUdE4bTHuEczaiLkSlHQKSekMYxDeSVfanbhbqn2VEbxu7JJV
# r1XM9CC2H3Kjx18QnULztQMsJB+UViwhX2Qr8y7jEYnqDWSBbtHNl7ua78pJd2QE
# FMYO6RNLMiSTWSup5M5wwBsEbCABVv53HIl1LM4eXVTINdXyd6YIFvrpKuvfQ9vZ
# x9HblPk8XKhie0Ja+xKcqrWc+6OK86DXm8X4qOrjklniX9m1cKxM3RerFLPWZXxF
# va/xCKcWbJmXyU9PtvTMRAJdvPVQeNsNeCC5Tr0iDARfuMT+o3YMtEfRx9AZPtBR
# wEHUPF4N6b7vxrXZFz6MlDLYc8SMCBYzdPmI5/xtSQjFuOaE+XolwfQpq9uuXXnV
# /pcuwTGCAfAwggHsAgEBME8wNzELMAkGA1UEBhMCUEsxEDAOBgNVBAoTB0NvZGVn
# aWMxFjAUBgNVBAMTDUNvZGVnaWMgQ0EgRzICFFyxVc4Hd9Y1wu4e3cYDHDfCAeK1
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBRIf3Wfyqx432donVrQDzDwFhN76zANBgkqhkiG9w0B
# AQEFAASCAQAaydIm4bqo9u5e6rsgCPQ2kRkvgMcOgH2XnRzmhivKcps2mxyfoLqJ
# At/bSpB7aTWBqet9st8pXhPf2vZQgU3b+TCxgZnZOSClaiWjQFfC7wrPaf/7ms8u
# tCm3eDRbvsMCycRf8xB3IWbS3OTmTwHSPjtYlNE58R602bFBcOsEHyCQUSGGyuFj
# OK2+UyRCbIKSDNQnmekGdxU9Fk1zx8nsfEpt+rj6UW0mJQnet8yR2fGNj9tx9YCA
# loczchR7g5/mymiDTW4bDWd5AoBceT+TeMD3EhGeVXJ8kr6j9dH7JKQgLTeQSQXj
# NX8g4K7wgG37PuiNfp7hnzIuguI+oGqo
# SIG # End signature block
