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
    $MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

    try {
        $sig = Get-AuthenticodeSignature -FilePath $File
        Write-Host $sig.SignerCertificate

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
        Write-Host $chain.ChainElements.Count
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


$scriptName = $script:MyInvocation.MyCommand.Name
$scriptPath = [IO.Path]::GetDirectoryName($script:MyInvocation.MyCommand.Path)
$scriptFullName = (Join-Path $scriptPath $scriptName)

$oldName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + ".old"
$oldFullName = (Join-Path $scriptPath $oldName)
$tempFullName = (Join-Path ((Get-Item $env:TEMP).FullName) $scriptName)

#Invoke-WebRequestWithProxyDetection -Uri "https://github.com/JakubRak-gamedev/Updater/releases/latest/download/$scriptName" -OutFile $tempFullName
Confirm-Signature -File $scriptFullName

# SIG # Begin signature block
# MIIImQYJKoZIhvcNAQcCoIIIijCCCIYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkyEPfuNnhCWFByJOuzKwrPud
# Si2gggY0MIIDEDCCAfygAwIBAgIQBOpHyfZOEqRJYvW8/79TJzAJBgUrDgMCHQUA
# MBcxFTATBgNVBAMTDFBvd2VyU2hlbGxDQTAeFw0yNTAyMDcxNDA1NDlaFw0zOTEy
# MzEyMzU5NTlaMBoxGDAWBgNVBAMTD1Bvd2VyU2hlbGwgU0lJVDCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAL6JVeey7k5V9WVIkoJTqKsXJVNPcnyuktyn
# KlBX71FojTFqCVaCWOpJRXUcOBQgWZl2qYlnEe/IyzCxbVb46na+DiNh5ajaDieF
# u0e9Pdf89RKNuin9I3H67b8nK/4IskuORLBf9I8QWOJa0YcPKDdTI/ZhPwtsamNu
# bm8TVP5WZo9tNkTp5KCUTH3q6zPZH81/xTJ4bwY/2Gw8A6lUlk/h0eSZr7c1Qr+g
# j+NvD5TbJC5RKi/UNmpMi/2DusnS8zSSd7T+tIg1IAEr4JABo5XX1aYYTnU8i0yK
# 6VoQODYZkFa7bHrzl1C7VXwiStT/+TpZ5OOskpmjH9SgX6FTNI0CAwEAAaNdMFsw
# DwYDVR0TAQH/BAUwAwEB/zBIBgNVHQEEQTA/gBBbaMuNWajk3GcB9qPfFLv8oRkw
# FzEVMBMGA1UEAxMMUG93ZXJTaGVsbENBghCkGMXype71lULXflDzW404MAkGBSsO
# AwIdBQADggEBAAiNoKSn6Otq73MYVU9xRYJZN282s5Fp6SiTZWxgT9Cq9KSc+uEB
# EGiZt7Fnb8OqrkWkZSpGhpfFxoc1mqcM0ptVmiY/OydEL0DS6GhrSqioLJb2X0EA
# oiOXwm+Kf8wcCKsiLdzsxj+GFQBzDw/HkJJ6pQJcuoJdpljk73FZkV57dIGfnDME
# QQ2bxaTJBKdG+KLj8q3CP0O++SHQb231UN9jQOcrjPnsMnkuH0DfwHcrfxW7Lijw
# g30Ixexk1KXOr3cyNgBykcfTjrHzs+ZH2cgSo6OibINDMMVQhffPxoFLIM921PQm
# nHUUQBW9yp2dvAoqe38idkPjKbfIe9BUscwwggMcMIICCKADAgECAhBHM9HoaWFU
# lESOZx0uMzO+MAkGBSsOAwIdBQAwGjEYMBYGA1UEAxMPUG93ZXJTaGVsbCBTSUlU
# MB4XDTI1MDIwNzE0MDU0OVoXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUUG93
# ZXJTaGVsbCBKYWt1YiBSYWswggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDIsYiLOMa4GYpiqCzCiLieCW3MLB3bZDHm4snUCKXqHjv2Pqw6y7HndiRUaRMT
# sLhK4I2GrJlHet0oOUr63x/AIKQmuCpDS2Txp42MFzy5IWUD+ewErIXOSCeZ6ugH
# q1YmwjzYc746yoZQ5hxFSYZggDoLpope5Rl+CB8hgaDpY+g6eW5+rwfC3XSM+6yd
# pcuTpGQSVUj9rktzO9CE6bp3OAjVEMPlvYp/5rC+bz6UZcHPBonCfEYOw3DlMJoC
# L3WkwvsNcvftjhBMJzaOtBR8sxUbVEgbc9VG+Nw+RC6ETHrhcWBrezqYSnBwKZn5
# 0gHDWNOWCSSYQ2s4OXrhTed1AgMBAAGjYTBfMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MEgGA1UdAQRBMD+AEHitN+sFK8gvjZR579A8a9+hGTAXMRUwEwYDVQQDEwxQb3dl
# clNoZWxsQ0GCEATqR8n2ThKkSWL1vP+/UycwCQYFKw4DAh0FAAOCAQEARzOx7Rn6
# v40xq9unz0wkm2IyXF8WO57zJ05mc+gucWbGfHyavVbspOPWmNiacTIGngFsIUgl
# +YjXmoIpV+dGr+Vz67yZfwMvGtm3SccYLQjvsLuvQThY5lTa6oD6c5yYasAvIAgP
# O0mwB6372/4WLZ+cOJ4Hz2TsrT1st/JdZOtMGc6/bUR/zzLOiFW5D2eB4vIZvvAK
# 0h4ELJuDJxSRSczQfiusOYL+HXXS0tjiu2+ETZjGEybPLoBZULx+hMpAc4VxKgOh
# f3lSxZCU3QpHrgETIlWnEPKVYKCTqrKW6Ac6CNxvA4YedB/IwMCaC43c84srXnWL
# mA3c3vRNDS9C1TGCAc8wggHLAgEBMC4wGjEYMBYGA1UEAxMPUG93ZXJTaGVsbCBT
# SUlUAhBHM9HoaWFUlESOZx0uMzO+MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEM
# MQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRe2vH38sMfib1l
# w+v6g1kp8FZfEDANBgkqhkiG9w0BAQEFAASCAQB82nKHFGt3t6dtXlKiRGCAKM6h
# SpzPoBvMkEqiTqfyRH3fUyznnAHpUYzNYno6Vjxlcd9smY5DtOcuClw43Gqco/6z
# 6wN59YHPfGfL8GmwzuB518kc0wk02k7F+qvI5TUPgcCr5vGK6cMDnfoOvtl0e6c5
# Bgw4kW4A3cncGFqaYBi+WH+KIHGmuhPTccKl3Zx4wWEd63rkxnKK98M0po2QuVba
# soC1J8KL5oQqRMvcG5/ZsivYl8A4Re44yAXHGfziqfRDIYr34QAYRO9UAxBMHM/3
# Ku6EaovHdipC4/k89K8RRhEYw59NFhr2jHYJvj9Zyr836gWyDRf9d1UaHEqA
# SIG # End signature block
