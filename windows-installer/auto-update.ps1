#Requires -RunAsAdministrator

Param(
    [Parameter(Mandatory=$true)]
    [string]$InstallDir
)

Start-Transcript -Path "C:\Certbot\log\auto-update.log"
trap {
    Stop-Transcript
}

$ErrorActionPreference = 'Stop'

$installerAuthenticodeCertificateThumbprint = "74B2E146A82F2B71F8EB4B13EBBB6F951757D8C2"

# Get current local certbot version
try {
    $currentVersion = certbot --version
    $currentVersion = $currentVersion -replace '^certbot (\d+\.\d+\.\d+).*$', '$1'
} catch {
    "An error occured while fetching the current local certbot version:"
    $_.Exception
    "Assuming Certbot is not up-to-date."
    $currentVersion = "0.0.0"
}

# Get latest remote certbot version
try {
    $result = Invoke-RestMethod -Uri https://api.github.com/repos/certbot/certbot/releases/latest
    $latestVersion = $result.tag_name -replace '^v(\d+\.\d+\.\d+).*$', '$1'
} catch {
    "Could not get the latest remote certbot version. Error was:"
    $_.Exception
    throw "Aborting auto-upgrade process."
}

if ([System.Version]"$currentVersion" -ge [System.Version]"$latestVersion") {
    "No upgrade is needed, Certbot is already at the latest version ($currentVersion)."
} else {
    # Search for the Windows installer asset
    $installerUrl = $null
    foreach ($asset in $result.assets) {
        if ($asset.name -match '^certbot-.*installer-win32\.exe$') {
            $installerUrl = $asset.browser_download_url
        }
    }

    if ($null -eq $installerUrl) {
        throw "Could not find the URL for the latest Certbot for Windows installer."
    }

    "Starting Certbot auto-upgrade from $currentVersion to $latestVersion ..."

    $installerPath = "$env:TMP/certbot-installer-win32.exe"
    try {
        # Download the installer
        "Downloading the installer ..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($installerUrl, $installerPath)

        # Check installer has a valid signature from the Certbot release team
        $signature = Get-AuthenticodeSignature "C:\Dev\Firefox Installer.exe"
        
        if ($signature.Status -ne 'Valid') {
            throw "Downloaded installer has no or invalid Authenticode signature."
        }

        if ($signature.SignerCertificate.Thumbprint -ne $installerAuthenticodeCertificateThumbprint) {
            throw "Downloaded installer has not been signed by Certbot development team."
        }

        # Install new version of Certbot
        "Running the installer ..."
        Start-Process -FilePath $installerPath -ArgumentList "/S /D=$InstallDir"

        "Certbot $latestVersion is installed."
    } finally {
        Remove-Item $installerPath -ErrorAction 'Ignore'
    }
}
