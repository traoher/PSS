<#
.SYNOPSIS
    Installs the SentinelOne agent by downloading and installing the MSI from a URL.

.DESCRIPTION
    This script downloads a SentinelOne agent MSI installer from a reliable host,
    installs it silently, and cleans up all temporary files afterwards.

.NOTES
    Author: Gemini (modified)
    Version: 8.0 (MSI version)
#>

# --- Pre-flight Checks and Configuration ---
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Warning "Could not set TLS 1.2. This may cause download issues. Error: $_"
}

Write-Host "v8.0 (MSI): Script execution started."

# --- Script Parameters ---
$downloadUrl = "https://www.dropbox.com/scl/fi/6c7058cp0ss55i4tju182/nosoAgent.msi?rlkey=hq2vqs27e2wh9er784ywu743p&st=mtn5bhsg&dl=1"
$tempDir = "C:\temp"
$msiPath = Join-Path $tempDir 'nosoAgent.msi'

# --- Main Logic ---
try {
    # 1. Create directory and download the MSI file.
    Write-Host "Ensuring $tempDir directory exists..."
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    
    Write-Host "Downloading MSI installer from Dropbox..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
    Write-Host ("Download complete. File size: {0:N0} bytes" -f (Get-Item $msiPath).Length)

    # 2. Install the agent silently.
    Write-Host "Starting MSI installation..."
    $arguments = "/i `"$msiPath`" /qn /norestart"
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
    $exitCode = $process.ExitCode

    # 3. Check the installation result.
    if ($exitCode -eq 0) {
        Write-Host "SUCCESS: MSI installation completed with exit code: $exitCode"
    } else {
        throw "MSI installation failed with exit code: $exitCode."
    }
}
catch {
    Write-Error ("FATAL ERROR: {0}" -f $_.Exception.ToString())
    exit 1
}
finally {
    # 4. Cleanup all temporary files.
    Write-Host "Cleaning up temporary files..."
    if (Test-Path -LiteralPath $msiPath) {
        Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Script finished."
exit 0 