# process_analysis.ps1
# This script exports process signature information to C:\temp\ProcessSignatures.csv

$processInfo = Get-Process | ForEach-Object {
    try {
        $path = $_.Path
        if ($path) {
            $sig = Get-AuthenticodeSignature $path
            [PSCustomObject]@{
                Process = $_.ProcessName
                Path    = $path
                Status  = $sig.Status
                Signer  = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unsigned or N/A" }
            }
        }
    } catch {}
}

# Export detailed process signature information
$processInfo | Export-Csv -Path "C:\\temp\\ProcessSignatures.csv" -NoTypeInformation

# Group by unique executable (Path), summarize
$summary = $processInfo | Group-Object Path | ForEach-Object {
    $first = $_.Group | Select-Object -First 1
    [PSCustomObject]@{
        Process = $first.Process
        Path    = $_.Name
        Count   = $_.Count
        Status  = $first.Status
        Signer  = $first.Signer
    }
}

# Export the summary to CSV
$summary | Export-Csv -Path "C:\\temp\\ProcessSignatureSummary.csv" -NoTypeInformation

# Optional: Output to console
$summary | Format-Table -AutoSize 

# Investigate unsigned processes/apps
$unsignedSummary = $summary | Where-Object { $_.Status -eq 'NotSigned' -or $_.Status -eq 'UnknownError' -or $_.Status -eq 'Unsigned' }
$unsignedSummary | ForEach-Object {
    $_ | Add-Member -NotePropertyName 'InvestigationNote' -NotePropertyValue 'Unsigned process/app - investigate source and legitimacy' -Force
    $_
} | Export-Csv -Path "C:\\temp\\ProcessUnsignedSummary.csv" -NoTypeInformation

Write-Output "\nUnsigned process/app summary written to ProcessUnsignedSummary.csv."

# Investigate unsigned processes/apps and write details to a CSV file
$unsignedInvestigationPath = "C:\\temp\\ProcessUnsignedInvestigation.csv"
$unsignedInvestigationRows = @()

$unsignedSummary | ForEach-Object {
    $exePath = $_.Path
    $processName = $_.Process
    $count = $_.Count
    $status = $_.Status
    $signer = $_.Signer
    $note = $_.InvestigationNote
    if (Test-Path $exePath) {
        $fileInfo = Get-Item $exePath
        $hash = Get-FileHash $exePath -Algorithm SHA256
        $version = $fileInfo.VersionInfo
        $unsignedInvestigationRows += [PSCustomObject]@{
            Process          = $processName
            Path             = $exePath
            Count            = $count
            Status           = $status
            Signer           = $signer
            Note             = $note
            Name             = $fileInfo.Name
            Length           = $fileInfo.Length
            CreationTime     = $fileInfo.CreationTime
            LastWriteTime    = $fileInfo.LastWriteTime
            LastAccessTime   = $fileInfo.LastAccessTime
            Mode             = $fileInfo.Mode
            LinkType         = $fileInfo.LinkType
            Target           = $fileInfo.Target
            SHA256           = $hash.Hash
            File             = $version.File
            InternalName     = $version.InternalName
            OriginalFilename = $version.OriginalFilename
            FileVersion      = $version.FileVersion
            FileDescription  = $version.FileDescription
            Product          = $version.Product
            ProductVersion   = $version.ProductVersion
            Debug            = $version.Debug
            Patched          = $version.Patched
            PreRelease       = $version.PreRelease
            PrivateBuild     = $version.PrivateBuild
            SpecialBuild     = $version.SpecialBuild
            Language         = $version.Language
        }
    } else {
        $unsignedInvestigationRows += [PSCustomObject]@{
            Process          = $processName
            Path             = $exePath
            Count            = $count
            Status           = $status
            Signer           = $signer
            Note             = $note
            Name             = $null
            Length           = $null
            CreationTime     = $null
            LastWriteTime    = $null
            LastAccessTime   = $null
            Mode             = $null
            LinkType         = $null
            Target           = $null
            SHA256           = $null
            File             = $null
            InternalName     = $null
            OriginalFilename = $null
            FileVersion      = $null
            FileDescription  = $null
            Product          = $null
            ProductVersion   = $null
            Debug            = $null
            Patched          = $null
            PreRelease       = $null
            PrivateBuild     = $null
            SpecialBuild     = $null
            Language         = $null
        }
    }
}

$unsignedInvestigationRows | Export-Csv -Path $unsignedInvestigationPath -NoTypeInformation
Write-Output "\nUnsigned process/app investigation details written to ProcessUnsignedInvestigation.csv."

# --- VirusTotal API Hash Lookup (commented out, requires API key) ---
<#
# To use: Uncomment this block and add your VirusTotal API key
$apiKey = "YOUR_API_KEY"
$unsignedSummary | ForEach-Object {
    $exePath = $_.Path
    if (Test-Path $exePath) {
        $hash = Get-FileHash $exePath -Algorithm SHA256
        $vtUrl = "https://www.virustotal.com/api/v3/files/$($hash.Hash)"
        $headers = @{ "x-apikey" = $apiKey }
        try {
            $response = Invoke-RestMethod -Uri $vtUrl -Headers $headers -Method Get
            # You can process $response as needed, e.g., output detection stats
            Write-Output "VirusTotal result for $exePath: $($response.data.attributes.last_analysis_stats)"
        } catch {
            Write-Output "VirusTotal lookup failed for $exePath: $($_.Exception.Message)"
        }
    }
}
#>

# Gather all processes with listening ports or outbound connections to global IPs, including vendor and signature status
$processSignatureMap = @{}
$processInfo | ForEach-Object {
    $processSignatureMap[$_.Path] = @{ Signer = $_.Signer; Status = $_.Status }
}

$networkConnections = Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $path = $null
    $signer = $null
    $status = $null
    try {
        $path = $proc.Path
        if ($processSignatureMap.ContainsKey($path)) {
            $signer = $processSignatureMap[$path].Signer
            $status = $processSignatureMap[$path].Status
        }
    } catch {}
    [PSCustomObject]@{
        ProcessName   = if ($proc) { $proc.ProcessName } else { $null }
        PID           = $_.OwningProcess
        Path          = $path
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = $_.State
        Signer        = $signer
        SignatureStatus = $status
    }
}

# Filter for listening ports or outbound connections to global IPs
$globalIpPattern = '^(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.|::1|fe80:|fc00:|fd00:|169\.254\.).+'
$networkFiltered = $networkConnections | Where-Object {
    $_.State -eq 'Listen' -or ($_.RemoteAddress -match $globalIpPattern -and $_.State -eq 'Established')
}

$networkFiltered | Export-Csv -Path "C:\\temp\\ProcessNetworkConnections.csv" -NoTypeInformation
Write-Output "\nNetwork connection details written to ProcessNetworkConnections.csv." 