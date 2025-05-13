<#
.SYNOPSIS
    Checks a website's SSL certificate chain using OpenSSL and Windows root store.

.DESCRIPTION
    Connects to a given domain, retrieves the certificate chain, checks for completeness,
    validates expiration, and verifies the chain against the Windows root CA store.

.PARAMETER Domain
    The domain name (e.g., example.com) to check.

.PARAMETER OutputDir
    (Optional) Directory to store temporary files. Defaults to C:\temp.

.EXAMPLE
    .\Check-CertChain.ps1 -Domain example.com -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9.-]+$')]
    [string]$Domain,

    [string]$OutputDir = "C:\temp"
)

$LogFile = Join-Path $OutputDir "check_cert_log.txt"

function Log {
    <#
    .SYNOPSIS
        Logs a message with a timestamp to the console and log file.
    #>
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp $Message"
    #Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
    Write-Verbose "Created output directory: $OutputDir"
}

# Check for OpenSSL
$openssl = Get-Command "openssl" -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Host "OpenSSL is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install OpenSSL and ensure it is in your PATH. Download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    exit 1
}
Write-Verbose "Using OpenSSL at $($openssl.Source)"
Write-Verbose "Target domain: $Domain"
# Prepare file paths
$certFile = Join-Path $OutputDir "$Domain.pem"
$leafCertFile = Join-Path $OutputDir "$Domain-leaf.pem"
$rootCertFile = Join-Path $OutputDir "$Domain-root.pem"
$caBundle = Join-Path $OutputDir "windows-root-ca-bundle.pem"
$chainFile = Join-Path $OutputDir "$Domain-chain.pem"
$intermediateCertFiles = @()

# Retrieve certificates from the server
$Target = $Domain + ':443'
try {
    Write-Verbose "Retrieving certificates from $Target"
    $certOutput = & {
        Write-Host "`n" | openssl s_client -showcerts -connect $Target 2>&1
    }
    if ($LASTEXITCODE -ne 0 -or -not $certOutput) {
        Write-Host "Failed to retrieve certificates from $Domain" -ForegroundColor Red
        Write-Host "Output:`n$certOutput"
        exit 2
    }
    $certOutput | Out-File -FilePath $certFile -Encoding ascii
    Write-Verbose "Certificates saved to $certFile"
    Log "Certificates retrieved and saved to $certFile"
} catch {
    Log "Exception occurred: $_"
    Write-Host "Failed to retrieve certificates from $Domain" -ForegroundColor Red
    exit 2
}

# Extract all certificates from the PEM file
$certs = @()
$certText = Get-Content $certFile -Raw
$certMatches = [regex]::Matches($certText, "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", "Singleline")
foreach ($match in $certMatches) {
    $certs += $match.Value
}
Log "Found $($certs.Count) certificate(s) in the chain."
Write-Verbose "Found $($certs.Count) certificate(s) in the chain."

if ($certs.Count -eq 0) {
    Write-Host "No certificates found in the server response." -ForegroundColor Red
    exit 3
}

# Save each cert to a file
if ($certs.Count -eq 1) {
    Set-Content -Path $leafCertFile -Value $certs[0]
    Log "Only one certificate found. Saved as leaf cert."
    Write-Verbose "Only one certificate found. Saved as leaf cert."
} elseif ($certs.Count -eq 2) {
    Set-Content -Path $leafCertFile -Value $certs[0]
    $intermediateFile = Join-Path $OutputDir "$Domain-intermediate.pem"
    Set-Content -Path $intermediateFile -Value $certs[1]
    $intermediateCertFiles += $intermediateFile
    Log "Two certificates found. Saved leaf and intermediate certs."
    Write-Verbose "Two certificates found. Saved leaf and intermediate certs."
} elseif ($certs.Count -ge 3) {
    Set-Content -Path $leafCertFile -Value $certs[0]
    for ($i = 1; $i -lt $certs.Count - 1; $i++) {
        $intermediateFile = Join-Path $OutputDir "$Domain-intermediate$i.pem"
        Set-Content -Path $intermediateFile -Value $certs[$i]
        $intermediateCertFiles += $intermediateFile
    }
    Set-Content -Path $rootCertFile -Value $certs[-1]
    Log "Three or more certificates found. Saved leaf, intermediate(s), and root cert."
    Write-Verbose "Three or more certificates found. Saved leaf, intermediate(s), and root cert."
}

# Check for incomplete chain
if ($certs.Count -lt 2) {
    Write-Host "The server did not supply a complete certificate chain." -ForegroundColor Red
    Log "Incomplete certificate chain."
    #Write-Verbose "Incomplete certificate chain."
}

# Extract CN from leaf cert
$leafCN = & openssl x509 -in $leafCertFile -noout -subject | Select-String -Pattern "CN=([^,]+)" | ForEach-Object {
    if ($_ -match "CN=([^,]+)") { $matches[1] }
}
Log "Leaf certificate CN: $leafCN"
Write-Verbose "Leaf certificate CN: $leafCN"

# Check expiration
$notAfter = & openssl x509 -in $leafCertFile -noout -enddate | ForEach-Object {
    $_ -replace "notAfter=", ""
}
$notAfter = $notAfter -replace ' +', ' '  # Replace multiple spaces with a single space
$notAfter = $notAfter -replace ' GMT$',''
try {
    $expiryDate = [datetime]::ParseExact($notAfter, "MMM d HH:mm:ss yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
    if ($expiryDate -lt (Get-Date)) {
        Write-Host "Certificate for $leafCN has expired on $expiryDate" -ForegroundColor Yellow
        Log "Certificate expired on $expiryDate"
        #Write-Verbose "Certificate for $leafCN has expired on $expiryDate"
    } else {
        Write-Host "Certificate for $leafCN is valid until $expiryDate" -ForegroundColor Green
        Log "Certificate valid until $expiryDate"
        #Write-Verbose "Certificate for $leafCN is valid until $expiryDate"
    }
} catch {
    Write-Host "Could not parse certificate expiration date." -ForegroundColor Red
    Log "Failed to parse expiration date: $_"
    #Write-Verbose "Failed to parse expiration date: $_"
}

# Build CA bundle from Windows Root Store
Log "Exporting Windows Root CA certificates to $caBundle"
Write-Verbose "Exporting Windows Root CA certificates to $caBundle"
$rootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.HasPrivateKey -eq $false }
$rootCerts | ForEach-Object {
    $pem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----"
    Add-Content -Path $caBundle -Value $pem
}
Log "Exported $($rootCerts.Count) root CA certificates."
Write-Verbose "Exported $($rootCerts.Count) root CA certificates."

# Combine leaf and intermediates into a chain file (do NOT include the root from the server)
Set-Content -Path $chainFile -Value $certs[0]  # leaf
foreach ($intermediate in $intermediateCertFiles) {
   Add-Content -Path $chainFile -Value (Get-Content $intermediate -Raw)
}
Write-Verbose "Combined leaf and intermediate certificates into $chainFile"

# Validate the certificate chain
$verifyCmd = "openssl verify -CAfile $caBundle -untrusted $chainFile $leafCertFile"
Log "Running command: $verifyCmd"
Write-Verbose "Running command: $verifyCmd"
$verifyResult = & openssl verify -CAfile $caBundle -untrusted $chainFile $leafCertFile 2>&1
Log "OpenSSL verify output: $verifyResult"
Write-Verbose "OpenSSL verify output: $verifyResult"

if ($verifyResult -match "OK$") {
    Write-Host "Certificate chain for $leafCN is valid." -ForegroundColor Green
    Log "Certificate chain is valid."
    Write-Verbose "Certificate chain for $leafCN is valid."
}
elseif ($verifyResult -match "error 10") {
    Write-Host "Certificate for $Domain has expired (OpenSSL verify error 10)." -ForegroundColor Yellow
    Log "OpenSSL verify error 10: Certificate for $Domain has expired. $verifyResult"
    Write-Verbose "OpenSSL verify error 10: Certificate for $Domain has expired. $verifyResult"
}
elseif ($verifyResult -match "error 20") {
    Write-Host "Probable incomplete certificate chain for $Domain (OpenSSL verify error 20)." -ForegroundColor Red
    Log "OpenSSL verify error 20: Probable incomplete certificate chain for $Domain. $verifyResult"
    Write-Verbose "OpenSSL verify error 20: Probable incomplete certificate chain for $Domain. $verifyResult"
}
else {
    Write-Host "Certificate chain for $leafCN is NOT valid!" -ForegroundColor Red
    Write-Host $verifyResult -ForegroundColor Red
    Log "Certificate is NOT valid: $verifyResult"
    Write-Verbose "Certificate chain for $leafCN is NOT valid! $verifyResult"
}

# Optional: Clean up temp files (uncomment if desired)
# Remove-Item $certFile, $leafCertFile, $rootCertFile, $caBundle, $chainFile -ErrorAction SilentlyContinue
# foreach ($file in $intermediateCertFiles) { Remove-Item $file -ErrorAction SilentlyContinue }
