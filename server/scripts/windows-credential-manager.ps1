param(
  [Parameter(Mandatory = $true)][string]$Service,
  [Parameter(Mandatory = $true)][string]$Account,
  [Parameter(Mandatory = $true)][string]$CreateOnly
)

$ErrorActionPreference = 'Stop'
$payload = [Console]::In.ReadToEnd()
if ([string]::IsNullOrWhiteSpace($payload) -or $payload.Length -gt 65536) {
  throw 'invalid credential payload'
}

# Validate JSON without writing it to output. PasswordVault stores the original
# field map, and the credential value is received only through stdin.
$parsed = $payload | ConvertFrom-Json
if ($null -eq $parsed -or $parsed -isnot [pscustomobject]) {
  throw 'credential payload must be a JSON object'
}

Add-Type -AssemblyName Windows.Security
$vault = New-Object Windows.Security.Credentials.PasswordVault
$existing = $null
try {
  $existing = $vault.Retrieve($Service, $Account)
  $existing.RetrievePassword()
} catch {}

if ($CreateOnly -eq '1' -and $null -ne $existing) {
  exit 3
}
if ($null -ne $existing) {
  $vault.Remove($existing)
}
$vault.Add((New-Object Windows.Security.Credentials.PasswordCredential($Service, $Account, $payload)))
