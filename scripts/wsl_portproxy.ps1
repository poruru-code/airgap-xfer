param(
  [int]$ListenPort = 5173,
  [int]$ConnectPort = 5173,
  [string]$ListenAddress = "0.0.0.0",
  [string]$Distro = "",
  [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell (Administrator)."
  }
}

function Get-WslIp {
  $wslArgs = @()
  if ($Distro -ne "") {
    $wslArgs += "-d"
    $wslArgs += $Distro
  }
  $wslArgs += "hostname"
  $wslArgs += "-I"
  $raw = & wsl.exe @wslArgs
  $ip = ($raw -split "\s+") | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" } | Select-Object -First 1
  if (-not $ip) {
    throw "Failed to detect WSL IP (hostname -I returned: $raw)"
  }
  return $ip
}

function Get-WindowsLanIps {
  $ips = @()
  $configs = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4Address -and $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" }
  foreach ($config in $configs) {
    foreach ($addr in $config.IPv4Address) {
      if ($addr.IPAddress -and $addr.IPAddress -notmatch "^169\\.254\\.") {
        $ips += $addr.IPAddress
      }
    }
  }
  if ($ips.Count -eq 0) {
    $fallback = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -and $_.IPAddress -notmatch "^169\\.254\\." -and $_.IPAddress -ne "127.0.0.1" } |
      Select-Object -ExpandProperty IPAddress
    if ($fallback) {
      $ips = $fallback
    }
  }
  return @($ips | Select-Object -Unique)
}

Assert-Admin
Get-Command wsl.exe | Out-Null

$ruleName = "WSL PortProxy $ListenPort"

if ($Remove) {
  Write-Host "Removing portproxy and firewall rule..."
  & netsh interface portproxy delete v4tov4 listenaddress=$ListenAddress listenport=$ListenPort | Out-Null
  Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Host "Removed."
  exit 0
}

$wslIp = Get-WslIp
Write-Host "WSL IP: $wslIp"
Write-Host ("Forwarding {0}:{1} -> {2}:{3}" -f $ListenAddress, $ListenPort, $wslIp, $ConnectPort)

& netsh interface portproxy delete v4tov4 listenaddress=$ListenAddress listenport=$ListenPort | Out-Null
& netsh interface portproxy add v4tov4 listenaddress=$ListenAddress listenport=$ListenPort connectaddress=$wslIp connectport=$ConnectPort

if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $ListenPort -Action Allow | Out-Null
}

$lanIps = @(Get-WindowsLanIps)
if ($lanIps.Count -gt 0) {
  Write-Host "Access URL (phone):"
  foreach ($ip in $lanIps) {
    Write-Host ("  https://{0}:{1} (use http:// if not using HTTPS)" -f $ip, $ListenPort)
  }
} else {
  Write-Host "Done. Windows LAN IP not detected. Use ipconfig to find your IPv4 address."
}
