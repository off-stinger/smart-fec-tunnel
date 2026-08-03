param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$OpenWrt,
    [Parameter(Mandatory=$true)][string]$ServerIdentityFile,
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$ServerEndpoint,
    [Parameter(Mandatory=$true)][string]$FecKey,
    [double]$RateMbps = 30
)

$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $Binary)) { throw "Binary not found: $Binary" }
if (!(Test-Path -LiteralPath $ServerIdentityFile)) { throw "Identity file not found: $ServerIdentityFile" }
if ($FecKey.Length -lt 32) { throw 'FecKey must be at least 32 characters' }
if ($RateMbps -lt 1 -or $RateMbps -gt 1000) { throw 'RateMbps must be between 1 and 1000' }

$serverInstaller = Join-Path $PSScriptRoot 'server-install.sh'
$routerInstaller = Join-Path $PSScriptRoot 'openwrt-install.sh'
$remoteBinary = '/tmp/smart-fec-tunnel.new'
$tempKey = New-TemporaryFile

try {
    [IO.File]::WriteAllText($tempKey.FullName, $FecKey, [Text.UTF8Encoding]::new($false))
    scp -i $ServerIdentityFile $Binary "${Server}:$remoteBinary"
    scp -i $ServerIdentityFile $serverInstaller "${Server}:/tmp/server-install.sh"
    scp -i $ServerIdentityFile $tempKey.FullName "${Server}:/tmp/smart-fec.key"
    ssh -i $ServerIdentityFile $Server "chmod 600 /tmp/smart-fec.key; chmod 700 /tmp/server-install.sh '$remoteBinary'; SMART_FEC_KEY=`$(cat /tmp/smart-fec.key) /tmp/server-install.sh '$remoteBinary' '$RateMbps'; rm -f /tmp/smart-fec.key"

    # Force legacy SCP because many OpenWrt Dropbear builds do not provide SFTP.
    scp -O $Binary "${OpenWrt}:$remoteBinary"
    scp -O $routerInstaller "${OpenWrt}:/tmp/openwrt-install.sh"
    scp -O $tempKey.FullName "${OpenWrt}:/tmp/smart-fec.key"
    ssh $OpenWrt "chmod 600 /tmp/smart-fec.key; chmod 700 /tmp/openwrt-install.sh '$remoteBinary'; SMART_FEC_KEY=`$(cat /tmp/smart-fec.key) /tmp/openwrt-install.sh '$remoteBinary' '$ServerEndpoint' '$RateMbps'; rm -f /tmp/smart-fec.key"
}
finally {
    Remove-Item -LiteralPath $tempKey.FullName -Force -ErrorAction SilentlyContinue
}

Write-Host 'Deployment completed. Passwall node switching is intentionally manual.'
