param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$OpenWrt,
    [Parameter(Mandatory=$true)][string]$ServerIdentityFile,
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$ServerEndpoint,
    [Parameter(Mandatory=$true)][string]$FecKey,
    [UInt64]$FecKeyId = 0,
    [string]$SingBoxSpec,
    [switch]$StableGoogleEgress,
    [double]$RateMbps = 30
)

$ErrorActionPreference = 'Stop'
function Assert-NativeExit([string]$Operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}
if (!(Test-Path -LiteralPath $Binary)) { throw "Binary not found: $Binary" }
if (!(Test-Path -LiteralPath $ServerIdentityFile)) { throw "Identity file not found: $ServerIdentityFile" }
if ($FecKey.Length -lt 32) { throw 'FecKey must be at least 32 characters' }
if ($FecKey -match '\s') { throw 'FecKey must not contain whitespace' }
if ($RateMbps -lt 1 -or $RateMbps -gt 1000) { throw 'RateMbps must be between 1 and 1000' }
if ($SingBoxSpec -and !(Test-Path -LiteralPath $SingBoxSpec)) { throw "sing-box spec not found: $SingBoxSpec" }

$serverInstaller = Join-Path $PSScriptRoot 'server-install.sh'
$routerInstaller = Join-Path $PSScriptRoot 'openwrt-install.sh'
$singBoxInstaller = Join-Path $PSScriptRoot 'sing-box-install.sh'
$singBoxMerger = Join-Path $PSScriptRoot 'sing-box-merge.py'
$googleRoutePatcher = Join-Path $PSScriptRoot 'add-google-stable-route.py'
$googleRouteInstaller = Join-Path $PSScriptRoot 'install-google-route-updater.sh'
$remoteBinary = '/tmp/smart-fec-tunnel.new'
$tempKey = New-TemporaryFile

try {
    # Confirm both management paths before the first remote mutation. This
    # prevents installing a new server half when the router is unreachable.
    ssh -i $ServerIdentityFile $Server true
    Assert-NativeExit 'Server SSH preflight'
    ssh $OpenWrt true
    Assert-NativeExit 'OpenWrt SSH preflight'

    [IO.File]::WriteAllText($tempKey.FullName, $FecKey, [Text.UTF8Encoding]::new($false))
    scp -i $ServerIdentityFile $Binary "${Server}:$remoteBinary"
    Assert-NativeExit 'Upload server binary'
    scp -i $ServerIdentityFile $serverInstaller "${Server}:/tmp/server-install.sh"
    Assert-NativeExit 'Upload server installer'
    scp -i $ServerIdentityFile $tempKey.FullName "${Server}:/tmp/smart-fec.key"
    Assert-NativeExit 'Upload server key'
    if ($SingBoxSpec) {
        scp -i $ServerIdentityFile $SingBoxSpec "${Server}:/tmp/sing-box-deployment.json"
        Assert-NativeExit 'Upload sing-box deployment spec'
        scp -i $ServerIdentityFile $singBoxInstaller "${Server}:/tmp/sing-box-install.sh"
        Assert-NativeExit 'Upload sing-box installer'
        scp -i $ServerIdentityFile $singBoxMerger "${Server}:/tmp/sing-box-merge.py"
        Assert-NativeExit 'Upload sing-box merger'
        ssh -i $ServerIdentityFile $Server "set -e; trap 'rm -f /tmp/sing-box-deployment.json' EXIT; chmod 700 /tmp/sing-box-install.sh /tmp/sing-box-merge.py; chmod 600 /tmp/sing-box-deployment.json; /tmp/sing-box-install.sh /tmp/sing-box-merge.py /tmp/sing-box-deployment.json"
        Assert-NativeExit 'Install sing-box configuration'
    }
    if ($StableGoogleEgress) {
        scp -i $ServerIdentityFile $googleRoutePatcher "${Server}:/tmp/add-google-stable-route.py"
        Assert-NativeExit 'Upload Google route patcher'
        scp -i $ServerIdentityFile $googleRouteInstaller "${Server}:/tmp/install-google-route-updater.sh"
        Assert-NativeExit 'Upload Google route installer'
        ssh -i $ServerIdentityFile $Server "set -e; trap 'rm -f /tmp/add-google-stable-route.py /tmp/install-google-route-updater.sh' EXIT; chmod 700 /tmp/add-google-stable-route.py /tmp/install-google-route-updater.sh; /tmp/install-google-route-updater.sh /tmp/add-google-stable-route.py"
        Assert-NativeExit 'Install Google route updater'
    }
    ssh -i $ServerIdentityFile $Server "set -e; trap 'rm -f /tmp/smart-fec.key' EXIT; chmod 600 /tmp/smart-fec.key; chmod 700 /tmp/server-install.sh '$remoteBinary'; SMART_FEC_KEY=`$(cat /tmp/smart-fec.key) SMART_FEC_KEY_ID='$FecKeyId' /tmp/server-install.sh '$remoteBinary' '$RateMbps'"
    Assert-NativeExit 'Install server components'

    # Force legacy SCP because many OpenWrt Dropbear builds do not provide SFTP.
    scp -O $Binary "${OpenWrt}:$remoteBinary"
    Assert-NativeExit 'Upload OpenWrt binary'
    scp -O $routerInstaller "${OpenWrt}:/tmp/openwrt-install.sh"
    Assert-NativeExit 'Upload OpenWrt installer'
    scp -O $tempKey.FullName "${OpenWrt}:/tmp/smart-fec.key"
    Assert-NativeExit 'Upload OpenWrt key'
    ssh $OpenWrt "set -e; trap 'rm -f /tmp/smart-fec.key' EXIT; chmod 600 /tmp/smart-fec.key; chmod 700 /tmp/openwrt-install.sh '$remoteBinary'; SMART_FEC_KEY=`$(cat /tmp/smart-fec.key) SMART_FEC_KEY_ID='$FecKeyId' /tmp/openwrt-install.sh '$remoteBinary' '$ServerEndpoint' '$RateMbps'"
    Assert-NativeExit 'Install OpenWrt components'
}
finally {
    Remove-Item -LiteralPath $tempKey.FullName -Force -ErrorAction SilentlyContinue
}

if (!$SingBoxSpec) { Write-Warning 'sing-box was not changed because -SingBoxSpec was omitted.' }
Write-Host 'Deployment completed. Passwall node switching is intentionally manual.'
