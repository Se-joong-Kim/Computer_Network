# Week 7 · Task 2 - empty the ARP table, watch it refill, capture it.
#
# Needs administrator rights (clearing the ARP cache and pktmon both do), so it
# is launched elevated:
#
#   Start-Process powershell -Verb RunAs -Wait -ArgumentList `
#       '-NoProfile','-ExecutionPolicy','Bypass','-File','task2_arp.ps1'
#
# Wireshark is not installed on this machine; Windows' own pktmon does the
# capture and converts it to pcapng. Every step is timestamped in Unix
# milliseconds in out/arp-run.log, so the capture can be lined up with the exact
# moment the table was emptied. Then, without elevation:
#
#   python task2_arp.py
#
# which reads it all back. On Wi-Fi, pktmon's pcapng holds 802.11 frames
# labelled as Ethernet; task2_arp.py explains that and fixes the file.
param(
    [string]$Out = (Join-Path $PSScriptRoot "out"),
    [int]$Seconds = 60
)
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out "arp-run.log"
Set-Content -Path $log -Value "" -Encoding ascii

function Note([string]$msg) {
    $ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    "{0}  {1:HH:mm:ss.fff}  {2}" -f $ms, (Get-Date), $msg | Add-Content -Path $log -Encoding ascii
}
function Snap([string]$name) {
    arp -a | Out-File -FilePath (Join-Path $Out $name) -Encoding ascii
}

$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1
$me  = $cfg.IPv4Address.IPAddress
$gw  = $cfg.IPv4DefaultGateway.NextHop
$mac = (Get-NetAdapter -InterfaceIndex $cfg.InterfaceIndex).MacAddress
Note "interface $($cfg.InterfaceAlias) me $me mac $mac gateway $gw"

Snap "arp-before.txt"
Note "arp-before saved"

$etl = Join-Path $env:TEMP "w07-arp.etl"
pktmon stop 2>$null | Out-Null
pktmon filter remove | Out-Null
pktmon filter add W07ARP -d ARP | Out-Null
pktmon start --capture --comp nics --pkt-size 0 --file-name $etl | Out-Null
$t0 = Get-Date
Note "capture started"
Start-Sleep -Seconds 3                                  # a little traffic before the clear

Note "CLEAR"
netsh interface ip delete arpcache | Out-Null
$clear = Get-Date
Snap "arp-cleared.txt"
Note "arp-cleared saved"

# What comes back on its own, before I send anything myself.
$refill = Join-Path $Out "arp-refill-log.txt"
Set-Content -Path $refill -Value "# arp -a -N $me every 0.5 s after the clear, before any ping" -Encoding ascii
for ($i = 0; $i -lt 8; $i++) {
    "===== +{0:N1} s after the clear" -f ((Get-Date) - $clear).TotalSeconds | Add-Content -Path $refill -Encoding ascii
    arp -a -N $me | Add-Content -Path $refill -Encoding ascii
    Start-Sleep -Milliseconds 500
}

Note "ping gateway"
ping -n 3 $gw | Add-Content -Path $log -Encoding ascii
Note "curl www.korea.ac.kr"
curl.exe -s -o NUL https://www.korea.ac.kr
Note "curl done"
Snap "arp-after.txt"
Note "arp-after saved"

$rest = $Seconds - ((Get-Date) - $t0).TotalSeconds     # one full minute of ARP for B4
if ($rest -gt 0) { Start-Sleep -Seconds ([int][math]::Ceiling($rest)) }
pktmon stop | Out-Null
Note "capture stopped"
pktmon etl2pcap $etl --out (Join-Path $Out "arp.pcapng") | Out-Null
pktmon filter remove | Out-Null
Remove-Item $etl -ErrorAction SilentlyContinue
Note "converted to pcapng"
Set-Content -Path (Join-Path $Out "arp-run.done") -Value "ok" -Encoding ascii
