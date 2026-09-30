<#
  Читает данные из Windows-инфраструктуры для сопоставления с портами коммутаторов:
    - DHCP: аренды и резервирования (MAC, IP, имя компьютера)
    - AD:   учётные записи компьютеров (описание, ОС, OU, последний вход)
  Только чтение. Результат — JSON в файл -OutFile (UTF-8).

  Учётная запись: по умолчанию текущий пользователь Windows. Другую можно передать
  через переменные окружения SWCFG_USER и SWCFG_PASS (их задаёт server.js).
#>
param(
  [Parameter(Mandatory = $true)][string]$OutFile,
  [string]$DhcpServers = '',
  [switch]$NoDhcp,
  [switch]$NoAD
)
$ErrorActionPreference = 'Stop'

$dhcp = New-Object System.Collections.ArrayList
$ad = New-Object System.Collections.ArrayList
$errors = [ordered]@{}
$servers = @()

$cred = $null
if ($env:SWCFG_USER) {
  $sec = ConvertTo-SecureString $env:SWCFG_PASS -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($env:SWCFG_USER, $sec)
}

function ConvertTo-Mac([string]$id) {
  $h = ($id -replace '[^0-9a-fA-F]', '').ToLower()
  if ($h.Length -eq 14 -and $h.StartsWith('01')) { $h = $h.Substring(2) }  # 01 — тип Ethernet перед MAC
  if ($h.Length -ne 12) { return $null }
  return $h.Substring(0, 4) + '-' + $h.Substring(4, 4) + '-' + $h.Substring(8, 4)
}
function ConvertTo-Iso($d) { if ($d) { return ([datetime]$d).ToUniversalTime().ToString('o') } return $null }

# ---------- DHCP ----------
if (-not $NoDhcp) {
  try {
    Import-Module DhcpServer
    if ($DhcpServers) { $servers = @($DhcpServers -split '[,;\s]+' | Where-Object { $_ }) }
    else { $servers = @(Get-DhcpServerInDC | ForEach-Object { $_.DnsName }) }
    if (-not $servers.Count) { $errors['DHCP'] = 'DHCP-серверы не найдены в AD — укажите их вручную' }

    foreach ($srv in $servers) {
      $cim = $null
      try {
        if ($cred) { $cim = New-CimSession -ComputerName $srv -Credential $cred; $p = @{ CimSession = $cim } }
        else { $p = @{ ComputerName = $srv } }
        foreach ($sc in @(Get-DhcpServerv4Scope @p)) {
          $scope = $sc.ScopeId.ToString()
          $seen = @{}
          $res = @{}
          foreach ($r in @(Get-DhcpServerv4Reservation @p -ScopeId $sc.ScopeId)) { $res[$r.IPAddress.ToString()] = $r }
          foreach ($l in @(Get-DhcpServerv4Lease @p -ScopeId $sc.ScopeId)) {
            $mac = ConvertTo-Mac $l.ClientId
            if (-not $mac) { continue }
            $ip = $l.IPAddress.ToString()
            $seen[$ip] = $true
            [void]$dhcp.Add([ordered]@{
              ip = $ip; mac = $mac; host = [string]$l.HostName; state = [string]$l.AddressState
              expires = ConvertTo-Iso $l.LeaseExpiryTime; scope = $scope; scopeName = [string]$sc.Name
              server = $srv; reserved = $res.ContainsKey($ip); description = [string]$l.Description
            })
          }
          # Резервирования, по которым сейчас нет аренды (устройство выключено)
          foreach ($r in $res.Values) {
            $ip = $r.IPAddress.ToString()
            $mac = ConvertTo-Mac $r.ClientId
            if ($seen.ContainsKey($ip) -or -not $mac) { continue }
            [void]$dhcp.Add([ordered]@{
              ip = $ip; mac = $mac; host = [string]$r.Name; state = 'ReservationOnly'; expires = $null
              scope = $scope; scopeName = [string]$sc.Name; server = $srv; reserved = $true; description = [string]$r.Description
            })
          }
        }
      } catch {
        $errors["DHCP $srv"] = $_.Exception.Message
      } finally {
        if ($cim) { Remove-CimSession $cim }
      }
    }
  } catch {
    $errors['DHCP'] = $_.Exception.Message
  }
}

# ---------- Active Directory: компьютеры ----------
if (-not $NoAD) {
  try {
    Import-Module ActiveDirectory
    $p = @{ Filter = '*'; Properties = @('DNSHostName', 'Description', 'OperatingSystem', 'LastLogonDate', 'Enabled', 'DistinguishedName') }
    if ($cred) { $p.Credential = $cred }
    foreach ($c in Get-ADComputer @p) {
      [void]$ad.Add([ordered]@{
        name = [string]$c.Name; dns = [string]$c.DNSHostName; description = [string]$c.Description
        os = [string]$c.OperatingSystem; lastLogon = ConvertTo-Iso $c.LastLogonDate
        enabled = [bool]$c.Enabled; dn = [string]$c.DistinguishedName
      })
    }
  } catch {
    $errors['AD'] = $_.Exception.Message
  }
}

$result = [ordered]@{
  at = (Get-Date).ToUniversalTime().ToString('o')
  servers = $servers
  dhcp = $dhcp
  ad = $ad
  errors = $errors
}
[IO.File]::WriteAllText($OutFile, ($result | ConvertTo-Json -Depth 5 -Compress), (New-Object Text.UTF8Encoding($false)))
