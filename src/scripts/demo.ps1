# demo.ps1 – schickt 5 Beispiel-Alerts im SOC-Server

param(
  [string]$ServerUri = "http://127.0.0.1:8000/alerts/ingest",  # Ziel-Endpoint
  [int]$PauseSekunden = 6,                                     # Wartezeit zwischen Alerts
  [ValidateSet('dashboard','legacy','both')]
  [string]$Schema = 'both',                                    # Feldschema
  [switch]$VerboseLog                                          # -VerboseLog für mehr Output
)

function New-AlertBody {
  param(
    [string]$Name,
    [string]$Description,
    [string[]]$Techniques,
    [string]$Hostname,
    [ValidateSet('Low','Medium','High','Critical')][string]$Severity = 'Medium',
    [ValidateSet('dashboard','legacy','both')][string]$Schema = 'both'
  )

  # Normalisierte Schweregrade
  $sevLower = $Severity.ToLower()     # für 'severity'
  $sevTitle = $Severity               # für 'Severity' (legacy)

  # Dashboard-Schema
  $dash = @{
    title       = $Name
    severity    = $sevLower                     # low|medium|high|critical
    description = $Description
    techniques  = $Techniques                   # ["T1059.001", ...]
    target      = @{ host = $Hostname }         # target.host
    source      = "demo.ps1"
    ts          = (Get-Date).ToUniversalTime().ToString("o")
  }

  # Legacy Schema
  $legacy = @{
    AlertName   = $Name
    Severity    = $sevTitle                  
    Description = $Description
    Techniques  = $Techniques
    Entities    = @{
      Host    = $Hostname
      Account = "corp\\j.doe"
    }
    Evidence    = @{
      Message = $Description
    }
  }

  switch ($Schema) {
    'dashboard' { return $dash }
    'legacy'    { return $legacy }
    'both'      {
      # Zusammenführen: bevorzugt dashboard-Keys, zusätzlich legacy-Keys
      $merged = $dash.Clone()
      foreach ($k in $legacy.Keys) { $merged[$k] = $legacy[$k] }
      return $merged
    }
  }
}

# --- Hilfsfunktion: Alert senden ---
function Send-Alert {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string[]]$Techniques,
    [Parameter(Mandatory)][string]$Hostname,       
    [ValidateSet('Low','Medium','High','Critical')]
    [string]$Severity = 'Medium'
  )

  $bodyObj = New-AlertBody -Name $Name -Description $Description -Techniques $Techniques `
                           -Hostname $Hostname -Severity $Severity -Schema $Schema

  $json = $bodyObj | ConvertTo-Json -Depth 8

  if ($VerboseLog) {
    Write-Host "[DEBUG] POST $ServerUri"
    Write-Host "[DEBUG] Body:"; Write-Host $json
  }

  try {
    Invoke-RestMethod -Method POST -Uri $ServerUri -Body $json -ContentType "application/json" | Out-Null
    if ($VerboseLog) { Write-Host "[OK] Alert '$Name' gesendet (`"$Hostname`")" -ForegroundColor Green }
  }
  catch {
    Write-Host "[FEHLER] Konnte Alert '$Name' nicht senden: $($_.Exception.Message)" -ForegroundColor Red
  }
}

# --- 5 Beispiel-Alerts (mit CVE/MITRE-Hinweisen) ---
Send-Alert -Name "Suspicious PowerShell"     -Description "PS spawned by Office. CVE-2024-3094 seen."      -Techniques @("T1059.001") -Hostname "SRV-APP-01"
Start-Sleep -Seconds $PauseSekunden
Send-Alert -Name "Unusual RDP"               -Description "Multiple failed logins from 203.0.113.50"       -Techniques @("T1110")     -Hostname "SRV-TERM-02"
Start-Sleep -Seconds $PauseSekunden
Send-Alert -Name "Encoded Command"           -Description "CMD /c ... possible loader. CVE-2023-23397"     -Techniques @("T1204")     -Hostname "WS-OPS-07"
Start-Sleep -Seconds $PauseSekunden
Send-Alert -Name "Credential Access"         -Description "LSASS access pattern detected"                  -Techniques @("T1003")     -Hostname "SRV-IDP-01"
Start-Sleep -Seconds $PauseSekunden
Send-Alert -Name "Suspicious Scripting Host" -Description "wscript.exe network calls. CVE-2021-44228 ref." -Techniques @("T1059")     -Hostname "WS-FIN-12"

# --- Sichtbares "Ticking" fürs Dashboard ---
$secs = 30
Write-Host "Ticking dashboard for $secs seconds..."
1..$secs | ForEach-Object { Start-Sleep -Seconds 1; Write-Host "." -NoNewline }
Write-Host "`nDone."

