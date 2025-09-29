# demo.ps1 – schickt 5 Beispiel-Alerts an deinen SOC-Server
# Zweck: das Dashboard „zum Leben bringen“ und Auto-Enrichment demonstrieren

$uri = "http://127.0.0.1:8000/alerts/ingest"

function Send-Alert($name, $desc, $techs, $host) {
  $body = @{
    AlertName   = $name
    Severity    = "Medium"
    Description = $desc
    Techniques  = $techs
    Entities    = @{ Host = $host; Account = "corp\j.doe" }
    Evidence    = @{ Message = $desc }
  } | ConvertTo-Json -Depth 5
  Invoke-RestMethod -Method POST -Uri $uri -Body $body -ContentType "application/json" | Out-Null
}

# 5 Beispiel-Alerts (mit CVE/MITRE-Hinweisen)
Send-Alert "Suspicious PowerShell"     "PS spawned by Office. CVE-2024-3094 seen."        @("T1059.001") "SRV-APP-01"
Start-Sleep -Seconds 6
Send-Alert "Unusual RDP"               "Multiple failed logins from 203.0.113.50"         @("T1110")     "SRV-TERM-02"
Start-Sleep -Seconds 6
Send-Alert "Encoded Command"           "CMD /c ... possible loader. CVE-2023-23397"       @("T1204")     "WS-OPS-07"
Start-Sleep -Seconds 6
Send-Alert "Credential Access"         "LSASS access pattern detected"                    @("T1003")     "SRV-IDP-01"
Start-Sleep -Seconds 6
Send-Alert "Suspicious Scripting Host" "wscript.exe network calls. CVE-2021-44228 ref."   @("T1059")     "WS-FIN-12"

# „Ticking“ damit das Dashboard sichtbar Aktivität zeigt
$secs = 30
Write-Host "Ticking dashboard for $secs seconds..."
1..$secs | ForEach-Object { Start-Sleep -Seconds 1; Write-Host "." -NoNewline }
Write-Host "`nDone."
