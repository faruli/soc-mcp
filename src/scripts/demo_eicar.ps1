<#
.SYNOPSIS
  Verifiziert den Malware-Endpoint mit dem EICAR-Testhash und zeigt eine kompakte Auswertung.
.DESCRIPTION
  Standard: prüft gegen deinen SOC_MCP_Server (GET /malware/{hash}).
  Optional: -DirectVT ruft VirusTotal v3 direkt (erfordert -VTApiKey); liefert dann auch last_analysis_date.

.PARAMETER BaseUrl
  Basis-URL deines SOC-Servers (Standard: http://127.0.0.1:8000)

.PARAMETER Hash
  Datei-Hash (MD5, SHA1 oder SHA256). Standard: EICAR-MD5 44d88612fea8a8f36de82e1278abb02f

.PARAMETER OutJson
  Pfad für Roh-JSON (Response) zur Dokumentation (optional)

.PARAMETER DirectVT
  Wenn gesetzt, wird direkt die VirusTotal API v3 abgefragt (erfordert -VTApiKey)

.PARAMETER VTApiKey
  VirusTotal API Key (nur relevant mit -DirectVT)
#>

[CmdletBinding()]
param(
  [string]$BaseUrl = "http://127.0.0.1:8000",
  [string]$Hash    = "44d88612fea8a8f36de82e1278abb02f",
  [string]$OutJson = "",
  [switch]$DirectVT,
  [string]$VTApiKey = ""
)

function Write-Heading($text) {
  Write-Host ""
  Write-Host ("=" * $text.Length)
  Write-Host $text
  Write-Host ("=" * $text.Length)
}

function Save-JsonIfWanted($obj, $path) {
  if ([string]::IsNullOrWhiteSpace($path)) { return }
  try {
    $json = $obj | ConvertTo-Json -Depth 12
    $dir  = Split-Path -Path $path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    Set-Content -Path $path -Value $json -Encoding UTF8
    Write-Host "→ JSON gespeichert: $path"
  } catch {
    Write-Warning "Konnte JSON nicht speichern: $($_.Exception.Message)"
  }
}

try {
  if ($DirectVT) {
    if (-not $VTApiKey) {
      throw "Für -DirectVT muss -VTApiKey gesetzt sein."
    }
    $uri = "https://www.virustotal.com/api/v3/files/$Hash"
    Write-Heading "Direktabruf VirusTotal v3 (Dateiobjekt)"
    $headers = @{ "x-apikey" = $VTApiKey }
    $vt = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
    $attr = $vt.data.attributes
    $stats = $attr.last_analysis_stats

    "{0,-22} {1}" -f "Hash:", $Hash | Write-Host
    "{0,-22} {1}" -f "last_analysis_date:", $( if ($attr.last_analysis_date) { (Get-Date 01.01.1970).AddSeconds([double]$attr.last_analysis_date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } else { "-" } ) | Write-Host
    "{0,-22} {1}" -f "malicious:", $stats.malicious | Write-Host
    "{0,-22} {1}" -f "suspicious:", $stats.suspicious | Write-Host
    "{0,-22} {1}" -f "undetected:", $stats.undetected | Write-Host
    "{0,-22} {1}" -f "harmless:", $stats.harmless | Write-Host

    Save-JsonIfWanted -obj $vt -path $OutJson
    Write-Host "`nHinweis: Zahlen können zeitabhängig variieren. Für die Thesis Datum/Uhrzeit dokumentieren."
  }
  else {
    $uri = "$BaseUrl/malware/$Hash"
    Write-Heading "Prüfung über SOC_MCP_Server ($uri)"
    $resp = Invoke-RestMethod -Method GET -Uri $uri -ErrorAction Stop

    # Erwartete Serverantwort: { hash, verdict, stats:{...}, source:"VirusTotal" }
    "{0,-22} {1}" -f "Hash:", $resp.hash | Write-Host
    "{0,-22} {1}" -f "Quelle:", $resp.source | Write-Host
    "{0,-22} {1}" -f "Verdikt:", $resp.verdict | Write-Host

    $s = $resp.stats
    if ($s) {
      "{0,-22} {1}" -f "malicious:", ($s.malicious   | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "suspicious:", ($s.suspicious | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "undetected:", ($s.undetected | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "harmless:",   ($s.harmless   | ForEach-Object { $_ }) | Write-Host
    } else {
      Write-Warning "Keine 'stats' im Response gefunden."
    }

    Save-JsonIfWanted -obj $resp -path $OutJson
    Write-Host "`nHinweis: Der Server ruft VirusTotal auf; stelle sicher, dass VIRUSTOTAL_API_KEY im Server-Umfeld gesetzt ist."
  }
}
catch {
  Write-Error "Fehler: $($_.Exception.Message)"
  if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__) {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host "HTTP-Status: $code"
    if ($code -eq 400) {
      Write-Host "Tipp: Ist der VIRUSTOTAL_API_KEY für den Server (oder -VTApiKey bei -DirectVT) gesetzt?"
    }
  }
  exit 1
}
