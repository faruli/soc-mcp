<#
.SYNOPSIS
  Verifiziert den Malware-Endpoint mit dem EICAR-Testhash und zeigt eine kompakte Auswertung.
.DESCRIPTION
  Standard: prüft gegen den SOC_MCP_Server (GET /malware/{hash}).
  Optional: -DirectVT ruft VirusTotal v3 direkt (erfordert -VTApiKey).
#>

[CmdletBinding()]
param(
  [string]$BaseUrl = "http://127.0.0.1:8000",
  [ValidatePattern('^[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}$')]
  [string]$Hash    = "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
  [string]$OutJson = "",
  [switch]$DirectVT,
  [string]$VTApiKey = ""
)

function Write-Heading([string]$text) {
  Write-Host "`n$('-' * $text.Length)"
  Write-Host $text
  Write-Host $('-' * $text.Length)
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

# Hilfsfunktion: Basis-URL 
function Join-Url([string]$base, [string]$tail) {
  if ($base.EndsWith('/')) { $base = $base.TrimEnd('/') }
  if ($tail.StartsWith('/')) { $tail = $tail.TrimStart('/') }
  return "$base/$tail"
}

try {
  if ($DirectVT) {
    if (-not $VTApiKey) { throw "Für -DirectVT muss -VTApiKey gesetzt sein." }

    $uri = "https://www.virustotal.com/api/v3/files/$Hash"
    Write-Heading "Direktabruf VirusTotal v3 (Dateiobjekt)"

    $headers = @{ "x-apikey" = $VTApiKey }
    try {
      $vt = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
    } catch {
      # 429 / 401 / TLS-Fehler 
      $resp = $_.Exception.Response
      if ($resp -and $resp.StatusCode.value__ -eq 429) { throw "VirusTotal: Rate limit (429). Wartezeit/Quota prüfen." }
      if ($resp -and $resp.StatusCode.value__ -eq 401) { throw "VirusTotal: Unauthorized (401). API-Key prüfen." }
      throw
    }

    $attr  = $vt.data.attributes
    $stats = $attr.last_analysis_stats

    "{0,-22} {1}" -f "Hash:", $Hash | Write-Host
    "{0,-22} {1}" -f "last_analysis_date:", $( if ($attr.last_analysis_date) { (Get-Date 01.01.1970).AddSeconds([double]$attr.last_analysis_date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } else { "-" } ) | Write-Host
    "{0,-22} {1}" -f "malicious:",   ($stats.malicious   | ForEach-Object { $_ }) | Write-Host
    "{0,-22} {1}" -f "suspicious:",  ($stats.suspicious  | ForEach-Object { $_ }) | Write-Host
    "{0,-22} {1}" -f "undetected:",  ($stats.undetected  | ForEach-Object { $_ }) | Write-Host
    "{0,-22} {1}" -f "harmless:",    ($stats.harmless    | ForEach-Object { $_ }) | Write-Host

    Save-JsonIfWanted -obj $vt -path $OutJson
    Write-Host "`nHinweis: Zahlen können zeitabhängig variieren."
  }
  else {
    $uri  = Join-Url $BaseUrl "malware/$Hash"
    Write-Heading "Prüfung über SOC_MCP_Server ($uri)"

    $resp = Invoke-RestMethod -Method GET -Uri $uri -ErrorAction Stop

    # Erwartete Serverantwort: { hash, verdict, stats:{...}, source:"VirusTotal" }
    "{0,-22} {1}" -f "Hash:",   ($resp.hash   | ForEach-Object { $_ }) | Write-Host
    "{0,-22} {1}" -f "Quelle:", ($resp.source | ForEach-Object { $_ }) | Write-Host
    "{0,-22} {1}" -f "Verdikt:",($resp.verdict| ForEach-Object { $_ }) | Write-Host

    $s = $resp.stats
    if ($s) {
      "{0,-22} {1}" -f "malicious:",   ($s.malicious   | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "suspicious:",  ($s.suspicious  | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "undetected:",  ($s.undetected  | ForEach-Object { $_ }) | Write-Host
      "{0,-22} {1}" -f "harmless:",    ($s.harmless    | ForEach-Object { $_ }) | Write-Host
    } else {
      Write-Warning "Keine 'stats' im Response gefunden."
    }

    Save-JsonIfWanted -obj $resp -path $OutJson
    Write-Host "`nHinweis: Server ruft VirusTotal; setzt 'VIRUSTOTAL_API_KEY' im Server."
  }
}
catch {
  Write-Error "Fehler: $($_.Exception.Message)"
  $resp = $_.Exception.Response
  if ($resp -and $resp.StatusCode.value__) {
    Write-Host "HTTP-Status: $($resp.StatusCode.value__)"
  }
  exit 1
}
