#Requires -Version 7.2
<#
.SYNOPSIS
Offline diagnostic pseudonymization. Outputs a candidate for human review.
.DESCRIPTION
Never uploads data. Inputs are read only. No reversible mapping is written.
Automatic detection cannot certify that arbitrary content is safe to disclose.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$InputPath,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [string[]]$SensitiveLiteral = @(),
    [string]$SensitiveValuesFile
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maps = @{}
$counts = @{}
function Get-Alias([string]$Kind, [string]$Value) {
    $key = $Kind + ':' + $Value.ToLowerInvariant()
    if (-not $maps.ContainsKey($key)) {
        if (-not $counts.ContainsKey($Kind)) { $counts[$Kind] = 0 }
        $counts[$Kind]++
        $maps[$key] = '[' + $Kind + $counts[$Kind] + ']'
    }
    return $maps[$key]
}
function Replace-Pattern([string]$Text, [string]$Pattern, [string]$Kind) {
    return [regex]::Replace($Text, $Pattern, [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        if ($m.Groups['value'].Success) {
            $g = $m.Groups['value']
            return $m.Value.Substring(0, $g.Index - $m.Index) + (Get-Alias $Kind $g.Value) + $m.Value.Substring($g.Index - $m.Index + $g.Length)
        }
        return Get-Alias $Kind $m.Value
    })
}
function Protect-Text([string]$Text) {
    # Explicit organization/person names are essential for free-form prose.
    foreach ($literal in $script:literals) {
        $Text = Replace-Pattern $Text ([regex]::Escape($literal)) 'Entity'
    }
    $Text = Replace-Pattern $Text '(?is)-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----.*?-----END (?:[A-Z0-9 ]*PRIVATE KEY)-----' 'Secret'
    $Text = Replace-Pattern $Text '(?im)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)\s*[:=]\s*(?<value>[^\r\n]+)' 'Secret'
    $Text = Replace-Pattern $Text '(?i)\b(?:Bearer|Basic)\s+(?<value>[A-Za-z0-9+/_.=~-]+)' 'Secret'
    $Text = Replace-Pattern $Text '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b' 'Secret'
    $Text = Replace-Pattern $Text '(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{16,})\b' 'Secret'
    $Text = Replace-Pattern $Text '(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"'']+' 'URL'
    $Text = Replace-Pattern $Text '(?i)\b[A-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b' 'Email'
    $Text = Replace-Pattern $Text '(?i)\bS-1-\d+(?:-\d+){1,14}\b' 'SID'
    $Text = Replace-Pattern $Text '(?i)\b(?:[a-z0-9_.-]+)\\(?<value>[a-z0-9_$.-]+)\b' 'Account'
    $Text = Replace-Pattern $Text '(?i)[a-z]:\\Users\\(?<value>[^\\\s<>"'']+)' 'Person'
    $Text = Replace-Pattern $Text '(?i)/(?:home|Users)/(?<value>[^/\s]+)' 'Person'
    $Text = Replace-Pattern $Text '(?im)\b(?:user(?:name)?|account(?:name)?|technician|owner|computer(?:name)?|hostname|server(?:name)?|domain|tenant(?:id)?|device(?:id)?|serial(?:number)?|from|to|cc|bcc|reply-to)\s*[:=]\s*"?(?<value>[^"\r\n<>]+)' 'Identity'
    $Text = Replace-Pattern $Text '(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])' 'IPaddr'
    # Validate IPv6 candidates to avoid treating timestamps as addresses.
    $Text = [regex]::Replace($Text, '(?i)(?<![\w:])[0-9a-f:]*:[0-9a-f:]+(?:%[\w.-]+)?(?![\w:])', [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $address = $null
        if ([System.Net.IPAddress]::TryParse($m.Value, [ref]$address) -and $address.AddressFamily -eq 'InterNetworkV6') { return Get-Alias 'IPaddr' $m.Value }
        return $m.Value
    })
    $Text = Replace-Pattern $Text '(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b' 'MAC'
    $Text = Replace-Pattern $Text '\b\d{3}-\d{2}-\d{4}\b' 'PersonalID'
    $Text = Replace-Pattern $Text '(?<!\d)(?:\+?\d[ .()-]*){10,16}(?!\d)' 'Number'
    $Text = Replace-Pattern $Text '(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|edu|gov|local|internal|corp|io|co|uk|de|au)\b' 'Host'
    return $Text
}
function Read-ZipXml($Entry) {
    $reader = [System.IO.StreamReader]::new($Entry.Open())
    try {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $xr = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($reader.ReadToEnd()), $settings)
        try { $doc = [System.Xml.XmlDocument]::new(); $doc.XmlResolver = $null; $doc.Load($xr); return ,$doc } finally { $xr.Dispose() }
    } finally { $reader.Dispose() }
}
function Read-Office([string]$Path, [string]$Extension) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($Extension -eq '.docx') {
            $parts = @($zip.Entries | Where-Object { $_.FullName -match '^word/(document|header\d*|footer\d*|comments|footnotes|endnotes)\.xml$' })
            if (-not ($parts | Where-Object FullName -eq 'word/document.xml')) { throw 'Invalid Word document.' }
            $output = foreach ($part in $parts) {
                "--- $($part.FullName) ---"
                $doc = Read-ZipXml $part
                foreach ($p in $doc.SelectNodes('//*[local-name()="p"]')) {
                    ($p.SelectNodes('.//*[local-name()="t" or local-name()="tab" or local-name()="br"]') | ForEach-Object {
                        if ($_.LocalName -eq 'tab') { "`t" } elseif ($_.LocalName -eq 'br') { "`n" } else { $_.InnerText }
                    }) -join ''
                }
            }
        } else {
            $strings = @()
            $shared = $zip.GetEntry('xl/sharedStrings.xml')
            if ($shared) {
                $doc = Read-ZipXml $shared
                $strings = @($doc.SelectNodes('//*[local-name()="si"]') | ForEach-Object { ($_.SelectNodes('.//*[local-name()="t"]') | ForEach-Object InnerText) -join '' })
            }
            $output = foreach ($part in ($zip.Entries | Where-Object FullName -match '^xl/worksheets/sheet\d+\.xml$' | Sort-Object FullName)) {
                "--- $($part.FullName) ---"
                $doc = Read-ZipXml $part
                foreach ($row in $doc.SelectNodes('//*[local-name()="row"]')) {
                    $cells = foreach ($cell in $row.SelectNodes('./*[local-name()="c"]')) {
                        $v = $cell.SelectSingleNode('./*[local-name()="v"]')
                        $value = if ($cell.GetAttribute('t') -eq 's' -and $v) { $strings[[int]$v.InnerText] }
                        elseif ($cell.GetAttribute('t') -eq 'inlineStr') { ($cell.SelectNodes('.//*[local-name()="t"]') | ForEach-Object InnerText) -join '' }
                        elseif ($v) { $v.InnerText } else { '' }
                        # Formulas/links are intentionally not exported; cached values only.
                        $cell.GetAttribute('r') + '=' + $value
                    }
                    $cells -join "`t"
                }
            }
            if (-not $output) { throw 'No readable worksheets found.' }
        }
        return $output -join [Environment]::NewLine
    } finally { $zip.Dispose() }
}
if ($SensitiveValuesFile) { $SensitiveLiteral += [System.IO.File]::ReadAllLines((Resolve-Path -LiteralPath $SensitiveValuesFile).Path) }
$script:literals = @($SensitiveLiteral | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique | Sort-Object Length -Descending)
$out = [System.IO.Path]::GetFullPath($OutputDirectory)
[void][System.IO.Directory]::CreateDirectory($out)
$results = @()
foreach ($inputItem in $InputPath) {
    $path = (Resolve-Path -LiteralPath $inputItem).Path
    if (-not [System.IO.File]::Exists($path)) { throw "Input must be a file: $path" }
    $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
    $suffix = '.txt'
    switch ($ext) {
        '.evtx' {
            if (-not $IsWindows) { throw 'EVTX requires Windows and Get-WinEvent.' }
            $events = @(Get-WinEvent -Path $path -Oldest -ErrorAction Stop | ForEach-Object { $_.ToXml() })
            $text = '<Events>' + [Environment]::NewLine + ($events -join [Environment]::NewLine) + [Environment]::NewLine + '</Events>'
            $suffix = '.xml.txt'
        }
        { $_ -in '.docx', '.xlsx' } { $text = Read-Office $path $ext }
        { $_ -in '.doc', '.xls', '.xlsb', '.msg', '.pst', '.ost', '.pdf', '.rtf', '.evt', '.etl', '.docm', '.xlsm' } {
            throw "Unsupported binary format $ext. Export locally to TXT, CSV, DOCX, XLSX, EML (plain text), or EVTX first."
        }
        default {
            $bytes = [System.IO.File]::ReadAllBytes($path)
            # BOM-aware UTF-8/UTF-16; reject ambiguous legacy encodings rather than corrupt them.
            if ($bytes.Length -ge 2 -and (($bytes[0] -eq 255 -and $bytes[1] -eq 254) -or ($bytes[0] -eq 254 -and $bytes[1] -eq 255))) {
                $text = [System.IO.File]::ReadAllText($path)
            } else { $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF) }
            if ($text.Contains([char]0)) { throw 'Binary input is not supported.' }
            if ($ext -eq '.eml' -and $text -match '(?im)^(Content-Type:\s*(multipart/|text/html)|Content-Transfer-Encoding:\s*(base64|quoted-printable)|Content-Disposition:\s*attachment)') {
                throw 'Encoded, HTML, or multipart email must first be exported locally as plain text, including any attachments requiring analysis.'
            }
            if ($ext -eq '.csv') { $suffix = '.csv' }
        }
    }
    $safe = Protect-Text $text
    $destination = Join-Path $out ([System.IO.Path]::GetFileNameWithoutExtension($path) + '.review' + $suffix)
    if ([System.IO.File]::Exists($destination) -or $destination -eq $path) { throw "Refusing to overwrite: $destination" }
    # CreateNew also prevents concurrent overwrite. Source filenames may themselves identify people.
    $stream = [System.IO.File]::Open($destination, [System.IO.FileMode]::CreateNew)
    try { $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false)); try { $writer.Write($safe) } finally { $writer.Dispose() } } finally { $stream.Dispose() }
    $results += [pscustomobject]@{ Output = $destination; Status = 'Human review required' }
}
$results
