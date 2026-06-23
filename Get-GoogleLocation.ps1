<#
.SYNOPSIS
    Queries Google Geolocation API using a BSSID (MAC address) to determine approximate coordinates.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$BSSID,

    [Parameter(Mandatory = $false)]
    [string]$DeviceFingerprint = "google/cheetah/cheetah:14/AP1A.240305.019.A1/11445907:user/release-keys",

    [switch]$Map
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Get-VarintBytes {
    param ([long]$Value)
    $bytes = @()
    do {
        $byte = $Value -band 0x7F
        $Value = $Value -shr 7
        if ($Value -ne 0) {
            $byte = $byte -bor 0x80
        }
        $bytes += [byte]$byte
    } while ($Value -ne 0)
    return $bytes
}

function Format-MacAddress {
    param ([string]$Mac)
    $clean = $Mac -replace "[:\-\.]", ""
    if ($clean.Length -ne 12) { return $Mac } 
    return -join ($clean.ToCharArray() | ForEach-Object { 
            $i++; $_; if ($i % 2 -eq 0 -and $i -lt 12) { ':' } 
        })
}

# Deflate & CRC32 Functions and Vars
$hashBits = 15
$hashSize = 1 -shl $hashBits
$maxWindowSize = 32768
$minMatchLen = 4
$maxMatchLen = 258
$baseMatchLen = 3

$baseLengths = [uint16[]]@(3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258)
$baseLengthsExtraBits = [byte[]]@(0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0)
$baseDistances = [uint16[]]@(1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577)
$baseDistanceExtraBits = [byte[]]@(0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13)

$baseLengthIndices = New-Object byte[] 259
for ($i = 3; $i -le 258; $i++) {
    $idx = 0
    for ($j = 0; $j -lt $baseLengths.Length; $j++) {
        if ($i -ge $baseLengths[$j] -and ($j -eq $baseLengths.Length - 1 -or $i -lt $baseLengths[$j + 1])) {
            $idx = $j; break
        }
    }
    $baseLengthIndices[$i - 3] = [byte]$idx
}

$distanceCodes = New-Object byte[] 256
for ($i = 0; $i -lt 256; $i++) {
    $idx = 0
    for ($j = 0; $j -lt $baseDistances.Length; $j++) {
        if ($i -ge ($baseDistances[$j] - 1) -and ($j -eq $baseDistances.Length - 1 -or $i -lt ($baseDistances[$j + 1] - 1))) {
            $idx = $j; break
        }
    }
    $distanceCodes[$i] = [byte]$idx
}

function Get-DistanceCodeIndex {
    param([uint16]$dist)
    if ($dist -lt $script:distanceCodes.Length) { return $script:distanceCodes[$dist] }
    elseif (($dist -shr 7) -lt $script:distanceCodes.Length) { return [uint16]($script:distanceCodes[$dist -shr 7] + 14) }
    else { return [uint16]($script:distanceCodes[$dist -shr 14] + 28) }
}

function Get-ReverseBits {
    param([uint16]$n, [int]$length)
    [uint16]$reversed = 0
    for ($i = 0; $i -lt $length; $i++) {
        $reversed = [uint16](($reversed -shl 1) -bor ($n -band 1))
        $n = [uint16]($n -shr 1)
    }
    return $reversed
}

function New-HuffmanCodes {
    param([byte[]]$lengths)
    $result = New-Object uint16[] $lengths.Length
    $lengthCounts = New-Object byte[] 16
    foreach ($l in $lengths) { $lengthCounts[$l]++ }
    $lengthCounts[0] = 0

    $nextCode = New-Object uint16[] 16
    for ($i = 1; $i -le 15; $i++) {
        $nextCode[$i] = [uint16](($nextCode[$i - 1] + $lengthCounts[$i - 1]) -shl 1)
    }

    for ($i = 0; $i -lt $result.Length; $i++) {
        if ($lengths[$i] -ne 0) {
            $result[$i] = [uint16]((Get-ReverseBits $nextCode[$lengths[$i]] 16) -shr (16 - $lengths[$i]))
            $nextCode[$lengths[$i]]++
        }
    }
    return $result
}

$fixedLitLenCodeLengths = New-Object byte[] 288
for ($i = 0; $i -le 143; $i++) { $fixedLitLenCodeLengths[$i] = 8 }
for ($i = 144; $i -le 255; $i++) { $fixedLitLenCodeLengths[$i] = 9 }
for ($i = 256; $i -le 279; $i++) { $fixedLitLenCodeLengths[$i] = 7 }
for ($i = 280; $i -le 287; $i++) { $fixedLitLenCodeLengths[$i] = 8 }
$fixedLitLenCodes = New-HuffmanCodes $fixedLitLenCodeLengths

$fixedDistanceCodeLengths = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $fixedDistanceCodeLengths[$i] = 5 }
$fixedDistanceCodes = New-HuffmanCodes $fixedDistanceCodeLengths

function Get-Hash4 {
    param([byte[]]$src, [int]$start)
    [uint32]$val = [uint32]$src[$start] -bor ([uint32]$src[$start + 1] -shl 8) -bor ([uint32]$src[$start + 2] -shl 16) -bor ([uint32]$src[$start + 3] -shl 24)
    $product = ([uint64]$val * [uint64]506828733) % [uint64]4294967296
    return [uint32]($product -shr (32 - $hashBits))
}

function DetermineMatchLength {
    param([byte[]]$src, [int]$s1, [int]$s2, [int]$limit)
    $result = 0
    while ($s2 -lt $limit) {
        if ($src[$s2] -ne $src[$s1 + $result]) { return $result }
        $s2++; $result++
    }
    return $result
}

function Compress-DeflateFixed {
    param([byte[]]$src)
    
    $blockStart = 0
    $blockLen = $src.Length
    $encoding = New-Object System.Collections.Generic.List[uint16]
    $configGood = 8; $configNice = 128; $configChain = 128
    
    $pos = $blockStart
    $literalLen = 0
    $head = New-Object uint16[] $script:hashSize
    $chain = New-Object uint16[] $script:maxWindowSize
    
    while ($pos -lt ($blockStart + $blockLen)) {
        if ($pos + $script:minMatchLen -ge $blockStart + $blockLen) {
            $remaining = $blockStart + $blockLen - $pos + $literalLen
            while ($remaining -gt 0) {
                $added = [Math]::Min($remaining, 32767)
                $encoding.Add([uint16]$added)
                $remaining -= $added
            }
            break
        }
        
        $windowPos = [uint16](($pos - $blockStart) -band ($script:maxWindowSize - 1))
        $hash = Get-Hash4 $src $pos
        $chain[$windowPos] = $head[$hash]
        $head[$hash] = $windowPos
        
        $hashPos = $chain[$windowPos]
        $limit = [Math]::Min($blockStart + $blockLen, $pos + $script:maxMatchLen)
        $tries = $configChain
        $prevOffset = 0; $longestMatchOffset = 0; $longestMatchLen = 0
        
        while ($tries -gt 0 -and $hashPos -ne 0) {
            $tries--
            $offset = if ($hashPos -le $windowPos) { $windowPos - $hashPos } else { $windowPos - $hashPos + $script:maxWindowSize }
            if ($offset -le 0 -or $offset -lt $prevOffset) { break }
            $prevOffset = $offset
            
            $matchLen = DetermineMatchLength $src ($pos - $offset) $pos $limit
            if ($matchLen -gt $longestMatchLen) {
                if ($matchLen -ge $configGood) { $tries = $tries -shr 2 }
                $longestMatchLen = $matchLen
                $longestMatchOffset = $offset
            }
            if ($longestMatchLen -ge $configNice -or $hashPos -eq $chain[$hashPos]) { break }
            $hashPos = $chain[$hashPos]
        }
        
        if ($longestMatchLen -gt $script:minMatchLen) {
            if ($literalLen -gt 0) {
                $remaining = $literalLen
                while ($remaining -gt 0) {
                    $added = [Math]::Min($remaining, 32767)
                    $encoding.Add([uint16]$added)
                    $remaining -= $added
                }
                $literalLen = 0
            }
            
            $lengthIndex = $script:baseLengthIndices[$longestMatchLen - $script:baseMatchLen]
            $distIndex = Get-DistanceCodeIndex ([uint16]($longestMatchOffset - 1))
            $encoding.Add([uint16]((([uint16]$lengthIndex -shl 8) -bor $distIndex) -bor 32768))
            $encoding.Add([uint16]$longestMatchOffset)
            $encoding.Add([uint16]$longestMatchLen)
            
            for ($k = 1; $k -lt $longestMatchLen; $k++) {
                $pos++
                $windowPos = [uint16]($pos -band ($script:maxWindowSize - 1))
                if ($pos + $script:minMatchLen -lt $blockStart + $blockLen) {
                    $hash = Get-Hash4 $src $pos
                    $chain[$windowPos] = $head[$hash]
                    $head[$hash] = $windowPos
                }
            }
        }
        else {
            $literalLen++
        }
        $pos++
    }
    
    $dst = New-Object System.Collections.Generic.List[byte]
    $state = New-Object PSObject -Property @{
        bits   = [uint64]0
        bitLen = [int]0
    }
    
    function AddBits([uint32]$val, [int]$length, $dst, $state) {
        $shifted = [uint64]$val -shl $state.bitLen
        $state.bits = $state.bits -bor $shifted
        $state.bitLen += $length
        while ($state.bitLen -ge 8) {
            $dst.Add([byte]($state.bits -band 0xFF))
            $state.bits = $state.bits -shr 8
            $state.bitLen -= 8
        }
    }
    
    AddBits 1 1 $dst $state
    AddBits 1 2 $dst $state
    
    $srcPos = $blockStart
    $encPos = 0
    while ($encPos -lt $encoding.Count) {
        if (($encoding[$encPos] -band 32768) -ne 0) {
            $value = $encoding[$encPos]
            $offset = $encoding[$encPos + 1]
            $length = $encoding[$encPos + 2]
            $lengthIndex = ($value -shr 8) -band 127
            $distanceIndex = $value -band 0xFF
            $lengthExtraBits = $script:baseLengthsExtraBits[$lengthIndex]
            $lengthExtra = $length - $script:baseLengths[$lengthIndex]
            $distanceExtraBits = $script:baseDistanceExtraBits[$distanceIndex]
            $distanceExtra = $offset - $script:baseDistances[$distanceIndex]
            
            $encPos += 3; $srcPos += $length
            
            [uint64]$buf = $script:fixedLitLenCodes[$lengthIndex + 257]
            $bLen = $script:fixedLitLenCodeLengths[$lengthIndex + 257]
            
            $buf = $buf -bor ([uint64]$lengthExtra -shl $bLen); $bLen += $lengthExtraBits
            $buf = $buf -bor ([uint64]$script:fixedDistanceCodes[$distanceIndex] -shl $bLen); $bLen += $script:fixedDistanceCodeLengths[$distanceIndex]
            $buf = $buf -bor ([uint64]$distanceExtra -shl $bLen); $bLen += $distanceExtraBits
            
            $firstAddLen = [Math]::Min($bLen, 32)
            AddBits ([uint32]$buf) $firstAddLen $dst $state
            $buf = $buf -shr $firstAddLen; $bLen -= $firstAddLen
            if ($bLen -gt 0) { AddBits ([uint32]$buf) $bLen $dst $state }
        }
        else {
            $literalsLength = $encoding[$encPos]; $encPos++
            [uint32]$buf = 0; $bLen = 0
            for ($k = 0; $k -lt $literalsLength; $k++) {
                $codeLength = $script:fixedLitLenCodeLengths[$src[$srcPos]]
                if ($bLen + $codeLength -gt 32) { AddBits $buf $bLen $dst $state; $buf = 0; $bLen = 0 }
                $buf = $buf -bor ([uint32]$script:fixedLitLenCodes[$src[$srcPos]] -shl $bLen); $bLen += $codeLength; $srcPos++
            }
            if ($bLen -gt 0) { AddBits $buf $bLen $dst $state }
        }
    }
    
    AddBits $script:fixedLitLenCodes[256] $script:fixedLitLenCodeLengths[256] $dst $state
    
    if ($state.bitLen -gt 0) {
        $dst.Add([byte]($state.bits -band 0xFF))
    }
    
    return $dst.ToArray()
}

function Get-Crc32 {
    param([byte[]]$data)
    $crcTable = New-Object uint32[] 256
    $poly = [uint32]3988292384
    for ([uint32]$i = 0; $i -lt 256; $i++) {
        [uint32]$c = $i
        for ($j = 0; $j -lt 8; $j++) {
            if (($c -band 1) -ne 0) { $c = $poly -bxor ($c -shr 1) }
            else { $c = $c -shr 1 }
        }
        $crcTable[$i] = $c
    }
    [uint32]$crc = 4294967295
    foreach ($b in $data) {
        $crc = $crcTable[($crc -bxor $b) -band 255] -bxor ($crc -shr 8)
    }
    return $crc -bxor 4294967295
}

# Main
$BSSIDFormatted = Format-MacAddress $BSSID
Write-Host ""
Write-Host "Searching for location of BSSID: $BSSIDFormatted"

# Calculate Varint for MAC
[long]$macLong = 0
$cleanMac = $BSSIDFormatted -replace ":", ""
for ($i = 0; $i -lt $cleanMac.Length; $i += 2) {
    $macLong = ($macLong -shl 8) -bor [Convert]::ToByte($cleanMac.Substring($i, 2), 16)
}
$varintBytes = Get-VarintBytes $macLong

# Build Uncompressed Payload
$fpBytes = [System.Text.Encoding]::UTF8.GetBytes($DeviceFingerprint)
$fpLenVarint = Get-VarintBytes $fpBytes.Length
$outerLenVarint = Get-VarintBytes (14 + $fpLenVarint.Length + $fpBytes.Length)

$prefix = [byte[]]@(0x0A) + $outerLenVarint + 
[byte[]]@(0x0A, 0x04, 0x32, 0x30, 0x32, 0x31, 0x12) + $fpLenVarint + $fpBytes + 
[byte[]]@(0x2A, 0x05, 0x65, 0x6E, 0x5F, 0x55, 0x53, 0x22, 0x22, 0x12, 0x1E, 0x08, 0xA3, 0xF7, 0x09, 0x12, 0x0A, 0x0A, 0x00, 0x40)

$suffix = [System.Convert]::FromBase64String("EgoKAEDmqpGao6QEGAJQAA==")

$uncompBytes = $prefix + $varintBytes + $suffix

# Compress
$deflateData = Compress-DeflateFixed $uncompBytes
$crc = Get-Crc32 $uncompBytes

# Build GZIP
$gzipHeader = [System.Convert]::FromBase64String("H4sIAAAAAAAAAA==")
$crcBytes = [System.BitConverter]::GetBytes([uint32]$crc)
$lenBytes = [System.BitConverter]::GetBytes([uint32]$uncompBytes.Length)
$compressed = $gzipHeader + $deflateData + $crcBytes + $lenBytes

# Build MASF Header & Payload
$masfHeader = [System.Convert]::FromBase64String("AAIAAB9sb2NhdGlvbiwyMDIxLGFuZHJvaWQsZ21zLGVuX1VTAAAAAAAAAAAAAWcAAAC7AAEBAAEACGc6bG9jL3FsAAAABFBPU1RtcgAAAARST09UAAAAAJMAAWc=")

$plenBytes = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int]($compressed.Length + 40)))
[System.Array]::Copy($plenBytes, 0, $masfHeader, 47, 4)
$pLenUshort = [System.BitConverter]::GetBytes([uint16]$compressed.Length)
[System.Array]::Copy($pLenUshort, 0, $masfHeader, 88, 2)

$payloadData = $masfHeader + $compressed + [byte[]]@(0x00, 0x00)

# Send HTTP Web Request
$url = "https://www.google.com/loc/m/api"
try {
    $req = [System.Net.WebRequest]::Create($url)
    $req.Method = "POST"
    $req.ContentType = "application/binary"
    $req.Proxy = $null
    $req.ContentLength = $payloadData.Length

    $stream = $req.GetRequestStream()
    $stream.Write($payloadData, 0, $payloadData.Length)
    $stream.Close()

    $resp = $req.GetResponse()
    $respStream = $resp.GetResponseStream()
    $ms = New-Object System.IO.MemoryStream
    $respStream.CopyTo($ms)
    $respBytes = $ms.ToArray()
    $resp.Close()
    $ms.Close()
}
catch {
    Write-Host "HTTP Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $errStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errStream)
        Write-Host "MASF Protocol Error: $($reader.ReadToEnd())" -ForegroundColor Red
        $reader.Close()
    }
    exit
}

# Parse Response
$gzStart = -1
for ($i = 0; $i -lt $respBytes.Length - 1; $i++) {
    if ($respBytes[$i] -eq 0x1f -and $respBytes[$i + 1] -eq 0x8b) {
        $gzStart = $i
        break
    }
}

if ($gzStart -ne -1) {
    $gzBytes = $respBytes[$gzStart..($respBytes.Length - 1)]
    $msGz = New-Object System.IO.MemoryStream(, $gzBytes)
    $msUncompResp = New-Object System.IO.MemoryStream
    $gzResp = New-Object System.IO.Compression.GZipStream($msGz, [System.IO.Compression.CompressionMode]::Decompress)
    $gzResp.CopyTo($msUncompResp)
    $uncomp = $msUncompResp.ToArray()
    
    $lat = $null
    $lon = $null
    for ($i = 0; $i -lt $uncomp.Length - 9; $i++) {
        if ($uncomp[$i] -eq 0x0d -and $uncomp[$i + 5] -eq 0x15) {
            $lat = [System.BitConverter]::ToInt32($uncomp, $i + 1) / 10000000.0
            $lon = [System.BitConverter]::ToInt32($uncomp, $i + 6) / 10000000.0
            break
        }
    }
    
    if ($null -ne $lat -and $null -ne $lon) {
        Write-Host "BSSID:     $BSSIDFormatted" -ForegroundColor Green
        Write-Host "Latitude:  $lat"
        Write-Host "Longitude: $lon"
        Write-Host "Google Maps: https://www.google.com/maps/search/?api=1&query=$lat,$lon"
        
        if ($Map) {
            Start-Process "https://www.google.com/maps/search/?api=1&query=$lat,$lon"
        }
    }
    else {
        Write-Host "The BSSID was not found." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Error: Could not parse coordinates from MASF binary response." -ForegroundColor Red
}
