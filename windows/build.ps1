param(
    [string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
    [string]$GitPath = "C:\Program Files\Git\bin\git.exe",
    [string]$SevenZPath = "C:\Program Files\7-Zip\7z.exe",
    [string]$GPGPath = "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
)

$CMake = $(Get-Command cmake -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($CMake)) {
    $CMake = $CMakePath
}

$Git = $(Get-Command git -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($Git)) {
    $Git = $GitPath
}

$SevenZ = $(Get-Command 7z -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($SevenZ) -and [string]::IsNullOrEmpty($SevenZPath)) {
    throw "Unable to locate 7z.exe"
} elseif([string]::IsNullOrEmpty($SevenZ)) {
    $SevenZ = $SevenZPath
}

$GPG = $(Get-Command gpg -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($GPG)) {
    $GPG = $GPGPath
}

if(-Not (Test-Path $CMake)) {
    throw "Unable to find CMake at $CMake"
}

if(-Not (Test-Path $Git)) {
    throw "Unable to find Git at $Git"
}

if(-Not (Test-Path $SevenZ)) {
    throw "Unable to find 7z at $SevenZ"
}

if(-Not (Test-Path $GPG)) {
    throw "Unable to find GPG at $GPG"
}

Write-Host "Git: $Git"
Write-Host "CMake: $CMake"
Write-Host "7z: $SevenZ"
Write-Host "GPG: $GPG"

New-Item -Type Directory $PSScriptRoot\..\build -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libressl-2.9.1-Win64 -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libcbor-0.5.0-Win64 -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libfido2-Win64 -ErrorAction Ignore

Push-Location $PSScriptRoot\..\build

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Write-Host "Building LibreSSL..."
    if(-Not (Test-Path libressl-2.9.1)) {
        Invoke-WebRequest https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.9.1.tar.gz -OutFile libressl-2.9.1.tar.gz
        & Invoke-WebRequest https://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.9.1.tar.gz.asc -OutFile libressl-2.9.1.tar.gz.asc
        & Copy-Item "$PSScriptRoot\libressl.gpg" -Destination "$PSScriptRoot\..\build"
        & $GPG --list-keys
        & $GPG -v --no-default-keyring --keyring ./libressl.gpg --verify libressl-2.9.1.tar.gz.asc libressl-2.9.1.tar.gz
        if ($LastExitCode -ne 0) {
            throw "gpg signature verification failed"
        }
        & $SevenZ e .\libressl-2.9.1.tar.gz
        & $SevenZ x .\libressl-2.9.1.tar
        Remove-Item -Force .\libressl-2.9.1.tar.gz
        Remove-Item -Force .\libressl-2.9.1.tar
    }

    if(-Not (Test-Path .\libressl-2.9.1\build)) {
        New-Item -Type Directory .\libressl-2.9.1\build
    }

    Push-Location libressl-2.9.1\build
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libressl-2.9.1-Win64" -DBUILD_SHARED_LIBS=ON -DLIBRESSL_TESTS=OFF
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
    Pop-Location

    # XXX no signature verification possible
    Write-host "Building libcbor..."
    if(-Not (Test-Path libcbor)) {
        & $Git clone --branch v0.5.0 https://github.com/pjk/libcbor
    }

    if(-Not (Test-Path .\libcbor\build)) {
        New-Item -Type Directory .\libcbor\build
    }

    Push-Location libcbor\build
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libcbor-0.5.0-Win64"
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
    Pop-Location

    Write-Host "Building libfido2..."
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCBOR_INCLUDE_DIRS="$PSScriptRoot\..\output\libcbor-0.5.0-Win64\include" -DCBOR_LIBRARY_DIRS="$PSScriptRoot\..\output\libcbor-0.5.0-Win64\lib" -DCRYPTO_INCLUDE_DIRS="$PSScriptRoot\..\output\libressl-2.9.1-Win64\include" -DCRYPTO_LIBRARY_DIRS="$PSScriptRoot\..\output\libressl-2.9.1-Win64\lib" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libfido2-Win64"
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
    & Copy-Item "$PSScriptRoot\..\output\libcbor-0.5.0-Win64\bin\cbor.dll" -Destination "$PSScriptRoot\..\build\examples\Release"
    & Copy-Item "$PSScriptRoot\..\output\libressl-2.9.1-Win64\bin\crypto-45.dll" -Destination "$PSScriptRoot\..\build\examples\Release"
} finally {
    Pop-Location
}