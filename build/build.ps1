Set-StrictMode -version Latest
Set $ErrorActionPreference='Stop'

$Configuration = "Release"

$SrcDir = "$PSScriptRoot/../src";
$OutDir = "$PSScriptRoot/../src/acryptohashnet/bin/$Configuration"
$TargetDir = "$PSScriptRoot/../bin"

dotnet build "$SrcDir/acryptohashnet.sln" --configuration $Configuration

New-Item -Force -Type Directory $TargetDir | Out-Null
Compress-Archive -Force "$OutDir/net*" $TargetDir/acryptohashnet.zip
Copy-Item -Force "$OutDir/*.nupkg" $TargetDir
