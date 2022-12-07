Set-StrictMode -version Latest
Set $ErrorActionPreference='Stop'

$Configuration = "Release"

$SrcDir = "$PSScriptRoot/../src";
$OutDir = "$PSScriptRoot/../src/acryptohashnet/bin/$Configuration"
$TargetDir = "$PSScriptRoot/../bin"

dotnet build "$SrcDir/acryptohashnet.sln" --configuration $Configuration

New-Item -Force -Type Directory $TargetDir | Out-Null
Copy-Item -Force "$OutDir/netstandard2.1/*.dll" $TargetDir
Copy-Item -Force "$OutDir/*.nupkg" $TargetDir
