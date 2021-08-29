Set-StrictMode -version Latest

$SrcDir = "$PSScriptRoot/../src";
$OutDir = "$PSScriptRoot/../src/acryptohashnet/bin/Release"
$TargetDir = "$PSScriptRoot/../bin"

msbuild.exe "$SrcDir/acryptohashnet.sln" /p:Configuration=Release

New-Item -Force -Type Directory $TargetDir
Copy-Item -Force "$OutDir/netstandard2.1/*" $TargetDir
Copy-Item -Force "$OutDir/*.nupkg" $TargetDir
