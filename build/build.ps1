$BinDir = "../../bin";
$SourcesDir = "../src";

msbuild.exe "$SourcesDir/acryptohashnet.sln" /p:OutDir="$BinDir/"