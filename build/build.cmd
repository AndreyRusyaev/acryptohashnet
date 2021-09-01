msbuild "../src/acryptohashnet.sln" /p:Configuration=Release

SET OutDir=../src/acryptohashnet/bin/Release/
SET TargetDir=../bin/

xcopy /I /Y /F "%OutDir%netstandard2.1/" "%TargetDir%"
xcopy /I /Y /F "%OutDir%*.nupkg" "%TargetDir%"
