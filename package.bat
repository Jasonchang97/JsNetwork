@echo off
echo Packaging JsNetwork for Windows...

set RELEASE_DIR=D:\JsNetwork\JsNetwork\build\Release
set OUTPUT_DIR=D:\JsNetwork\JsNetwork\dist
set OUTPUT_FILE=%OUTPUT_DIR%\JsNetwork-v0.1.0-win32.zip

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Creating package...
cd /d "%RELEASE_DIR%"

REM Check if PowerShell is available for zip creation
powershell -Command "Compress-Archive -Path 'JsNetwork.exe', 'Qt5CoreKso.dll', 'Qt5GuiKso.dll', 'Qt5NetworkKso.dll', 'Qt5SqlKso.dll', 'Qt5WidgetsKso.dll', 'platforms' -DestinationPath '%OUTPUT_FILE%' -Force"

if exist "%OUTPUT_FILE%" (
    echo.
    echo Package created successfully: %OUTPUT_FILE%
    echo.
    echo Contents:
    powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::OpenRead('%OUTPUT_FILE%').Entries | ForEach-Object { $_.FullName }"
) else (
    echo Failed to create package
)

pause
