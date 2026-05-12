@echo off
echo Building 64-bit LSP DLL...

set BUILD_DIR=D:\JsNetwork\JsNetwork\build-lsp64

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cd /d "%BUILD_DIR%"

echo.
echo Configuring with CMake (x64)...
cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release ..\lsp64

if errorlevel 1 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

echo.
echo Building...
cmake --build . --config Release

if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build successful!
echo Output: %BUILD_DIR%\Release\jsnetwork_lsp.dll
echo.

pause
