@echo off
echo Building JsNetwork for Windows...

set BUILD_DIR=D:\JsNetwork\JsNetwork\build-win2
set LSP64_DIR=D:\JsNetwork\JsNetwork\build-lsp64

echo.
echo === Building main project (32-bit) ===
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"
cmake -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release ..\CMakeLists.txt
if errorlevel 1 ( echo CMake configure failed! & pause & exit /b 1 )
cmake --build . --config Release
if errorlevel 1 ( echo Build failed! & pause & exit /b 1 )

echo.
echo === Building 64-bit LSP ===
if not exist "%LSP64_DIR%" mkdir "%LSP64_DIR%"
cd /d "%LSP64_DIR%"
cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release ..\lsp64
if errorlevel 1 ( echo LSP64 CMake configure failed! & pause & exit /b 1 )
cmake --build . --config Release
if errorlevel 1 ( echo LSP64 Build failed! & pause & exit /b 1 )

echo.
echo === Copying 64-bit LSP to output ===
mkdir "%BUILD_DIR%\Release\x64" 2>nul
copy /Y "%LSP64_DIR%\Release\jsnetwork_lsp.dll" "%BUILD_DIR%\Release\x64\jsnetwork_lsp.dll"
copy /Y "%LSP64_DIR%\Release\lsp_installer64.exe" "%BUILD_DIR%\Release\lsp_installer64.exe"

echo.
echo Build successful!
echo Output: %BUILD_DIR%\Release\JsNetwork.exe
echo 64-bit LSP: %BUILD_DIR%\Release\x64\jsnetwork_lsp.dll
echo.
