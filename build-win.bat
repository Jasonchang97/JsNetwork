@echo off
echo Building JsNetwork for Windows...

set SOURCE_DIR=%~dp0
set BUILD_DIR=%SOURCE_DIR%build-win2
set LSP64_DIR=%SOURCE_DIR%build-lsp64

REM Allow environment variables to override defaults
if "%QT5_DIR%"=="" set QT5_DIR=D:\aqua\debug\xwares\3rd\qt5\build_x86\qtbase
if "%OPENSSL_DIR%"=="" set OPENSSL_DIR=D:\aqua\debug\xwares\3rd\static\x86-windows-static
if "%VCPKG_LIB_DIR%"=="" set VCPKG_LIB_DIR=D:\aqua\debug\xwares\3rd\default\x86-windows
if "%NPCAP_SDK_DIR%"=="" set NPCAP_SDK_DIR=D:\npcap-sdk

echo.
echo === Building main project (32-bit) ===
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd /d "%BUILD_DIR%"
cmake -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release ^
    -DQT5_DIR="%QT5_DIR%" ^
    -DOPENSSL_DIR="%OPENSSL_DIR%" ^
    -DVCPKG_LIB_DIR="%VCPKG_LIB_DIR%" ^
    -DNPCAP_SDK_DIR="%NPCAP_SDK_DIR%" ^
    "%SOURCE_DIR%"
if errorlevel 1 ( echo CMake configure failed! & pause & exit /b 1 )
cmake --build . --config Release
if errorlevel 1 ( echo Build failed! & pause & exit /b 1 )

echo.
echo === Building 64-bit LSP ===
if not exist "%LSP64_DIR%" mkdir "%LSP64_DIR%"
cd /d "%LSP64_DIR%"
cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release "%SOURCE_DIR%lsp64"
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
