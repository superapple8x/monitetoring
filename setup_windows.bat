@echo off
title Monitetoring Windows Setup Helper
echo.
echo ================================================
echo     Monitetoring Windows Setup Helper
echo ================================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running as Administrator
) else (
    echo [WARNING] Not running as Administrator
    echo           Please run this script as Administrator for full functionality
    echo.
)

REM Detect if this is source or binary release
if exist "Cargo.toml" (
    echo This appears to be a SOURCE CODE directory.
    echo This script will help install dependencies and build the project.
) else if exist "monitetoring.exe" (
    echo This appears to be a BINARY RELEASE directory.
    echo This script will help install dependencies for running the application.
) else (
    echo Directory type unclear - checking for Cargo.toml or monitetoring.exe
)

echo.
echo Checking Npcap installation status...
echo.

REM Check for Npcap service
sc query npcap >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Npcap Runtime service found
    sc query npcap | findstr "STATE"
    set RUNTIME_OK=1
) else (
    echo [MISSING] Npcap Runtime service not found
    set RUNTIME_OK=0
)

REM Check for Npcap SDK
echo.
echo Checking for Npcap SDK...
set SDK_OK=0
if exist "C:\Program Files\Npcap SDK\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK found at: C:\Program Files\Npcap SDK\
    set SDK_OK=1
) else if exist "C:\Npcap-SDK\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK found at: C:\Npcap-SDK\
    set SDK_OK=1
) else if exist "C:\Program Files\Npcap\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK found at: C:\Program Files\Npcap\
    set SDK_OK=1
) else (
    echo [MISSING] Npcap SDK not found
)

echo.
echo ================================================
echo                 STATUS SUMMARY
echo ================================================
if %RUNTIME_OK%==1 (
    echo Npcap Runtime: [OK] Installed
) else (
    echo Npcap Runtime: [MISSING] Not installed
)

if %SDK_OK%==1 (
    echo Npcap SDK:     [OK] Installed  
) else (
    echo Npcap SDK:     [MISSING] Not installed
)
echo ================================================

REM If everything is OK, check if we're in source or binary release
if %RUNTIME_OK%==1 if %SDK_OK%==1 (
    echo.
    echo Great! All dependencies are installed.
    echo.
    
    REM Check if this is a source directory or binary release
    if exist "Cargo.toml" (
        echo This appears to be a source code directory.
        set /p BUILD_NOW="Do you want to build monitetoring now? (y/n): "
        if /i "!BUILD_NOW!"=="y" goto :build
        if /i "!BUILD_NOW!"=="yes" goto :build
        echo.
        echo Setup complete. You can build manually with: cargo build --release
        goto :end
    ) else if exist "monitetoring.exe" (
        echo This appears to be a binary release - no building required!
        echo.
        echo You can now run: monitetoring.exe --help
        echo                   monitetoring.exe --iface ^<interface_name^>
        echo.
        echo Remember to run as Administrator for packet capture functionality.
        goto :end
    ) else (
        echo Setup complete. Dependencies are ready.
        echo.
        echo If this is a source directory, you can build with: cargo build --release
        echo If this is a binary release, look for monitetoring.exe
        goto :end
    )
)

REM Show installation guide if something is missing
echo.
echo ================================================
echo            INSTALLATION REQUIRED
echo ================================================
echo.
echo You need to install the missing components before building.
echo.

if %RUNTIME_OK%==0 (
    echo STEP 1: Install Npcap Runtime
    echo --------------------------------
    echo 1. Go to: https://npcap.com/#download
    echo 2. Download "Npcap [version] installer for Windows" (the main installer)
    echo 3. Run as Administrator
    echo 4. IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode"
    echo 5. Complete installation and reboot if prompted
    echo.
)

if %SDK_OK%==0 (
    echo STEP 2: Install Npcap SDK
    echo --------------------------
    echo 1. On the same download page, find "Npcap SDK [version] (ZIP)"
    echo 2. Download the SDK ZIP file
    echo 3. Extract to C:\Npcap-SDK\ or C:\Program Files\Npcap SDK\
    echo.
    echo NOTE: The SDK is SEPARATE from the runtime installer!
    echo       You need BOTH components - the installer AND the SDK ZIP.
    echo.
)

echo AFTER INSTALLING:
echo ------------------
echo 1. Close this window
echo 2. Run this script again to verify installation
echo 3. Build the project when all dependencies are ready
echo.

:confirm_install
set /p INSTALLED="Have you installed the missing components? (y/n): "
if /i "%INSTALLED%"=="y" goto :recheck
if /i "%INSTALLED%"=="yes" goto :recheck
if /i "%INSTALLED%"=="n" goto :end
if /i "%INSTALLED%"=="no" goto :end
echo Please enter y or n
goto :confirm_install

:recheck
echo.
echo Re-checking installation...
echo.

REM Re-check Npcap service
sc query npcap >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Npcap Runtime service now found
    set RUNTIME_OK=1
) else (
    echo [STILL MISSING] Npcap Runtime service not found
    echo                  Please install Npcap Runtime first
    set RUNTIME_OK=0
)

REM Re-check SDK
set SDK_OK=0
if exist "C:\Program Files\Npcap SDK\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK now found at: C:\Program Files\Npcap SDK\
    set SDK_OK=1
) else if exist "C:\Npcap-SDK\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK now found at: C:\Npcap-SDK\
    set SDK_OK=1
) else if exist "C:\Program Files\Npcap\Lib\x64\wpcap.lib" (
    echo [OK] Npcap SDK now found at: C:\Program Files\Npcap\
    set SDK_OK=1
) else (
    echo [STILL MISSING] Npcap SDK not found
    echo                  Please install Npcap SDK
)

REM Check if we can proceed now
if %RUNTIME_OK%==1 if %SDK_OK%==1 (
    echo.
    echo Excellent! All dependencies are now installed.
    echo.
    
    REM Check if this is a source directory or binary release
    if exist "Cargo.toml" (
        echo This appears to be a source code directory.
        set /p BUILD_NOW="Proceed with building monitetoring? (y/n): "
        if /i "!BUILD_NOW!"=="y" goto :build
        if /i "!BUILD_NOW!"=="yes" goto :build
        echo.
        echo You can build manually later with: cargo build --release
        goto :end
    ) else if exist "monitetoring.exe" (
        echo This appears to be a binary release - you're all set!
        echo.
        echo You can now run: monitetoring.exe --help
        echo                   monitetoring.exe --iface ^<interface_name^>
        echo.
        echo Remember to run as Administrator for packet capture functionality.
        goto :end
    ) else (
        echo Dependencies are ready.
        echo.
        echo If this is a source directory, you can build with: cargo build --release
        echo If this is a binary release, look for monitetoring.exe
        goto :end
    )
) else (
    echo.
    REM Check if this is a binary release - don't need to build anything
    if exist "monitetoring.exe" (
        echo This is a binary release. Dependencies are not critical for already-built executable.
        echo.
        echo You can try running: monitetoring.exe --help
        echo                      monitetoring.exe --iface ^<interface_name^>
        echo.
        echo Note: Some features may not work without proper Npcap installation.
        echo       Install missing components for full functionality.
        goto :end
    ) else (
        echo Some dependencies are still missing. Please complete the installation
        echo and run this script again.
        goto :end
    )
)

REM This should never be reached - everything above should goto :end
goto :end

:build
setlocal enabledelayedexpansion
echo.
echo ================================================
echo                 BUILDING PROJECT
echo ================================================
echo.
echo Building monitetoring...
echo This may take a few minutes...
echo.

cargo build --release
if %errorLevel% == 0 (
    echo.
    echo ================================================
    echo                BUILD SUCCESSFUL!
    echo ================================================
    echo.
    echo The monitetoring executable is ready at:
    echo target\release\monitetoring.exe
    echo.
    echo To run monitetoring:
    echo   target\release\monitetoring.exe --help
    echo   target\release\monitetoring.exe --iface ^<interface_name^>
    echo.
    echo REMEMBER: Run as Administrator for packet capture functionality
    echo.
) else (
    echo.
    echo ================================================
    echo                 BUILD FAILED
    echo ================================================
    echo.
    echo The build failed. Common issues:
    echo - Missing Npcap SDK components
    echo - Incorrect SDK installation path
    echo - Missing Visual Studio Build Tools
    echo.
    echo Try running this script again or check the error messages above.
    echo.
)

:end
echo.
echo Press any key to exit...
pause >nul 