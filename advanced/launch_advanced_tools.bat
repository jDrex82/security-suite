@echo off
REM ADVANCED SECURITY TOOLS LAUNCHER - WINDOWS
REM Quick launcher for Network Traffic Monitor, Ransomware Detector, and AD Monitor

title Advanced Security Tools Launcher v3.0

echo ================================================================
echo.
echo         ADVANCED SECURITY TOOLS - WINDOWS LAUNCHER v3.0
echo.
echo ================================================================
echo.

REM Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.6+
    pause
    exit /b 1
)

echo [OK] Python found
echo.

:MENU
echo ================================================================
echo AVAILABLE TOOLS
echo ================================================================
echo.
echo 1. Network Traffic Monitor (NTM)
echo    - Real-time traffic analysis
echo    - C2 beaconing detection
echo    - Data exfiltration monitoring
echo.
echo 2. Ransomware Behavior Detector (RBD)
echo    - Mass encryption detection
echo    - File entropy analysis
echo    - Backup tampering alerts
echo.
echo 3. Active Directory Monitor (ADSM)
echo    - Golden/Silver Ticket detection
echo    - GPO change monitoring
echo    - Domain security monitoring
echo.
echo 4. Run All Tools (Recommended)
echo.
echo 5. Exit
echo.
set /p TOOL_CHOICE="Select tool [1-5]: "

echo.
echo ================================================================
echo MONITORING MODE
echo ================================================================
echo.
echo 1. Quick Test (5 minutes)
echo 2. Short Monitoring (1 hour)
echo 3. Full Monitoring (24 hours)
echo.
set /p MODE_CHOICE="Select mode [1-3]: "

REM Set duration based on choice
if "%MODE_CHOICE%"=="1" (
    set DURATION=300
    set INTERVAL=30
    set MODE_NAME=Quick Test
)
if "%MODE_CHOICE%"=="2" (
    set DURATION=3600
    set INTERVAL=60
    set MODE_NAME=Short Monitoring
)
if "%MODE_CHOICE%"=="3" (
    set DURATION=86400
    set INTERVAL=300
    set MODE_NAME=Full Monitoring
)

echo.
echo [OK] Mode: %MODE_NAME%
echo [OK] Duration: %DURATION%s ^| Interval: %INTERVAL%s

REM Create logs directory
if not exist logs mkdir logs
echo [OK] Log directory: .\logs
echo.

echo ================================================================
echo STARTING TOOLS
echo ================================================================
echo.

if "%TOOL_CHOICE%"=="1" goto NTM
if "%TOOL_CHOICE%"=="2" goto RBD
if "%TOOL_CHOICE%"=="3" goto ADSM
if "%TOOL_CHOICE%"=="4" goto ALL
if "%TOOL_CHOICE%"=="5" goto EXIT
goto INVALID

:NTM
echo [*] Starting Network Traffic Monitor...
echo.
python network_traffic_monitor.py --monitor --duration %DURATION% --interval %INTERVAL% --export .\logs\ntm_results.json
goto COMPLETE

:RBD
echo [*] Starting Ransomware Behavior Detector...
echo.
python ransomware_detector.py --monitor --duration %DURATION% --interval %INTERVAL% --export .\logs\rbd_results.json
goto COMPLETE

:ADSM
echo [*] Starting Active Directory Monitor...
echo.
python ad_monitor.py --scan --export .\logs\adsm_results.json
goto COMPLETE

:ALL
echo [*] Starting all tools in background...
echo.

start /B python network_traffic_monitor.py --monitor --duration %DURATION% --interval %INTERVAL% --export .\logs\ntm_results.json
echo [OK] Network Traffic Monitor started

start /B python ransomware_detector.py --monitor --duration %DURATION% --interval %INTERVAL% --export .\logs\rbd_results.json
echo [OK] Ransomware Detector started

start /B python ad_monitor.py --scan --export .\logs\adsm_results.json
echo [OK] AD Monitor started

echo.
echo [*] All tools running in background
echo [*] Results will be saved to .\logs\
echo [*] Close this window when monitoring is complete
echo.
pause
goto COMPLETE

:INVALID
echo [ERROR] Invalid choice
pause
goto MENU

:EXIT
echo [*] Exiting...
exit /b 0

:COMPLETE
echo.
echo ================================================================
echo MONITORING COMPLETE
echo ================================================================
echo.
echo [OK] Results saved to .\logs\
echo.
echo Next steps:
echo   1. Review results in .\logs\ directory
echo   2. Check for CRITICAL alerts
echo   3. Set up continuous monitoring (see docs\INTEGRATION_GUIDE.md)
echo.
echo ================================================================
echo            MONITORING SESSION COMPLETE
echo ================================================================
echo.
pause
