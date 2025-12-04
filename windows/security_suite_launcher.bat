@echo off
REM ============================================================================
REM Complete Security Suite Launcher for Windows
REM Version 2.0 - Windows Compatible
REM ============================================================================

color 0A
title Security Monitoring Toolkit - Windows Edition

:MENU
cls
echo.
echo ========================================================================
echo           CYBERSECURITY MONITORING TOOLKIT - WINDOWS EDITION
echo ========================================================================
echo.
echo  [CROSS-PLATFORM TOOLS]
echo  1. Port Scanner           - Scan network ports and services
echo  2. SSL Monitor            - Check SSL/TLS certificates
echo  3. Web Log Analyzer       - Analyze web server logs
echo.
echo  [WINDOWS SYSTEM TOOLS]
echo  4. Event Log Monitor      - Monitor Windows security events
echo  5. File Integrity Monitor - Detect file changes
echo  6. Privilege Monitor      - Detect privilege escalation
echo  7. Process Monitor        - Monitor processes and connections
echo.
echo  [UTILITIES]
echo  8. Run All Quick Scan     - Basic security check (all tools)
echo  9. View Documentation     - Open README files
echo  10. Check Requirements    - Verify Python installation
echo.
echo  0. Exit
echo.
echo ========================================================================
echo.

set /p choice="Enter your choice (0-10): "

if "%choice%"=="1" goto PORT_SCANNER
if "%choice%"=="2" goto SSL_MONITOR
if "%choice%"=="3" goto WEB_LOG_ANALYZER
if "%choice%"=="4" goto EVENT_LOG_MONITOR
if "%choice%"=="5" goto FILE_INTEGRITY
if "%choice%"=="6" goto PRIVILEGE_MONITOR
if "%choice%"=="7" goto PROCESS_MONITOR
if "%choice%"=="8" goto RUN_ALL
if "%choice%"=="9" goto DOCUMENTATION
if "%choice%"=="10" goto CHECK_REQUIREMENTS
if "%choice%"=="0" goto EXIT
goto MENU

REM ============================================================================
REM Cross-Platform Tools
REM ============================================================================

:PORT_SCANNER
cls
echo.
echo ========================================================================
echo                            PORT SCANNER
echo ========================================================================
echo.
set /p target="Enter target IP or hostname: "
set /p ports="Enter port range (e.g., 1-1000) or press Enter for common ports: "
if "%ports%"=="" (
    python port_scanner.py %target%
) else (
    python port_scanner.py %target% -p %ports%
)
echo.
pause
goto MENU

:SSL_MONITOR
cls
echo.
echo ========================================================================
echo                            SSL MONITOR
echo ========================================================================
echo.
set /p domain="Enter domain to check (e.g., example.com): "
python ssl_monitor.py %domain%
echo.
pause
goto MENU

:WEB_LOG_ANALYZER
cls
echo.
echo ========================================================================
echo                        WEB LOG ANALYZER
echo ========================================================================
echo.
set /p logfile="Enter path to web server log file: "
if exist "%logfile%" (
    python web_log_analyzer.py "%logfile%"
) else (
    echo ERROR: Log file not found!
    echo Please check the path and try again.
)
echo.
pause
goto MENU

REM ============================================================================
REM Windows System Tools
REM ============================================================================

:EVENT_LOG_MONITOR
cls
echo.
echo ========================================================================
echo                      WINDOWS EVENT LOG MONITOR
echo ========================================================================
echo.
echo Checking Windows Event Logs (requires administrator privileges)...
echo.
python ssh_monitor_windows.py
echo.
pause
goto MENU

:FILE_INTEGRITY
cls
echo.
echo ========================================================================
echo                     FILE INTEGRITY MONITOR
echo ========================================================================
echo.
echo 1. Create new baseline
echo 2. Check for changes
echo 3. Continuous monitoring
echo 4. Back to main menu
echo.
set /p fimchoice="Select option: "

if "%fimchoice%"=="1" (
    python fim_windows.py --create-baseline
) else if "%fimchoice%"=="2" (
    python fim_windows.py --check
) else if "%fimchoice%"=="3" (
    python fim_windows.py --monitor --interval 60
) else (
    goto MENU
)
echo.
pause
goto MENU

:PRIVILEGE_MONITOR
cls
echo.
echo ========================================================================
echo                    PRIVILEGE ESCALATION DETECTOR
echo ========================================================================
echo.
echo 1. Create new baseline
echo 2. Check for privilege changes
echo 3. Continuous monitoring
echo 4. Back to main menu
echo.
set /p pedchoice="Select option: "

if "%pedchoice%"=="1" (
    python ped_windows.py --create-baseline
) else if "%pedchoice%"=="2" (
    python ped_windows.py --check
) else if "%pedchoice%"=="3" (
    python ped_windows.py --monitor --interval 300
) else (
    goto MENU
)
echo.
pause
goto MENU

:PROCESS_MONITOR
cls
echo.
echo ========================================================================
echo              PROCESS AND NETWORK CONNECTION MONITOR
echo ========================================================================
echo.
echo 1. Create new baseline
echo 2. Check for anomalies
echo 3. Continuous monitoring
echo 4. Back to main menu
echo.
set /p pncmchoice="Select option: "

if "%pncmchoice%"=="1" (
    python pncm_windows.py --create-baseline
) else if "%pncmchoice%"=="2" (
    python pncm_windows.py --check
) else if "%pncmchoice%"=="3" (
    python pncm_windows.py --monitor --interval 60
) else (
    goto MENU
)
echo.
pause
goto MENU

REM ============================================================================
REM Utilities
REM ============================================================================

:RUN_ALL
cls
echo.
echo ========================================================================
echo                     RUNNING COMPREHENSIVE SCAN
echo ========================================================================
echo.
echo This will run a basic security check with all tools...
echo Please wait, this may take several minutes.
echo.
echo [1/7] Checking localhost ports...
python port_scanner.py 127.0.0.1 -p 1-1000
echo.
echo [2/7] Checking file integrity...
if exist fim_baseline.json (
    python fim_windows.py --check
) else (
    echo No baseline found, creating one...
    python fim_windows.py --create-baseline
)
echo.
echo [3/7] Checking for privilege escalation...
if exist ped_baseline.json (
    python ped_windows.py --check
) else (
    echo No baseline found, creating one...
    python ped_windows.py --create-baseline
)
echo.
echo [4/7] Checking processes and connections...
if exist pncm_baseline.json (
    python pncm_windows.py --check
) else (
    echo No baseline found, creating one...
    python pncm_windows.py --create-baseline
)
echo.
echo [5/7] Checking Windows Event Logs...
python ssh_monitor_windows.py --last-hours 24
echo.
echo ========================================================================
echo                      SCAN COMPLETE
echo ========================================================================
echo.
pause
goto MENU

:DOCUMENTATION
cls
echo.
echo ========================================================================
echo                          DOCUMENTATION
echo ========================================================================
echo.
echo Opening README files...
echo.
if exist README.md start notepad README.md
if exist WINDOWS_DEPLOYMENT_GUIDE.md start notepad WINDOWS_DEPLOYMENT_GUIDE.md
if exist COMPLETE_TOOLKIT_README.md start notepad COMPLETE_TOOLKIT_README.md
echo.
echo Documentation opened in Notepad.
echo.
pause
goto MENU

:CHECK_REQUIREMENTS
cls
echo.
echo ========================================================================
echo                     CHECKING REQUIREMENTS
echo ========================================================================
echo.
echo Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.6 or higher from python.org
    echo.
) else (
    echo.
    echo Python is installed correctly.
    echo.
    echo Checking for required Python modules...
    python -c "import sys, os, json, re, hashlib, datetime, pathlib" 2>nul
    if %errorlevel% neq 0 (
        echo ERROR: Some required modules are missing.
    ) else (
        echo All required modules are available.
    )
    echo.
    echo Checking for administrator privileges...
    net session >nul 2>&1
    if %errorlevel% neq 0 (
        echo WARNING: Not running as administrator.
        echo Some tools may require administrator privileges.
        echo Right-click and select "Run as administrator" for full functionality.
    ) else (
        echo Running with administrator privileges - OK
    )
)
echo.
echo ========================================================================
echo.
pause
goto MENU

:EXIT
cls
echo.
echo Thank you for using the Security Monitoring Toolkit!
echo.
timeout /t 2 >nul
exit

REM ============================================================================
REM Error Handling
REM ============================================================================

:ERROR
echo.
echo An error occurred. Please check your input and try again.
echo.
pause
goto MENU
