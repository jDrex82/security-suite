# Windows Security Monitoring Toolkit - Automated Deployment Script
# Version 2.0
# Deploys and configures the complete security monitoring suite for Windows

#Requires -RunAsAdministrator

param(
    [string]$InstallPath = "C:\SecurityTools",
    [string]$LogPath = "C:\SecurityTools\Logs",
    [switch]$CreateScheduledTasks,
    [switch]$InstallDependencies,
    [switch]$CreateBaselines,
    [switch]$TestInstallation,
    [switch]$UninstallScheduledTasks
)

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "✓ $Message" "Green"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "✗ $Message" "Red"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "⚠ $Message" "Yellow"
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput "ℹ $Message" "Cyan"
}

# Banner
Clear-Host
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    Windows Security Monitoring Toolkit - Deployment Script" -ForegroundColor Cyan
Write-Host "    Version 2.0" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator!"
    Write-Info "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Write-Success "Running with Administrator privileges"
Write-Host ""

# Create directories
Write-Info "Creating directories..."
try {
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        Write-Success "Created installation directory: $InstallPath"
    } else {
        Write-Info "Installation directory already exists: $InstallPath"
    }
    
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Success "Created log directory: $LogPath"
    } else {
        Write-Info "Log directory already exists: $LogPath"
    }
    
    # Create subdirectories for logs
    $logSubdirs = @("fim", "ped", "pncm", "events")
    foreach ($subdir in $logSubdirs) {
        $path = Join-Path $LogPath $subdir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    Write-Success "Created log subdirectories"
} catch {
    Write-Error "Failed to create directories: $_"
    exit 1
}

Write-Host ""

# Check Python installation
Write-Info "Checking Python installation..."
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        if ($major -ge 3 -and $minor -ge 6) {
            Write-Success "Python $pythonVersion is installed"
        } else {
            Write-Error "Python version must be 3.6 or higher (found: $pythonVersion)"
            Write-Info "Download from: https://www.python.org/downloads/"
            exit 1
        }
    }
} catch {
    Write-Error "Python is not installed or not in PATH"
    Write-Info "Download from: https://www.python.org/downloads/"
    Write-Info "Make sure to check 'Add Python to PATH' during installation"
    exit 1
}

Write-Host ""

# Install Python dependencies
if ($InstallDependencies) {
    Write-Info "Installing Python dependencies..."
    
    $dependencies = @("pywin32", "wmi")
    foreach ($dep in $dependencies) {
        try {
            Write-Info "Installing $dep..."
            $result = pip install $dep 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Installed $dep"
            } else {
                Write-Warning "Failed to install $dep (may already be installed)"
            }
        } catch {
            Write-Warning "Error installing $dep: $_"
        }
    }
    
    # Run pywin32 post-install if needed
    try {
        Write-Info "Running pywin32 post-install script..."
        python -c "import win32api" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $pythonScripts = (python -c "import sys; print(sys.prefix + '\\Scripts')")
            if (Test-Path "$pythonScripts\pywin32_postinstall.py") {
                python "$pythonScripts\pywin32_postinstall.py" -install
                Write-Success "Completed pywin32 post-install"
            }
        } else {
            Write-Success "pywin32 is working correctly"
        }
    } catch {
        Write-Warning "Could not run pywin32 post-install: $_"
    }
    
    Write-Host ""
}

# Copy files (if in current directory)
Write-Info "Checking for toolkit files in current directory..."
$toolFiles = @(
    "security_suite_launcher.bat",
    "ssh_monitor_windows.py",
    "fim_windows.py", 
    "ped_windows.py",
    "pncm_windows.py",
    "WINDOWS_DEPLOYMENT_GUIDE.md",
    "README.md"
)

$foundFiles = 0
foreach ($file in $toolFiles) {
    if (Test-Path $file) {
        $foundFiles++
        if ($InstallPath -ne (Get-Location).Path) {
            Copy-Item $file $InstallPath -Force
            Write-Success "Copied $file to $InstallPath"
        }
    }
}

if ($foundFiles -gt 0) {
    Write-Success "Found and processed $foundFiles toolkit files"
} else {
    Write-Warning "No toolkit files found in current directory"
    Write-Info "Make sure to extract all files to $InstallPath"
}

Write-Host ""

# Create baselines
if ($CreateBaselines) {
    Write-Info "Creating security baselines..."
    Write-Warning "This may take several minutes..."
    Write-Host ""
    
    $baselineTools = @(
        @{Name="File Integrity Monitor"; Script="fim_windows.py"},
        @{Name="Privilege Escalation Detector"; Script="ped_windows.py"},
        @{Name="Process & Network Monitor"; Script="pncm_windows.py"}
    )
    
    foreach ($tool in $baselineTools) {
        Write-Info "Creating baseline for $($tool.Name)..."
        $scriptPath = Join-Path $InstallPath $tool.Script
        if (Test-Path $scriptPath) {
            try {
                $result = python $scriptPath --create-baseline 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Created baseline for $($tool.Name)"
                } else {
                    Write-Error "Failed to create baseline for $($tool.Name)"
                    Write-Host $result
                }
            } catch {
                Write-Error "Error creating baseline for $($tool.Name): $_"
            }
        } else {
            Write-Warning "Script not found: $scriptPath"
        }
        Write-Host ""
    }
}

# Create scheduled tasks
if ($CreateScheduledTasks) {
    Write-Info "Creating scheduled tasks for automated monitoring..."
    Write-Host ""
    
    $tasks = @(
        @{
            Name = "Security-FIM-Daily"
            Description = "File Integrity Monitor - Daily Check"
            Script = "fim_windows.py"
            Arguments = "--check --export `"$LogPath\fim\fim-`$(Get-Date -Format 'yyyyMMdd-HHmmss').json`""
            Trigger = "Daily"
            Time = "02:00"
        },
        @{
            Name = "Security-PED-Daily"
            Description = "Privilege Escalation Detector - Daily Check"
            Script = "ped_windows.py"
            Arguments = "--check --export `"$LogPath\ped\ped-`$(Get-Date -Format 'yyyyMMdd-HHmmss').json`""
            Trigger = "Daily"
            Time = "03:00"
        },
        @{
            Name = "Security-PNCM-4Hours"
            Description = "Process & Network Monitor - Every 4 Hours"
            Script = "pncm_windows.py"
            Arguments = "--check --export `"$LogPath\pncm\pncm-`$(Get-Date -Format 'yyyyMMdd-HHmmss').json`""
            Trigger = "Hourly"
            Hours = 4
        },
        @{
            Name = "Security-EventLog-6Hours"
            Description = "Windows Event Log Monitor - Every 6 Hours"
            Script = "ssh_monitor_windows.py"
            Arguments = "--last-hours 6 --export `"$LogPath\events\events-`$(Get-Date -Format 'yyyyMMdd-HHmmss').json`""
            Trigger = "Hourly"
            Hours = 6
        }
    )
    
    foreach ($task in $tasks) {
        try {
            # Check if task already exists
            $existingTask = Get-ScheduledTask -TaskName $task.Name -ErrorAction SilentlyContinue
            if ($existingTask) {
                Write-Warning "Task '$($task.Name)' already exists - skipping"
                continue
            }
            
            $scriptPath = Join-Path $InstallPath $task.Script
            $pythonExe = (Get-Command python).Source
            
            $Action = New-ScheduledTaskAction -Execute $pythonExe `
                -Argument "`"$scriptPath`" $($task.Arguments)" `
                -WorkingDirectory $InstallPath
            
            if ($task.Trigger -eq "Daily") {
                $Trigger = New-ScheduledTaskTrigger -Daily -At $task.Time
            } else {
                $Trigger = New-ScheduledTaskTrigger -Once -At "00:00" `
                    -RepetitionInterval (New-TimeSpan -Hours $task.Hours) `
                    -RepetitionDuration ([TimeSpan]::MaxValue)
            }
            
            $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
                -LogonType ServiceAccount -RunLevel Highest
            
            $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            Register-ScheduledTask -TaskName $task.Name `
                -Action $Action `
                -Trigger $Trigger `
                -Principal $Principal `
                -Settings $Settings `
                -Description $task.Description | Out-Null
            
            Write-Success "Created scheduled task: $($task.Name)"
        } catch {
            Write-Error "Failed to create task '$($task.Name)': $_"
        }
    }
    
    Write-Host ""
    Write-Success "Scheduled tasks created successfully"
    Write-Info "View tasks in Task Scheduler: taskschd.msc"
}

# Uninstall scheduled tasks
if ($UninstallScheduledTasks) {
    Write-Info "Removing scheduled tasks..."
    
    $taskNames = @(
        "Security-FIM-Daily",
        "Security-PED-Daily",
        "Security-PNCM-4Hours",
        "Security-EventLog-6Hours"
    )
    
    foreach ($taskName in $taskNames) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Success "Removed task: $taskName"
            } else {
                Write-Info "Task not found: $taskName"
            }
        } catch {
            Write-Error "Failed to remove task '$taskName': $_"
        }
    }
    
    Write-Host ""
}

# Test installation
if ($TestInstallation) {
    Write-Info "Testing installation..."
    Write-Host ""
    
    $tests = @(
        @{Name="Python"; Command="python --version"},
        @{Name="FIM Script"; Test="Test-Path (Join-Path $InstallPath 'fim_windows.py')"},
        @{Name="PED Script"; Test="Test-Path (Join-Path $InstallPath 'ped_windows.py')"},
        @{Name="PNCM Script"; Test="Test-Path (Join-Path $InstallPath 'pncm_windows.py')"},
        @{Name="Event Log Monitor Script"; Test="Test-Path (Join-Path $InstallPath 'ssh_monitor_windows.py')"},
        @{Name="Launcher Script"; Test="Test-Path (Join-Path $InstallPath 'security_suite_launcher.bat')"}
    )
    
    $passed = 0
    $failed = 0
    
    foreach ($test in $tests) {
        try {
            if ($test.Command) {
                $result = Invoke-Expression $test.Command 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "$($test.Name): OK"
                    $passed++
                } else {
                    Write-Error "$($test.Name): FAILED"
                    $failed++
                }
            } elseif ($test.Test) {
                if (Invoke-Expression $test.Test) {
                    Write-Success "$($test.Name): OK"
                    $passed++
                } else {
                    Write-Error "$($test.Name): FAILED"
                    $failed++
                }
            }
        } catch {
            Write-Error "$($test.Name): FAILED - $_"
            $failed++
        }
    }
    
    Write-Host ""
    Write-Info "Test Results: $passed passed, $failed failed"
    
    if ($failed -eq 0) {
        Write-Success "All tests passed!"
    } else {
        Write-Warning "Some tests failed. Please review the errors above."
    }
}

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                    DEPLOYMENT SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Info "Installation Path: $InstallPath"
Write-Info "Log Path: $LogPath"
Write-Host ""

Write-ColorOutput "Next Steps:" "Yellow"
Write-Host "1. Review the README.md file in $InstallPath"
Write-Host "2. Run the launcher: $InstallPath\security_suite_launcher.bat"
Write-Host "3. Or use individual tools with Python"
Write-Host "4. Check scheduled tasks in Task Scheduler (taskschd.msc)"
Write-Host ""

Write-ColorOutput "Quick Start Commands:" "Yellow"
Write-Host "cd $InstallPath"
Write-Host "python fim_windows.py --create-baseline"
Write-Host "python fim_windows.py --check"
Write-Host "python ssh_monitor_windows.py --last-hours 24"
Write-Host ""

Write-Success "Deployment completed successfully!"
Write-Host ""
