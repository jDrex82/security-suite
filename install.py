#!/usr/bin/env python3
"""
Security Suite - Automated Installer
Installs and configures all 29 security tools (26 v4.1 + 3 v5.0 ML)

Usage:
    sudo python3 install.py
    
    OR with options:
    sudo python3 install.py --install-dir /opt/security_suite --log-dir /var/log/security_suite

Author: John Drexler
"""

import os
import sys
import shutil
import subprocess
import json
from pathlib import Path
from datetime import datetime

class SecuritySuiteInstaller:
    """Automated installer for Security Suite"""
    
    def __init__(self, install_dir="/opt/security_suite", log_dir="/var/log/security_suite", 
                 data_dir="/var/lib/security_suite"):
        self.install_dir = Path(install_dir)
        self.log_dir = Path(log_dir)
        self.data_dir = Path(data_dir)
        self.config_dir = self.install_dir / "config"
        self.tools_installed = []
        self.errors = []
        
    def print_banner(self):
        """Print installation banner"""
        print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                 SECURITY SUITE - AUTOMATED INSTALLER                         ║
║                  Healthcare Security Monitoring Platform                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Installing 29 security tools:
  • 26 Traditional Security Monitors (v4.1)
  • 3 ML-Powered Anomaly Detectors (v5.0)

Installation directories:
  • Tools:   {self.install_dir}
  • Logs:    {self.log_dir}
  • Data:    {self.data_dir}
  • Config:  {self.config_dir}

""".format(self=self))
    
    def check_permissions(self):
        """Verify running as root/admin"""
        print("[*] Checking permissions...")
        
        if os.geteuid() != 0:
            print("[!] ERROR: This installer must be run as root (use sudo)")
            print("    Run: sudo python3 install.py")
            return False
        
        print("[+] Running with root privileges")
        return True
    
    def check_python_version(self):
        """Check Python version"""
        print("[*] Checking Python version...")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"[!] ERROR: Python 3.8+ required (found {version.major}.{version.minor})")
            return False
        
        print(f"[+] Python {version.major}.{version.minor}.{version.micro} OK")
        return True
    
    def create_directories(self):
        """Create installation directories"""
        print("[*] Creating directories...")
        
        directories = [
            self.install_dir,
            self.install_dir / "v4_1_tools",
            self.install_dir / "v5_ml_engine",
            self.config_dir,
            self.log_dir,
            self.data_dir,
            self.data_dir / "models",
            self.data_dir / "reports",
            self.data_dir / "pcap",
            self.data_dir / "netflow",
        ]
        
        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                print(f"    [+] Created: {directory}")
            except Exception as e:
                print(f"    [!] Failed to create {directory}: {e}")
                self.errors.append(f"Directory creation failed: {directory}")
                return False
        
        return True
    
    def copy_tools(self):
        """Copy all tool files to installation directory"""
        print("[*] Copying tool files...")
        
        # Get current script directory (repo root)
        repo_root = Path(__file__).parent.absolute()
        
        # Copy v4.1 tools
        v41_source = repo_root / "v4_1_tools"
        v41_dest = self.install_dir / "v4_1_tools"
        
        if v41_source.exists():
            print("    [*] Copying v4.1 tools...")
            try:
                for tool_file in v41_source.glob("*.py"):
                    shutil.copy2(tool_file, v41_dest)
                    print(f"        [+] {tool_file.name}")
                    self.tools_installed.append(tool_file.name)
            except Exception as e:
                print(f"    [!] Error copying v4.1 tools: {e}")
                self.errors.append(f"v4.1 copy failed: {e}")
                return False
        else:
            print(f"    [!] WARNING: v4.1 tools not found at {v41_source}")
        
        # Copy v5.0 ML tools
        v5_source = repo_root / "v5_ml_engine"
        v5_dest = self.install_dir / "v5_ml_engine"
        
        if v5_source.exists():
            print("    [*] Copying v5.0 ML tools...")
            try:
                for tool_file in v5_source.glob("*.py"):
                    shutil.copy2(tool_file, v5_dest)
                    print(f"        [+] {tool_file.name}")
                    self.tools_installed.append(tool_file.name)
                
                # Copy README if exists
                readme = v5_source / "README.md"
                if readme.exists():
                    shutil.copy2(readme, v5_dest)
                    print(f"        [+] README.md")
                    
            except Exception as e:
                print(f"    [!] Error copying v5.0 tools: {e}")
                self.errors.append(f"v5.0 copy failed: {e}")
                return False
        else:
            print(f"    [!] WARNING: v5.0 ML tools not found at {v5_source}")
        
        print(f"[+] Copied {len(self.tools_installed)} tool files")
        return True
    
    def set_permissions(self):
        """Set proper file permissions"""
        print("[*] Setting file permissions...")
        
        try:
            # Make all Python scripts executable
            for py_file in self.install_dir.rglob("*.py"):
                py_file.chmod(0o755)
                
            # Set directory permissions
            os.chmod(self.install_dir, 0o755)
            os.chmod(self.log_dir, 0o777)  # Allow all users to write logs
            os.chmod(self.data_dir, 0o777)  # Allow all users to write data
            
            # Make subdirectories writable too
            for subdir in self.data_dir.rglob("*"):
                if subdir.is_dir():
                    os.chmod(subdir, 0o777)
            
            print("[+] Permissions set")
            return True
            
        except Exception as e:
            print(f"[!] Error setting permissions: {e}")
            self.errors.append(f"Permission setting failed: {e}")
            return False
    
    def create_config_file(self):
        """Create default configuration file"""
        print("[*] Creating configuration file...")
        
        config = {
            "version": "5.0",
            "installation": {
                "date": datetime.now().isoformat(),
                "install_dir": str(self.install_dir),
                "log_dir": str(self.log_dir),
                "data_dir": str(self.data_dir)
            },
            "alerting": {
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.hospital.local",
                    "smtp_port": 25,
                    "from": "security-suite@hospital.local",
                    "to": ["security@hospital.local"]
                },
                "syslog": {
                    "enabled": False,
                    "server": "192.168.1.50",
                    "port": 514,
                    "protocol": "udp"
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#security-alerts"
                }
            },
            "ml_settings": {
                "baseline_days": 7,
                "model_retrain_interval_days": 7,
                "anomaly_threshold": 0.45
            },
            "tools": {
                "v4_1_enabled": True,
                "v5_ml_enabled": True
            }
        }
        
        config_file = self.config_dir / "config.json"
        
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"[+] Configuration created: {config_file}")
            print("    [*] Edit this file to customize settings")
            return True
            
        except Exception as e:
            print(f"[!] Error creating config: {e}")
            self.errors.append(f"Config creation failed: {e}")
            return False
    
    def create_launcher_scripts(self):
        """Create convenience launcher scripts"""
        print("[*] Creating launcher scripts...")
        
        # Master launcher
        launcher_content = f"""#!/bin/bash
# Security Suite - Master Launcher
# Runs all security tools

INSTALL_DIR="{self.install_dir}"
LOG_DIR="{self.log_dir}"
DATA_DIR="{self.data_dir}"
REPORTS_DIR="$DATA_DIR/reports"

echo "========================================"
echo "  Security Suite - Running All Tools"
echo "========================================"
echo ""

# Ensure directories are writable
chmod 777 "$LOG_DIR" 2>/dev/null || true
chmod 777 "$DATA_DIR" 2>/dev/null || true
chmod 777 "$REPORTS_DIR" 2>/dev/null || true

# Change to reports directory so JSON files go here
cd "$REPORTS_DIR" || exit 1

# Run v4.1 tools
echo "[*] Running v4.1 traditional security monitors..."
for tool in "$INSTALL_DIR"/v4_1_tools/*.py; do
    echo "  [*] Running $(basename $tool)..."
    python3 "$tool" >> "$LOG_DIR/v4_1.log" 2>&1
done

# Run v5.0 ML tools
echo "[*] Running v5.0 ML anomaly detectors..."
for tool in "$INSTALL_DIR"/v5_ml_engine/*_ml.py; do
    echo "  [*] Running $(basename $tool)..."
    python3 "$tool" >> "$LOG_DIR/v5_ml.log" 2>&1
done

echo ""
echo "[+] All tools completed"
echo "[*] Check logs: $LOG_DIR"
echo "[*] Check reports: $REPORTS_DIR"
echo ""
echo "Latest reports:"
ls -lht "$REPORTS_DIR"/*.json 2>/dev/null | head -5 || echo "  No reports yet"
"""
        
        launcher_file = self.install_dir / "run_all_tools.sh"
        
        try:
            with open(launcher_file, 'w') as f:
                f.write(launcher_content)
            
            launcher_file.chmod(0o755)
            print(f"[+] Created: {launcher_file}")
            
            # Create symlink in /usr/local/bin
            symlink = Path("/usr/local/bin/security-suite")
            if symlink.exists():
                symlink.unlink()
            symlink.symlink_to(launcher_file)
            print(f"[+] Created symlink: {symlink}")
            print("    [*] You can now run: security-suite")
            
            return True
            
        except Exception as e:
            print(f"[!] Error creating launcher: {e}")
            self.errors.append(f"Launcher creation failed: {e}")
            return False
    
    def create_status_script(self):
        """Create status check script"""
        print("[*] Creating status check script...")
        
        status_content = f"""#!/usr/bin/env python3
# Security Suite - Status Check

import os
import json
from pathlib import Path
from datetime import datetime

install_dir = Path("{self.install_dir}")
log_dir = Path("{self.log_dir}")
data_dir = Path("{self.data_dir}")

print("=" * 80)
print("SECURITY SUITE - STATUS")
print("=" * 80)

# Check installation
if install_dir.exists():
    print(f"✓ Installation: {{install_dir}}")
else:
    print(f"✗ Installation NOT FOUND: {{install_dir}}")

# Count tools
v41_tools = list((install_dir / "v4_1_tools").glob("*.py")) if (install_dir / "v4_1_tools").exists() else []
v5_tools = list((install_dir / "v5_ml_engine").glob("*_ml.py")) if (install_dir / "v5_ml_engine").exists() else []

print(f"\\nTools Installed:")
print(f"  v4.1 Traditional: {{len(v41_tools)}} tools")
print(f"  v5.0 ML:          {{len(v5_tools)}} tools")
print(f"  TOTAL:            {{len(v41_tools) + len(v5_tools)}} tools")

# Check logs
print(f"\\nLog Directory: {{log_dir}}")
if log_dir.exists():
    logs = list(log_dir.glob("*.log"))
    print(f"  Log files: {{len(logs)}}")
    for log in logs[-5:]:  # Show last 5
        size = log.stat().st_size
        print(f"    - {{log.name}} ({{size:,}} bytes)")
else:
    print("  ✗ Log directory not found")

# Check data
print(f"\\nData Directory: {{data_dir}}")
if data_dir.exists():
    reports = list((data_dir / "reports").glob("*.json")) if (data_dir / "reports").exists() else []
    models = list((data_dir / "models").glob("*")) if (data_dir / "models").exists() else []
    print(f"  Reports: {{len(reports)}}")
    print(f"  ML Models: {{len(models)}}")
else:
    print("  ✗ Data directory not found")

# Check config
config_file = install_dir / "config" / "config.json"
print(f"\\nConfiguration: {{config_file}}")
if config_file.exists():
    with open(config_file) as f:
        config = json.load(f)
    print(f"  Version: {{config.get('version', 'unknown')}}")
    print(f"  Email alerts: {{'enabled' if config.get('alerting', {{}}).get('email', {{}}).get('enabled') else 'disabled'}}")
    print(f"  Syslog: {{'enabled' if config.get('alerting', {{}}).get('syslog', {{}}).get('enabled') else 'disabled'}}")
else:
    print("  ✗ Configuration not found")

print("\\n" + "=" * 80)
"""
        
        status_file = self.install_dir / "status.py"
        
        try:
            with open(status_file, 'w') as f:
                f.write(status_content)
            
            status_file.chmod(0o755)
            print(f"[+] Created: {status_file}")
            print("    [*] Run: security-suite-status")
            
            # Create symlink
            symlink = Path("/usr/local/bin/security-suite-status")
            if symlink.exists():
                symlink.unlink()
            symlink.symlink_to(status_file)
            
            return True
            
        except Exception as e:
            print(f"[!] Error creating status script: {e}")
            self.errors.append(f"Status script failed: {e}")
            return False
    
    def print_summary(self):
        """Print installation summary"""
        print("\n" + "=" * 80)
        print("INSTALLATION COMPLETE")
        print("=" * 80)
        
        if self.errors:
            print("\n⚠️  WARNINGS/ERRORS:")
            for error in self.errors:
                print(f"  • {error}")
            print()
        
        print(f"\n✓ Tools installed: {len(self.tools_installed)}")
        print(f"✓ Installation directory: {self.install_dir}")
        print(f"✓ Log directory: {self.log_dir}")
        print(f"✓ Data directory: {self.data_dir}")
        
        print("\n📋 NEXT STEPS:")
        print("  1. Review configuration: {}/config/config.json".format(self.install_dir))
        print("  2. Edit alerting settings (email, Slack, syslog)")
        print("  3. Check status: security-suite-status")
        print("  4. Run all tools: security-suite")
        
        print("\n📖 USAGE:")
        print("  • Run all tools:        security-suite")
        print("  • Check status:         security-suite-status")
        print("  • View logs:            tail -f {}/v4_1.log".format(self.log_dir))
        print("  • View ML logs:         tail -f {}/v5_ml.log".format(self.log_dir))
        
        print("\n🔧 CONFIGURATION:")
        print("  • Main config:          {}/config/config.json".format(self.install_dir))
        print("  • Enable email alerts:  Edit config file")
        print("  • Enable syslog:        Edit config file")
        
        print("\n📂 DIRECTORIES:")
        print("  • v4.1 tools:           {}/v4_1_tools/".format(self.install_dir))
        print("  • v5.0 ML tools:        {}/v5_ml_engine/".format(self.install_dir))
        print("  • Reports:              {}/reports/".format(self.data_dir))
        print("  • ML models:            {}/models/".format(self.data_dir))
        
        print("\n" + "=" * 80)
        print("Security Suite v5.0 - Ready for deployment")
        print("=" * 80)
        print()
    
    def install(self):
        """Run full installation"""
        self.print_banner()
        
        steps = [
            ("Checking permissions", self.check_permissions),
            ("Checking Python version", self.check_python_version),
            ("Creating directories", self.create_directories),
            ("Copying tools", self.copy_tools),
            ("Setting permissions", self.set_permissions),
            ("Creating configuration", self.create_config_file),
            ("Creating launcher scripts", self.create_launcher_scripts),
            ("Creating status script", self.create_status_script),
        ]
        
        for step_name, step_func in steps:
            if not step_func():
                print(f"\n[✗] Installation failed at: {step_name}")
                print(f"[!] See errors above for details")
                return False
        
        self.print_summary()
        return True


def main():
    """Main installer entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Suite Installer")
    parser.add_argument("--install-dir", default="/opt/security_suite",
                       help="Installation directory (default: /opt/security_suite)")
    parser.add_argument("--log-dir", default="/var/log/security_suite",
                       help="Log directory (default: /var/log/security_suite)")
    parser.add_argument("--data-dir", default="/var/lib/security_suite",
                       help="Data directory (default: /var/lib/security_suite)")
    
    args = parser.parse_args()
    
    installer = SecuritySuiteInstaller(
        install_dir=args.install_dir,
        log_dir=args.log_dir,
        data_dir=args.data_dir
    )
    
    success = installer.install()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()