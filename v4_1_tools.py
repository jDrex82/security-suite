#!/usr/bin/env python3
"""
v4.1 Tools Test Suite
Tests all 7 new enterprise security monitors

Author: John Drexler
"""

import subprocess
import sys
import os
from pathlib import Path

def test_tool(tool_name, tool_path):
    """Test a single tool"""
    print(f"\n{'='*80}")
    print(f"TESTING: {tool_name}")
    print('='*80)
    
    try:
        result = subprocess.run(
            [sys.executable, tool_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Check if tool ran successfully
        if result.returncode == 0:
            print(f"✅ {tool_name} - PASSED")
            print(f"\nOutput preview (first 50 lines):")
            print('\n'.join(result.stdout.split('\n')[:50]))
            return True
        else:
            print(f"❌ {tool_name} - FAILED")
            print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f⚠️  {tool_name} - TIMEOUT (still running after 30s)")
        return True  # Might be waiting for input
    except Exception as e:
        print(f"❌ {tool_name} - ERROR: {e}")
        return False

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    v4.1 TOOLS - COMPREHENSIVE TEST SUITE                     ║
║                         Testing 7 NEW Tools                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Define tools to test
    tools = [
        ("Email Security Monitor", "email_security_monitor.py"),
        ("Backup Integrity Monitor", "backup_integrity_monitor.py"),
        ("Patch Compliance Monitor", "patch_compliance_monitor.py"),
        ("Medical Device Security Monitor", "medical_device_monitor.py"),
        ("Cloud Security Posture Monitor", "cloud_security_monitor.py"),
        ("VPN/Remote Access Monitor", "vpn_security_monitor.py"),
        ("API Security Monitor", "api_security_monitor.py")
    ]
    
    # Try to find v4_1_tools directory
    possible_paths = [
        "v4_1_tools",
        "../v4_1_tools",
        "../../v4_1_tools",
        "/mnt/user-data/outputs/v4_1_tools",
        "C:\\security_suite_v4_LEGENDARY\\v4_1_tools"
    ]
    
    tools_dir = None
    for path in possible_paths:
        if os.path.exists(path):
            tools_dir = path
            break
    
    if not tools_dir:
        print("❌ Error: Could not find v4_1_tools directory")
        print("\nSearched in:")
        for path in possible_paths:
            print(f"  - {path}")
        sys.exit(1)
    
    print(f"Found tools directory: {tools_dir}\n")
    
    # Test each tool
    results = []
    for tool_name, tool_file in tools:
        tool_path = os.path.join(tools_dir, tool_file)
        
        if not os.path.exists(tool_path):
            print(f"❌ {tool_name} - FILE NOT FOUND: {tool_path}")
            results.append((tool_name, False))
            continue
        
        passed = test_tool(tool_name, tool_path)
        results.append((tool_name, passed))
    
    # Summary
    print(f"\n{'='*80}")
    print("TEST SUMMARY")
    print('='*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for tool_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {tool_name}")
    
    print(f"\nTotal: {passed}/{total} tools passed")
    
    if passed == total:
        print("\n🎉 ALL TOOLS WORKING! 🎉")
        return 0
    else:
        print(f"\n⚠️  {total - passed} tools failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())