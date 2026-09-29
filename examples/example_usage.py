"""
Example programmatic usage of the Passive Security Scanner.
"""

import os
import sys
import json

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import run_scan


def main():
    target = "example.com"
    print(f"[*] Running passive security audit on: {target}")
    
    # Run audit in quiet mode
    scan_result = run_scan(target=target, quiet=True)
    
    print("\n[+] Audit Summary:")
    print(f"    Target:        {scan_result['target']}")
    print(f"    Overall Score: {scan_result['overall_score']}/100")
    print(f"    Overall Grade: {scan_result['overall_grade']}")
    
    print("\n[+] Module Scores:")
    for mod_name, mod_data in scan_result.get("modules", {}).items():
        print(f"    - {mod_name:10s}: {mod_data.get('score', 0)}/100 (Grade: {mod_data.get('grade', 'N/A')})")


if __name__ == "__main__":
    main()
