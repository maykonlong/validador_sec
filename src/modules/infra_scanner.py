import shutil
import subprocess
import os
import json
import logging
from typing import Dict, Any

class InfraScanner:
    """
    Infrastructure Scanner Engine
    Integrates Nmap and Masscan for active scanning.
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        self.target = target
        self.options = options or {}
        
    def _get_nmap_path(self):
        # Check PATH first
        if shutil.which("nmap"):
            return "nmap"
        # Common Windows Paths
        paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def run_nmap_scan(self, scan_type="standard") -> Dict[str, Any]:
        """
        Runs Nmap scan.
        types: 'standard' (Top 1000), 'full' (All ports), 'vuln' (Script vuln)
        """
        nmap_bin = self._get_nmap_path()
        if not nmap_bin:
            return {"error": "Nmap binary not found. Please install Nmap."}

        # Base arguments
        # -oX output.xml for easy parsing (using python-nmap or manual)
        # We will retrieve XML output to stdout by using -oX -
        
        args = [nmap_bin, self.target, "-oX", "-"]
        
        if scan_type == "quick":
            args.extend(["-F", "-T4"]) # Fast scan, top 100 ports
        elif scan_type == "full":
            args.extend(["-p-", "-T4"]) # All ports
        elif scan_type == "vuln":
            args.extend(["-sV", "--script", "vuln", "-T3"]) # Service detection + vuln scripts
        else:
            args.extend(["-sV", "--top-ports", "1000"]) # Standard service det
            
        print(f"[*] Running Nmap ({scan_type}) on {self.target}...")
        
        try:
            process = subprocess.run(args, capture_output=True, text=True, timeout=1200) # 20 mins max
            
            if process.returncode != 0:
                return {
                    "tool": "Nmap",
                    "error": process.stderr or "Unknown Nmap Error"
                }

            # Basic XML parsing to dict (simplified)
            # In a real heavy app we would use python-nmap lib, but for zero-dep we can try to parse or just return raw
            # For this context, let's return a simplified summary + raw xml
            
            return {
                "tool": "Nmap",
                "scan_type": scan_type,
                "raw_xml": process.stdout[:5000] + "... (truncated)" if len(process.stdout) > 5000 else process.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Nmap scan timed out."}
        except Exception as e:
            return {"error": str(e)}

    def run_masscan(self, ports="0-65535", rate="1000") -> Dict[str, Any]:
        """
        Wrapper for Masscan (High speed scanner).
        Warning: Masscan on Windows is finicky.
        """
        if not shutil.which("masscan"):
             return {"error": "Masscan not found."}
             
        try:
             # masscan target -p0-65535 --rate 1000
             # require admin privileges usually
             cmd = ["masscan", self.target, f"-p{ports}", "--rate", rate]
             process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
             return {
                 "tool": "Masscan",
                 "output": process.stdout
             }
        except Exception as e:
            return {"error": str(e)}
