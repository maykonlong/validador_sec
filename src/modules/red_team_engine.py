import subprocess
import shutil
import os
import time
from typing import Dict, Any

class RedTeamEngine:
    """
    Red Team Operations Engine
    Handles invasive tools: SQLMap, Hydra, Metasploit.
    REQUIRES 'allow_invasive' flag to operate.
    """
    
    def __init__(self, target: str, options: Dict[str, Any] = None):
        self.target = target
        self.options = options or {}
        self.allow_invasive = self.options.get('allow_invasive', False)
        
    def _check_permission(self):
        if not self.allow_invasive:
            raise PermissionError("Red Team module requires 'allow_invasive=True' option.")

    def run_sqlmap(self, url: str) -> Dict[str, Any]:
        """
        Runs SQLMap against a specific URL.
        """
        self._check_permission()
        
        if not shutil.which("sqlmap"):
            # Check for python script version
            # Assuming sqlmap.py might be in path or known location
            return {"error": "SQLMap not found in PATH."}
            
        print(f"[*] [RED TEAM] Launching SQLMap against {url}...")
        
        # batch: never ask for user input
        # random-agent: use random user-agent
        # dbs: enumerate databases if found
        cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--dbs"]
        
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            vulnerable = "Parameter: " in process.stdout
            
            return {
                "tool": "SQLMap",
                "vulnerable": vulnerable,
                "output_snippet": process.stdout[-1000:] if process.stdout else ""
            }
        except subprocess.TimeoutExpired:
            return {"error": "SQLMap timed out."}

    def run_hydra(self, service: str, user_list: str, pass_list: str) -> Dict[str, Any]:
        """
        Runs Hydra brute-force against a service (ssh, ftp, etc).
        """
        self._check_permission()
        
        if not shutil.which("hydra"):
            return {"error": "Hydra not found."}
            
        # hydra -L users.txt -P pass.txt target service
        cmd = ["hydra", "-L", user_list, "-P", pass_list, self.target, service]
        
        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            success_lines = [line for line in process.stdout.split('\n') if "login:" in line]
            
            return {
                "tool": "Hydra",
                "success": len(success_lines) > 0,
                "credentials": success_lines
            }
        except Exception as e:
            return {"error": str(e)}

    def run_metasploit_db_check(self) -> Dict[str, Any]:
        """
        Checks if Metasploit RPC is reachable or runs a basic resource script via msfconsole.
        """
        self._check_permission()
        
        if not shutil.which("msfconsole"):
             return {"error": "Metasploit (msfconsole) not found."}
             
        # Just a health check or version check for now
        # msfconsole -v
        try:
            cmd = ["msfconsole", "-v"]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {
                "tool": "Metasploit",
                "version_info": process.stdout
            }
        except Exception as e:
            return {"error": str(e)}

    def run_all_red_team(self):
        """
        Orchestrates all Red Team attacks.
        Currently focused on SQLMap if a URL is provided, and basic checks.
        """
        results = {}
        try:
            # If target is a URL, try SQLMap
            if self.target.startswith("http"):
                 # Normally we would crawl for params first, but here we assume target is a candidate
                 results["sqlmap"] = self.run_sqlmap(self.target)
                 
            # Metasploit check
            results["metasploit"] = self.run_metasploit_db_check()
            
            return results
        except PermissionError:
            return {"error": "Invasive mode not enabled."}
