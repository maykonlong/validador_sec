import subprocess
import json
import os
import shutil

class ArsenalEngine:
    """
    Advanced Security Engine that integrates external industry-standard tools.
    Handles Nuclei, Subfinder, FFuF and more.
    """
    
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.results = []
        # Pasta de binários local
        self.local_bin = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "wins")
        
    def _is_tool_available(self, name):
        """Checks if a command-line tool is available in the system PATH or local bin folder."""
        if shutil.which(name):
            return True
        # Check local bin
        local_exe = os.path.join(self.local_bin, f"{name}.exe")
        return os.path.exists(local_exe)

    def _get_tool_cmd(self, name):
        """Returns the command to run the tool, prioritizing global PATH then local bin."""
        if shutil.which(name):
            return name
        return os.path.join(self.local_bin, f"{name}.exe")

    def run_nuclei(self):
        """
        Runs OWASP Nuclei with community templates.
        Focuses on Critical/High vulnerabilities.
        """
        if not self._is_tool_available("nuclei"):
            return {"error": "Nuclei not found in PATH", "status": "Not Installed"}
            
        try:
            # We use -json for easy parsing
            # Using -severity critical,high to keep it focused
            nuclei_cmd = self._get_tool_cmd("nuclei")
            cmd = [nuclei_cmd, "-u", self.target, "-severity", "critical,high,medium", "-json-export", "nuclei_results.json"]
            
            # For this implementation, we'll try to get the output from stdout if possible or read the file
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Nuclei outputs one JSON object per line to stdout usually if -json is used
            # But let's check if we can parse it
            lines = process.stdout.strip().split('\n')
            parsed_results = []
            for line in lines:
                if line.strip():
                    try:
                        parsed_results.append(json.loads(line))
                    except:
                        continue
            
            return {
                "tool": "Nuclei",
                "results": parsed_results,
                "raw": process.stdout
            }
        except Exception as e:
            return {"error": str(e), "tool": "Nuclei"}

    def run_subfinder(self):
        """Runs ProjectDiscovery Subfinder for fast subdomain discovery."""
        if not self._is_tool_available("subfinder"):
            return {"error": "Subfinder not found in PATH"}
            
        try:
            subfinder_cmd = self._get_tool_cmd("subfinder")
            cmd = [subfinder_cmd, "-d", self.target, "-silent"]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            subdomains = process.stdout.strip().split('\n')
            return {
                "tool": "Subfinder",
                "results": [s for s in subdomains if s],
                "count": len(subdomains)
            }
        except Exception as e:
            return {"error": str(e), "tool": "Subfinder"}

    def run_ffuf(self, wordlist_path):
        """Runs FFuF for ultra-fast directory fuzzing."""
        if not self._is_tool_available("ffuf"):
            return {"error": "FFuF not found in PATH"}
            
        try:
            # Basic FFuF command
            ffuf_cmd = self._get_tool_cmd("ffuf")
            cmd = [ffuf_cmd, "-u", f"{self.target}/FUZZ", "-w", wordlist_path, "-mc", "200,403", "-s"]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            # FFuF silent mode with -s usually outputs the findings
            findings = process.stdout.strip().split('\n')
            return {
                "tool": "FFuF",
                "results": [f for f in findings if f]
            }
        except Exception as e:
            return {"error": str(e), "tool": "FFuF"}

    def run_all_advanced(self):
        """Orchestrates the advanced arsenal scan."""
        advanced_report = {}
        
        if self.options.get("use_nuclei"):
            advanced_report["nuclei"] = self.run_nuclei()
            
        if self.options.get("use_subfinder"):
            advanced_report["subfinder"] = self.run_subfinder()
            
        return advanced_report
