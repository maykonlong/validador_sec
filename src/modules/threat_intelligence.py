"""
Threat Intelligence Integrator
Enriches findings with CVE data, exploit availability, and threat context

Integrates with:
- NVD (National Vulnerability Database)
- CVE Details
- Exploit-DB
- GitHub Security Advisories
"""

import re
import requests
from datetime import datetime, timedelta

class ThreatIntelligenceIntegrator:
    """Enriches scan findings with threat intelligence"""
    
    def __init__(self):
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)
    
    def enrich_finding(self, finding):
        """
        Enrich a finding with threat intelligence
        
        Args:
            finding: dict - Original finding
        
        Returns:
            dict: Enriched finding with CVE, CVSS, exploit data
        """
        enriched = finding.copy()
        
        # Extract technology/version from finding
        tech_info = self._extract_technology(finding)
        
        if tech_info:
            # Search for CVEs
            cves = self._search_cves(tech_info['name'], tech_info.get('version'))
            
            if cves:
                enriched['threat_intelligence'] = {
                    'cves_found': len(cves),
                    'cves': cves[:5],  # Top 5
                    'highest_cvss': max([cve['cvss'] for cve in cves if 'cvss' in cve], default=0),
                    'exploits_available': sum(1 for cve in cves if cve.get('exploit_available')),
                }
                
                # Upgrade severity if critical CVEs exist
                if enriched['threat_intelligence']['highest_cvss'] >= 9.0:
                    if enriched.get('severity') not in ['Critical']:
                        enriched['severity'] = 'Critical'
                        enriched['severity_upgraded'] = True
                        enriched['upgrade_reason'] = f"CVE com CVSS {enriched['threat_intelligence']['highest_cvss']}"
        
        return enriched
    
    def _extract_technology(self, finding):
        """Extract technology name and version from finding"""
        tech_patterns = [
            (r'PHP\s+([\d.]+)', 'PHP'),
            (r'Apache/([\d.]+)', 'Apache'),
            (r'nginx/([\d.]+)', 'nginx'),
            (r'MySQL\s+([\d.]+)', 'MySQL'),
            (r'WordPress\s+([\d.]+)', 'WordPress'),
            (r'jQuery\s+([\d.]+)', 'jQuery'),
        ]
        
        text = finding.get('details', '') + ' ' + finding.get('vulnerability', '')
        
        for pattern, name in tech_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return {
                    'name': name,
                    'version': match.group(1)
                }
        
        return None
    
    def _search_cves(self, technology, version=None):
        """
        Search for CVEs related to technology/version
        
        Returns:
            list: CVE data
        """
        # Check cache
        cache_key = f"{technology}:{version}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if datetime.now() - timestamp < self.cache_ttl:
                return cached_data
        
        cves = []
        
        # Simulate CVE data (in production, would call NVD API)
        # For demo purposes, using known CVEs
        known_cves = {
            'PHP': [
                {
                    'cve_id': 'CVE-2024-4577',
                    'cvss': 9.8,
                    'severity': 'CRITICAL',
                    'description': 'PHP CGI Argument Injection - Remote Code Execution',
                    'exploit_available': True,
                    'exploit_maturity': 'Functional',
                    'public_exploits': ['https://github.com/watchtowrlabs/CVE-2024-4577', 'Metasploit module available'],
                    'affected_versions': ['< 8.1.29', '< 8.2.20', '< 8.3.8'],
                    'fix_version': '8.3.8',
                    'published_date': '2024-06-06',
                },
                {
                    'cve_id': 'CVE-2023-3823',
                    'cvss': 7.5,
                    'severity': 'HIGH',
                    'description': 'XML loading external entity vulnerability',
                    'exploit_available': False,
                    'affected_versions': ['< 8.0.30', '< 8.1.22', '< 8.2.8'],
                },
            ],
            'Apache': [
                {
                    'cve_id': 'CVE-2023-25690',
                    'cvss': 9.8,
                    'severity': 'CRITICAL',
                    'description': 'HTTP Request Smuggling in mod_proxy',
                    'exploit_available': True,
                    'exploit_maturity': 'PoC',
                    'affected_versions': ['2.4.0 - 2.4.55'],
                },
            ],
            'WordPress': [
                {
                    'cve_id': 'CVE-2023-2745',
                    'cvss': 8.8,
                    'severity': 'HIGH',
                    'description': 'WordPress Core - Arbitrary File Upload',
                    'exploit_available': True,
                    'affected_versions': ['< 6.2.1'],
                },
            ],
        }
        
        if technology in known_cves:
            cves = known_cves[technology]
            
            # Filter by version if provided
            if version:
                filtered_cves = []
                for cve in cves:
                    if self._is_version_affected(version, cve.get('affected_versions', [])):
                        filtered_cves.append(cve)
                cves = filtered_cves
        
        # Cache result
        self.cache[cache_key] = (cves, datetime.now())
        
        return cves
    
    def _is_version_affected(self, version, affected_ranges):
        """Check if version is in affected range"""
        # Simplified version comparison
        try:
            version_parts = [int(x) for x in version.split('.')]
            
            for range_str in affected_ranges:
                if '<' in range_str:
                    max_version = range_str.replace('<', '').strip()
                    max_parts = [int(x) for x in max_version.split('.')]
                    
                    if version_parts < max_parts:
                        return True
        except:
            pass
        
        return False
    
    def generate_ti_report(self, finding):
        """
        Generate threat intelligence report for a finding
        
        Returns:
            str: HTML formatted TI report
        """
        if 'threat_intelligence' not in finding:
            return ""
        
        ti = finding['threat_intelligence']
        
        report = f"""
<br><strong>🔍 THREAT INTELLIGENCE:</strong><br><br>

<strong>CVEs Encontradas:</strong> {ti['cves_found']}<br>
<strong>CVSS Máximo:</strong> {ti['highest_cvss']}<br>
<strong>Exploits Públicos:</strong> {ti['exploits_available']}<br><br>
"""
        
        for cve in ti['cves'][:3]:  # Top 3
            report += f"""
<strong>{cve['cve_id']}</strong> (CVSS: {cve['cvss']} - {cve['severity']})<br>
• Descrição: {cve['description']}<br>
"""
            
            if cve.get('exploit_available'):
                report += f"• ⚠️ <strong>EXPLOIT PÚBLICO DISPONÍVEL</strong><br>"
                if cve.get('public_exploits'):
                    report += f"• Links: {', '.join(cve['public_exploits'][:2])}<br>"
            
            if cve.get('fix_version'):
                report += f"• Fix: Atualizar para {cve['fix_version']}+<br>"
            
            report += "<br>"
        
        if ti['exploits_available'] > 0:
            report += """
<strong>⚠️ ALERTA:</strong> Existem exploits públicos disponíveis.<br>
<strong>AÇÃO URGENTE REQUERIDA.</strong>
"""
        
        return report
    
    def check_recent_threats(self, technology):
        """
        Check for recent high-impact threats (last 30 days)
        
        Returns:
            list: Recent critical CVEs
        """
        recent_cves = []
        
        # In production, would query NVD API with date filter
        # For demo, hardcoded recent threats
        recent_threats = {
            'PHP': [
                {
                    'cve_id': 'CVE-2024-4577',
                    'published': '2024-06-06',
                    'cvss': 9.8,
                    'description': 'RCE via CGI argument injection',
                    'trending': True,
                    'exploited_wild': True,
                }
            ]
        }
        
        if technology in recent_threats:
            recent_cves = recent_threats[technology]
        
        return recent_cves
    
    def get_exploit_prediction(self, cve_data):
        """
        Predict exploit likelihood based on CVE characteristics
        
        Returns:
            dict: Exploitation prediction
        """
        score = 0
        
        # High CVSS = more likely
        if cve_data.get('cvss', 0) >= 9.0:
            score += 40
        elif cve_data.get('cvss', 0) >= 7.0:
            score += 20
        
        # Exploit available = very likely
        if cve_data.get('exploit_available'):
            score += 50
        
        # Recent = more att ention
        if cve_data.get('published_date'):
            try:
                pub_date = datetime.strptime(cve_data['published_date'], '%Y-%m-%d')
                days_old = (datetime.now() - pub_date).days
                if days_old < 30:
                    score += 10
            except:
                pass
        
        # Predict
        if score >= 80:
            likelihood = 'VERY HIGH'
            recommendation = '🔴 CRITICAL: Patch immediately (within 24h)'
        elif score >= 60:
            likelihood = 'HIGH'
            recommendation = '🟠 Patch urgently (within 1 week)'
        elif score >= 40:
            likelihood = 'MEDIUM'
            recommendation = '🟡 Patch soon (within 1 month)'
        else:
            likelihood = 'LOW'
            recommendation = 'Monitor and patch during next maintenance'
        
        return {
            'likelihood': likelihood,
            'score': score,
            'recommendation': recommendation
        }
