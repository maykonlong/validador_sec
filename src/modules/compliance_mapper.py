"""
Compliance Mapper - Mapeia findings para frameworks de compliance
Facilita auditorias e certificações (OWASP, PCI-DSS, GDPR, CWE, etc)
"""

class ComplianceMapper:
    """Mapeia vulnerabilidades para frameworks de compliance."""
    
    # Mapeamentos detalhados
    VULNERABILITY_MAPPINGS = {
        'SQL Injection': {
            'OWASP_2021': ['A03:2021 – Injection'],
            'OWASP_TOP10': ['A1:2017 – Injection'],
            'PCI_DSS': ['6.5.1 – Injection flaws', '6.5.7 – Cross-site scripting'],
            'CWE': ['CWE-89 – SQL Injection'],
            'GDPR': ['Article 32 – Security of processing'],
            'ISO_27001': ['A.14.2.5 – Secure system engineering principles'],
        },
        'Cross-Site Scripting': {
            'OWASP_2021': ['A03:2021 – Injection'],
            'OWASP_TOP10': ['A7:2017 – Cross-Site Scripting (XSS)'],
            'PCI_DSS': ['6.5.7 – Cross-site scripting'],
            'CWE': ['CWE-79 – Cross-site Scripting'],
            'GDPR': ['Article 32 – Security of processing'],
            'ISO_27001': ['A.14.2.5 – Secure system engineering principles'],
        },
        'CORS': {
            'OWASP_2021': ['A05:2021 – Security Misconfiguration'],
            'OWASP_TOP10': ['A6:2017 – Security Misconfiguration'],
            'PCI_DSS': ['6.5.10 – Broken authentication and session management'],
            'CWE': ['CWE-346 – Origin Validation Error'],
            'GDPR': ['Article 32 – Security of processing'],
        },
        'Clickjacking': {
            'OWASP_2021': ['A05:2021 – Security Misconfiguration'],
            'OWASP_TOP10': ['A6:2017 – Security Misconfiguration'],
            'CWE': ['CWE-1021 – Clickjacking'],
            'PCI_DSS': ['6.5.9 – Improper error handling'],
        },
        'Command Injection': {
            'OWASP_2021': ['A03:2021 – Injection'],
            'OWASP_TOP10': ['A1:2017 – Injection'],
            'PCI_DSS': ['6.5.1 – Injection flaws'],
            'CWE': ['CWE-78 – OS Command Injection'],
            'GDPR': ['Article 32 – Security of processing'],
            'ISO_27001': ['A.14.2.5 – Secure system engineering principles'],
        },
        'Open Redirect': {
            'OWASP_2021': ['A01:2021 – Broken Access Control'],
            'CWE': ['CWE-601 – URL Redirection to Untrusted Site'],
            'PCI_DSS': ['6.5.10 – Broken authentication'],
        },
        'Sensitive Data Exposure': {
            'OWASP_2021': ['A02:2021 – Cryptographic Failures'],
            'OWASP_TOP10': ['A3:2017 – Sensitive Data Exposure'],
            'PCI_DSS': ['3.4 – Cryptography', '4.1 – Encryption'],
            'CWE': ['CWE-311 – Missing Encryption'],
            'GDPR': ['Article 32 – Security of processing', 'Article 33 – Data breach notification'],
            'ISO_27001': ['A.10.1 – Cryptographic controls'],
        },
    }
    
    def __init__(self):
        self.compliance_cache = {}
    
    def map_finding_to_compliance(self, finding):
        """
        Mapeia um finding específico para frameworks.
        
        Args:
            finding: dict - Finding do scanner
        
        Returns:
            dict: Mapeamentos de compliance
        """
        vuln_name = finding.get('vulnerability', '')
        
        # Busca por match parcial (case-insensitive)
        mappings = {}
        for vuln_key, compliance in self.VULNERABILITY_MAPPINGS.items():
            if vuln_key.lower() in vuln_name.lower():
                mappings = compliance
                break
        
        return mappings
    
    def generate_compliance_report(self, findings):
        """
        Gera relatório de compliance completo.
        
        Args:
            findings: list - Lista de findings
        
        Returns:
            dict: Relatório por framework
        """
        report = {
            'OWASP_2021': set(),
            'OWASP_TOP10': set(),
            'PCI_DSS': set(),
            'CWE': set(),
            'GDPR': set(),
            'ISO_27001': set(),
        }
        
        finding_details = []
        
        for finding in findings:
            mappings = self.map_finding_to_compliance(finding)
            
            # Adicionar aos frameworks
            for framework, codes in mappings.items():
                if framework in report:
                    report[framework].update(codes)
            
            # Guardar detalhes
            if mappings:
                finding_details.append({
                    'vulnerability': finding.get('vulnerability'),
                    'severity': finding.get('severity'),
                    'mappings': mappings,
                })
        
        # Converter sets para lists
        report = {k: sorted(list(v)) for k, v in report.items()}
        
        return {
            'summary': report,
            'total_violations': sum(len(v) for v in report.values()),
            'finding_details': finding_details,
            'compliance_status': self._calculate_compliance_status(report),
        }
    
    def _calculate_compliance_status(self, report):
        """Calcula status de compliance por framework."""
        status = {}
        
        # OWASP Top 10 (máximo 10 categorias)
        owasp_violations = len(report.get('OWASP_2021', []))
        status['OWASP_2021'] = {
            'violations': owasp_violations,
            'max_categories': 10,
            'compliance_percentage': max(0, 100 - (owasp_violations * 10)),
            'status': 'Pass' if owasp_violations < 3 else 'Fail',
        }
        
        # PCI-DSS (baseado em requisito 6.5)
        pci_violations = len(report.get('PCI_DSS', []))
        status['PCI_DSS'] = {
            'violations': pci_violations,
            'status': 'Compliant' if pci_violations == 0 else 'Non-Compliant',
            'risk_level': 'High' if pci_violations > 3 else 'Medium' if pci_violations > 0 else 'Low',
        }
        
        # GDPR (foco em Article 32 - Security)
        gdpr_violations = len(report.get('GDPR', []))
        status['GDPR'] = {
            'violations': gdpr_violations,
            'status': 'Compliant' if gdpr_violations == 0 else 'At Risk',
            'data_breach_risk': 'High' if gdpr_violations > 2 else 'Medium' if gdpr_violations > 0 else 'Low',
        }
        
        return status
    
    def export_compliance_matrix(self, findings):
        """
        Exporta matriz de compliance em formato de tabela.
        
        Returns:
            str: Tabela formatada
        """
        report = self.generate_compliance_report(findings)
        
        matrix = "# Compliance Matrix\n\n"
        matrix += "| Vulnerability | Severity | OWASP 2021 | PCI-DSS | GDPR | CWE |\n"
        matrix += "|--------------|----------|------------|---------|------|-----|\n"
        
        for detail in report['finding_details']:
            vuln = detail['vulnerability'][:30]  # Truncate
            severity = detail['severity']
            mappings = detail['mappings']
            
            owasp = ', '.join(mappings.get('OWASP_2021', ['-']))[:20]
            pci = ', '.join(mappings.get('PCI_DSS', ['-']))[:20]
            gdpr = ', '.join(mappings.get('GDPR', ['-']))[:20]
            cwe = ', '.join(mappings.get('CWE', ['-']))[:15]
            
            matrix += f"| {vuln} | {severity} | {owasp} | {pci} | {gdpr} | {cwe} |\n"
        
        return matrix
    
    def get_audit_checklist(self, framework='PCI_DSS'):
        """
        Retorna checklist de auditoria para framework específico.
        
        Args:
            framework: str - Framework (PCI_DSS, OWASP_2021, etc)
        
        Returns:
            dict: Checklist
        """
        checklists = {
            'PCI_DSS': {
                'name': 'PCI-DSS v3.2.1 Requirement 6.5',
                'requirements': [
                    '6.5.1 - Injection flaws (SQL, OS, LDAP)',
                    '6.5.7 - Cross-site scripting (XSS)',
                    '6.5.8 - Improper access control',
                    '6.5.9 - Cross-site request forgery (CSRF)',
                    '6.5.10 - Broken authentication',
                ],
            },
            'OWASP_2021': {
                'name': 'OWASP Top 10 - 2021',
                'requirements': [
                    'A01:2021 – Broken Access Control',
                    'A02:2021 – Cryptographic Failures',
                    'A03:2021 – Injection',
                    'A05:2021 – Security Misconfiguration',
                    'A07:2021 – Identification and Authentication Failures',
                ],
            },
        }
        
        return checklists.get(framework, {})
