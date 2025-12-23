import re
from typing import Dict, List, Any
from datetime import datetime
from collections import Counter

class LogSentinel:
    """Analisador de Logs de Servidor (Apache/Nginx/IIS)"""

    ATTACK_SIGNATURES = {
        'SQL Injection': [r"UNION SELECT", r"OR '1'='1", r"INFORMATION_SCHEMA", r"WAITFOR DELAY", r"BENCHMARK\("],
        'XSS': [r"<script>", r"javascript:", r"onerror=", r"onload=", r"alert\("],
        'Path Traversal': [r"\.\./\.\./", r"/etc/passwd", r"boot\.ini", r"\\windows\\win\.ini"],
        'Command Injection': [r"; cat /", r"| ls", r"\$\(whoami\)", r"&& net user"],
        'Scanner': [r"Nmap", r"Nikto", r"BurpSuite", r"sqlmap", r"DirBuster", r"Go-http-client"]
    }

    def analyze(self, content: str) -> Dict[str, Any]:
        report = {
            'total_lines': 0,
            'attacks_detected': 0,
            'unique_ips': 0,
            'top_attackers': [],
            'attack_distribution': {},
            'geo_map_data': [], # Simulação de dados para mapa
            'threats': []
        }

        lines = content.split('\n')
        report['total_lines'] = len(lines)
        
        attackers_ip = []
        attack_types = []

        # Regex básica para extrair IP (funciona para Common Log Format)
        ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

        for i, line in enumerate(lines):
            if not line.strip(): continue

            # Checar Ataques
            detected_attack = None
            for attack_name, sigs in self.ATTACK_SIGNATURES.items():
                for sig in sigs:
                    if re.search(sig, line, re.IGNORECASE):
                        detected_attack = attack_name
                        break
                if detected_attack: break
            
            # Se ataque detectado
            if detected_attack:
                report['attacks_detected'] += 1
                attack_types.append(detected_attack)
                
                # Tentar extrair IP
                ip_match = re.search(ip_pattern, line)
                attacker_ip = ip_match.group(1) if ip_match else "Desconhecido"
                if attacker_ip != "Desconhecido":
                    attackers_ip.append(attacker_ip)

                # Adicionar aos detalhes (Max 50 para não poluir)
                if len(report['threats']) < 50:
                    report['threats'].append({
                        'line': i + 1,
                        'ip': attacker_ip,
                        'type': detected_attack,
                        'payload': line[:200] + "..." if len(line) > 200 else line
                    })

        # Estatísticas
        report['unique_ips'] = len(set(attackers_ip))
        report['top_attackers'] = Counter(attackers_ip).most_common(5)
        report['attack_distribution'] = dict(Counter(attack_types))

        return report
