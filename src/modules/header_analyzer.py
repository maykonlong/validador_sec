import re
import ipaddress
from typing import Dict, Any

class EmailHeaderAnalyzer:
    """Analisador de Cabeçalhos de E-mail para Detecção de Phishing"""

    def analyze(self, raw_header: str) -> Dict[str, Any]:
        result = {
            'subject': None,
            'from': None,
            'to': None,
            'return_path': None,
            'origin_ip': None,
            'origin_country': 'Desconhecido',
            'security_checks': {
                'spf': 'Não encontrado',
                'dkim': 'Não encontrado',
                'dmarc': 'Não encontrado'
            },
            'risk_score': 0,
            'verdict': 'Seguro',
            'warnings': []
        }

        # Normalizar quebras de linha
        header = raw_header.replace('\r\n', '\n')

        # Extrair Campos Básicos
        result['subject'] = self._extract_field(header, r'^Subject: (.+)$')
        result['from'] = self._extract_field(header, r'^From: (.+)$')
        result['to'] = self._extract_field(header, r'^To: (.+)$')
        result['return_path'] = self._extract_field(header, r'^Return-Path: <(.+)>')

        # Extrair Autenticação (Authentication-Results)
        auth_results = self._extract_field(header, r'Authentication-Results: (.+)')
        if auth_results:
            if 'spf=pass' in auth_results.lower(): result['security_checks']['spf'] = 'PASS'
            elif 'spf=fail' in auth_results.lower(): 
                result['security_checks']['spf'] = 'FAIL'
                result['warnings'].append("SPF Falhou: O servidor de envio não é autorizado.")
                result['risk_score'] += 30

            if 'dkim=pass' in auth_results.lower(): result['security_checks']['dkim'] = 'PASS'
            elif 'dkim=fail' in auth_results.lower():
                result['security_checks']['dkim'] = 'FAIL'
                result['warnings'].append("DKIM Falhou: A mensagem pode ter sido alterada.")
                result['risk_score'] += 30

            if 'dmarc=pass' in auth_results.lower(): result['security_checks']['dmarc'] = 'PASS'
            elif 'dmarc=fail' in auth_results.lower():
                result['security_checks']['dmarc'] = 'FAIL'
                result['warnings'].append("DMARC Falhou: Política de segurança violada.")
                result['risk_score'] += 20

        # Extrair IP de Origem (Achar o último 'Received: from' confiável)
        ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if ips:
            # Pegar o IP mais profundo que não seja privado (10.x, 192.168.x)
            for ip in reversed(ips):
                if not self._is_private_ip(ip):
                    result['origin_ip'] = ip
                    break
            
            if not result['origin_ip'] and ips:
                result['origin_ip'] = ips[-1] # Fallback

        # Análise de Risco Extra
        if result['return_path'] and result['from']:
            # Extrair emails simples para comparar
            email_from = re.search(r'[\w\.-]+@[\w\.-]+', result['from'])
            if email_from and result['return_path'] not in email_from.group(0):
                 result['warnings'].append("Spoofing Detectado: Return-Path diferente do Remetente")
                 result['risk_score'] += 40

        # Calcular Veredito
        if result['risk_score'] > 70:
            result['verdict'] = 'CRÍTICO: Phishing Provável'
        elif result['risk_score'] > 30:
            result['verdict'] = 'SUSPEITO: Cuidado'
        
        return result

    def _extract_field(self, text, pattern):
        match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _is_private_ip(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str).is_private
        except:
            return False
