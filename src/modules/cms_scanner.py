import requests
import re
from typing import Dict, Any

class CMSDetective:
    """Scanner Específico para WordPress"""

    def scan(self, url: str) -> Dict[str, Any]:
        if not url.startswith('http'):
            url = 'http://' + url
        url = url.rstrip('/')

        report = {
            'target': url,
            'is_wordpress': False,
            'version': None,
            'users': [],
            'plugins': [],
            'vulns': [],
            'config_exposed': False
        }

        try:
            # 1. Detectar se é WP
            resp = requests.get(url, timeout=5)
            if 'wp-content' in resp.text:
                report['is_wordpress'] = True
            
            # Tentar pegar versão via meta tag
            meta_match = re.search(r'content="WordPress (.*?)"', resp.text)
            if meta_match:
                report['version'] = meta_match.group(1)

            if report['is_wordpress']:
                # 2. User Enumeration (API REST)
                # Tenta listar usuários pela API pública do WP
                try:
                    api_url = f"{url}/wp-json/wp/v2/users"
                    api_resp = requests.get(api_url, timeout=5)
                    if api_resp.status_code == 200:
                        users_json = api_resp.json()
                        for u in users_json:
                            report['users'].append(u['slug'])
                except:
                    pass

                # 3. Check Sensitive Files
                files = ['/wp-config.php.bak', '/readme.html', '/license.txt']
                for f in files:
                     check = requests.get(f"{url}{f}", timeout=3)
                     if check.status_code == 200:
                         report['vulns'].append(f"Arquivo exposto: {f}")

                # 4. Check XMLRPC
                xml_check = requests.get(f"{url}/xmlrpc.php", timeout=3)
                if xml_check.status_code != 404:
                     report['vulns'].append("XML-RPC habilitado (Risco de Brute Force / DDoS)")

            else:
                report['vulns'].append("Não parece ser um WordPress (ou está bem oculto).")

        except Exception as e:
            report['vulns'].append(f"Erro de conexão: {str(e)}")

        return report
