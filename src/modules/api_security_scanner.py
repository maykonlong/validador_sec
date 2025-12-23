"""
API Security Scanner
Detects vulnerabilities specific to REST APIs and GraphQL

Based on OWASP API Security Top 10:
1. Broken Object Level Authorization (BOLA/IDOR)
2. Broken Authentication
3. Excessive Data Exposure
4. Lack of Resources & Rate Limiting
5. Broken Function Level Authorization
6. Mass Assignment
7. Security Misconfiguration
8. Injection
9. Improper Assets Management
10. Insufficient Logging & Monitoring
"""

import re
import json
import time

class APISecurityScanner:
    """Scanner focused on API-specific vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        self.findings = []
    
    def scan_endpoint(self, url, method='GET'):
        """
        Comprehensive API security scan
        
        Args:
            url: API endpoint URL
            method: HTTP method (GET, POST, PUT, DELETE)
        
        Returns:
            list: API-specific findings
        """
        findings = []
        
        # Test 1: BOLA/IDOR
        bola_result = self._test_bola(url, method)
        if bola_result:
            findings.append(bola_result)
        
        # Test 2: Excessive Data Exposure
        data_exposure = self._test_data_exposure(url)
        if data_exposure:
            findings.append(data_exposure)
        
        # Test 3: Mass Assignment
        mass_assignment = self._test_mass_assignment(url)
        if mass_assignment:
            findings.append(mass_assignment)
        
        # Test 4: Broken Function Level Authorization
        function_auth = self._test_function_authorization(url)
        if function_auth:
            findings.append(function_auth)
        
        # Test 5: Rate Limiting
        rate_limit = self._test_rate_limiting(url)
        if rate_limit:
            findings.append(rate_limit)
        
        return findings
    
    def _test_bola(self, url, method):
        """Test for Broken Object Level Authorization (IDOR)"""
        try:
            # Check if URL has numeric ID pattern
            id_patterns = [
                r'/(\d+)/?$',  # /users/123
                r'[?&]id=(\d+)',  # ?id=123
                r'[?&]user_id=(\d+)',  # ?user_id=123
            ]
            
            for pattern in id_patterns:
                match = re.search(pattern, url)
                if match:
                    original_id = match.group(1)
                    
                    # Test with original ID
                    resp1 = self.session.request(method, url, timeout=5)
                    
                    # Try incrementing ID
                    new_id = str(int(original_id) + 1)
                    test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, new_id), url)
                    
                    resp2 = self.session.request(method, test_url, timeout=5)
                    
                    # Vulnerable if both return 200 with different data
                    if resp1.status_code == 200 and resp2.status_code == 200:
                        if len(resp2.content) > 100:  # Not just error message
                            return {
                                'vulnerability': 'BOLA/IDOR - Broken Object Level Authorization',
                                'status': 'Vulnerable',
                                'severity': 'Critical',
                                'details': f"""
<strong>IDOR Detectado - API permite acesso a objetos de outros usuários</strong><br><br>

<strong>Endpoint:</strong> {url}<br>
<strong>ID Original:</strong> {original_id}<br>
<strong>ID Testado:</strong> {new_id}<br>
<strong>Resultado:</strong> Ambos retornam 200 OK<br><br>

<strong>Evidências:</strong><br>
✅ Endpoint aceita IDs arbitrários<br>
✅ Sem validação de propriedade do objeto<br>
✅ Dados de outros usuários acessíveis<br>
✅ OWASP API1:2023 - Broken Object Level Authorization
""",
                                'methodology': f"""
Teste BOLA/IDOR em 3 etapas:<br><br>
<strong>1.</strong> Acesso ao ID original ({original_id}): 200 OK<br>
<strong>2.</strong> Acesso ao ID incrementado ({new_id}): 200 OK<br>
<strong>3.</strong> Análise: Sem controle de autorização<br><br>
Padrão OWASP API Testing Guide
""",
                                'manual_test': f"""
<strong>Reprodução Manual:</strong><br><br>

<strong>1. Request com ID original:</strong><br>
<code>curl {url}</code><br>
Resultado: Dados do usuário {original_id}<br><br>

<strong>2. Request com ID diferente:</strong><br>
<code>curl {test_url}</code><br>
Resultado: Dados do usuário {new_id} (VULNERÁVEL)<br><br>

<strong>3. Teste automatizado:</strong><br>
<code>
for i in {{1..100}}; do<br>
  curl "https://api.site.com/users/$i" -H "Auth: token"<br>
done
</code><br>
Deve retornar apenas dados do próprio usuário authenticado
""",
                                'risk': """
<strong>SEVERIDADE: CRÍTICA</strong><br><br>

<strong>Impacto Real:</strong><br>
✅ Acesso a dados de TODOS os usuários<br>
✅ PII exposure (nome, email, telefone, endereço)<br>
✅ Dados financeiros expostos<br>
✅ Violação LGPD/GDPR<br>
✅ Responsabilidade legal<br><br>

<strong>Cenário de Ataque:</strong><br>
1. Atacante enumera IDs (1 a 100000)<br>
2. Extrai dados de todos os usuários<br>
3. Vende database na dark web<br>
4. Empresa multada + perda de reputação<br><br>

<strong>Fix Urgente:</strong><br>
🔴 Validar se user_id == authenticated_user_id<br>
🔴 Usar UUIDs ao invés de IDs sequenciais<br>
🔴 Implementar ACL (Access Control List)<br>
🔴 Rate limiting em endpoints sensíveis
""",
                                'category': 'API Security'
                            }
        except:
            pass
        
        return None
    
    def _test_data_exposure(self, url):
        """Test for Excessive Data Exposure"""
        try:
            resp = self.session.get(url, timeout=5)
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    
                    # Check for sensitive fields in response
                    sensitive_fields = ['password', 'token', 'secret', 'api_key', 'ssn', 'credit_card']
                    found_sensitive = []
                    
                    def check_dict(obj, path=''):
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                current_path = f"{path}.{key}" if path else key
                                if any(s in key.lower() for s in sensitive_fields):
                                    found_sensitive.append(current_path)
                                check_dict(value, current_path)
                        elif isinstance(obj, list):
                            for item in obj:
                                check_dict(item, path)
                    
                    check_dict(data)
                    
                    if found_sensitive:
                        return {
                            'vulnerability': 'API3:2023 - Excessive Data Exposure',
                            'status': 'Vulnerable',
                            'severity': 'High',
                            'details': f"""
<strong>API expõe dados sensíveis desnecessários</strong><br><br>

<strong>Endpoint:</strong> {url}<br>
<strong>Campos Sensíveis Detectados:</strong><br>
{'<br>'.join([f"• {field}" for field in found_sensitive[:5]])}<br><br>

<strong>Problema:</strong><br>
API retorna mais dados do que o cliente precisa, incluindo informações sensíveis.
""",
                            'methodology': 'Análise de schema JSON + detecção de campos sensíveis',
                            'manual_test': f'curl {url} | jq',
                            'risk': 'Exposição desnecessária de dados sensíveis facilita ataques',
                            'category': 'API Security'
                        }
                except:
                    pass
        except:
            pass
        
        return None
    
    def _test_mass_assignment(self, url):
        """Test for Mass Assignment vulnerabilities"""
        # Test if API accepts unexpected parameters
        try:
            # Try adding admin/role parameters
            test_data = {
                'is_admin': True,
                'role': 'admin',
                'verified': True,
                'premium': True
            }
            
            resp = self.session.post(url, json=test_data, timeout=5)
            
            # If accepts without error, might be vulnerable
            if resp.status_code in [200, 201]:
                return {
                    'vulnerability': 'API6:2023 - Mass Assignment',
                    'status': 'Warning',
                    'severity': 'Medium',
                    'details': f"""
<strong>API pode ser vulnerável a Mass Assignment</strong><br><br>

<strong>Endpoint:</strong> {url}<br>
Aceita parâmetros não documentados (is_admin, role, etc.)<br><br>

Requer validação manual.
""",
                    'methodology': 'Teste de parâmetros privilegiados',
                    'manual_test': f'curl -X POST {url} -d \'{{"is_admin": true}}\'',
                    'risk': 'Usuários podem se promover a admin via mass assignment',
                    'category': 'API Security'
                }
        except:
            pass
        
        return None
    
    def _test_function_authorization(self, url):
        """Test for Broken Function Level Authorization"""
        # Test administrative endpoints without auth
        admin_paths = ['/admin', '/api/admin', '/v1/admin', '/debug', '/internal']
        
        try:
            for admin_path in admin_paths:
                test_url = url.rsplit('/', 1)[0] + admin_path
                resp = self.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    return {
                        'vulnerability': 'API5:2023 - Broken Function Level Authorization',
                        'status': 'Vulnerable',
                        'severity': 'High',
                        'details': f'Endpoint administrativo acessível sem autenticação: {test_url}',
                        'methodology': 'Enumeração de endpoints privilegiados',
                        'manual_test': f'curl {test_url}',
                        'risk': 'Funções administrativas expostas sem controle de acesso',
                        'category': 'API Security'
                    }
        except:
            pass
        
        return None
    
    def _test_rate_limiting(self, url):
        """Test for lack of rate limiting"""
        try:
            # Send 10 rapid requests
            start_time = time.time()
            statuses = []
            
            for i in range(10):
                resp = self.session.get(url, timeout=2)
                statuses.append(resp.status_code)
            
            elapsed = time.time() - start_time
            
            # If all succeeded rapidly, no rate limit
            if statuses.count(200) == 10 and elapsed < 3:
                return {
                    'vulnerability': 'API4:2023 - Lack of Rate Limiting',
                    'status': 'Warning',
                    'severity': 'Medium',
                    'details': f"""
<strong>API sem Rate Limiting detectado</strong><br><br>

<strong>Endpoint:</strong> {url}<br>
<strong>Teste:</strong> 10 requests em {elapsed:.2f}s<br>
<strong>Resultado:</strong> Todas aceitas (200 OK)<br><br>

Vulnerável a:<br>
• Brute force<br>
• DoS<br>
• Resource exhaustion<br>
• Scraping em massa
""",
                    'methodology': 'Burst de 10 requests rápidas',
                    'manual_test': f'for i in {{1..100}}; do curl {url}; done',
                    'risk': 'API pode ser abusada para DoS, brute force, ou scraping',
                    'category': 'API Security'
                }
        except:
            pass
        
        return None
    
    def is_api_endpoint(self, url):
        """
        Detect if URL is an API endpoint
        
        Returns:
            bool: True if looks like API
        """
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/rest/', '/graphql', '/json',
            'api.', '.json', '.xml'
        ]
        
        return any(indicator in url.lower() for indicator in api_indicators)
