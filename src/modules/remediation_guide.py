"""
Automated Remediation Guide Generator
Generates step-by-step fix guides for vulnerabilities

Provides:
- Code examples (before/after)
- Configuration fixes
- Validation tests
- Timeline recommendations
- Official documentation links
"""

class RemediationGuideGenerator:
    """Generates comprehensive remediation guides"""
    
    def __init__(self):
        self.guides = self._load_guides()
    
    def _load_guides(self):
        """Load remediation guides for common vulnerabilities"""
        return {
            'SQL Injection': {
                'priority': 'CRITICAL',
                'timeline': '24-48 hours',
                'difficulty': 'Medium',
                'steps': [
                    {
                        'title': '1. Use Prepared Statements (RECOMENDADO)',
                        'before': '''# VULNERÁVEL
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)''',
                        'after': '''# SEGURO - Prepared Statement
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Ou usando ORM (Django)
User.objects.filter(id=user_id)''',
                        'explanation': 'Prepared statements separam SQL de dados, impossibilitando injeção'
                    },
                    {
                        'title': '2. Input Validation',
                        'code': '''# Validar tipo
if not isinstance(user_id, int):
    raise ValueError("ID deve ser número")

# Whitelist characters
import re
if not re.match(r'^[0-9]+$', user_id):
    raise ValueError("ID inválido")''',
                        'explanation': 'Validação adicional como defesa em profundidade'
                    },
                    {
                        'title': '3. Configurar WAF',
                        'code': '''# ModSecurity / CloudFlare
SecRule ARGS "@detectSQLi" \\
    "id:1,phase:2,deny,status:403"''',
                        'explanation': 'WAF detecta e bloqueia tentativas de SQLi'
                    },
                ],
                'validation': '''# Teste após o fix
curl "https://site.com?id=' OR 1=1--"
→ Deve retornar erro 400/500, não dados''',
                'references': [
                    'https://owasp.org/www-community/attacks/SQL_Injection',
                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                ]
            },
            
            'XSS': {
                'priority': 'HIGH',
                'timeline': '3-7 days',
                'difficulty': 'Easy',
                'steps': [
                    {
                        'title': '1. Output Encoding (ESSENCIAL)',
                        'before': '''<!-- VULNERÁVEL -->
<div>Bem-vindo, {{ user_name }}</div>''',
                        'after': '''<!-- SEGURO -->
<div>Bem-vindo, {{ user_name|escape }}</div>

<!-- Ou em Python -->
from html import escape
safe_name = escape(user_name)''',
                        'explanation': 'Encoding converte < > em &lt; &gt; impossibilitando execução'
                    },
                    {
                        'title': '2. Content-Security-Policy Header',
                        'code': '''# Adicionar no servidor
Content-Security-Policy: default-src 'self'; script-src 'self'

# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'";

# Apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self'"''',
                        'explanation': 'CSP bloqueia execução de scripts inline/externos'
                    },
                ],
                'validation': '''# Teste
curl "https://site.com?q=<script>alert(1)</script>"
→ Response deve conter &lt;script&gt; (encoded)
→ Alert NÃO deve aparecer no browser''',
                'references': [
                    'https://owasp.org/www-community/attacks/xss/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                ]
            },
            
            'Clickjacking': {
                'priority': 'MEDIUM',
                'timeline': '1-2 weeks',
                'difficulty': 'Very Easy',
                'steps': [
                    {
                        'title': '1. Adicionar X-Frame-Options Header',
                        'code': '''# Nginx
add_header X-Frame-Options "DENY";

# Apache
Header always set X-Frame-Options "DENY"

# PHP
header("X-Frame-Options: DENY");

# Express.js
app.use(helmet.frameguard({ action: 'deny' }));''',
                        'explanation': 'Impede que site seja carregado em iframe'
                    },
                    {
                        'title': '2. Content-Security-Policy frame-ancestors',
                        'code': '''# Mais moderno que X-Frame-Options
Content-Security-Policy: frame-ancestors 'none'

# Ou permitir apenas seu domínio
Content-Security-Policy: frame-ancestors 'self' https://example.com''',
                        'explanation': 'CSP oferece controle mais granular'
                    },
                ],
                'validation': '''# Teste
curl -I https://site.com | grep X-Frame-Options
→ Deve retornar: X-Frame-Options: DENY

# Teste visual
Criar arquivo test.html:
<iframe src="https://site.com"></iframe>
→ Deve mostrar erro de frame bloqueado''',
                'references': [
                    'https://owasp.org/www-community/attacks/Clickjacking'
                ]
            },
            
            'BOLA/IDOR': {
                'priority': 'CRITICAL',
                'timeline': '24 hours',
                'difficulty': 'Medium',
                'steps': [
                    {
                        'title': '1. Validar Propriedade do Objeto',
                        'before': '''# VULNERÁVEL
@app.route('/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())''',
                        'after': '''# SEGURO
@app.route('/users/<user_id>')
@login_required
def get_user(user_id):
    # Verificar se user autenticado é dono
    if str(current_user.id) != user_id:
        return {"error": "Unauthorized"}, 403
    
    user = User.query.get(user_id)
    return jsonify(user.to_dict())''',
                        'explanation': 'Sempre validar se usuário autenticado tem permissão'
                    },
                    {
                        'title': '2. Usar UUIDs ao invés de IDs sequenciais',
                        'code': '''# Ao invés de /users/1, /users/2...
# Usar /users/550e8400-e29b-41d4-a716-446655440000

import uuid
user.id = uuid.uuid4()

# Dificulta enumeração de recursos''',
                        'explanation': 'UUIDs impossibilitam adivinhação de IDs'
                    },
                ],
                'validation': '''# Teste
# Como User A, tentar acessar recurso de User B
curl https://api.com/users/USER_B_ID \\
  -H "Authorization: Bearer USER_A_TOKEN"
→ Deve retornar 403 Forbidden''',
                'references': [
                    'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'
                ]
            },
            
            'Sensitive Data Exposure': {
                'priority': 'HIGH',
                'timeline': '1 week',
                'difficulty': 'Easy',
                'steps': [
                    {
                        'title': '1. Filtrar Campos Sensíveis na Response',
                        'before': '''# VULNERÁVEL - Retorna tudo
return jsonify(user.__dict__)''',
                        'after': '''# SEGURO - Whitelist de campos
safe_fields = ['id', 'name', 'email', 'created_at']
response = {k: v for k, v in user.__dict__.items() if k in safe_fields}
return jsonify(response)

# Ou usar serializer
class UserSerializer:
    fields = ['id', 'name', 'email']  # SEM password, token, etc.''',
                        'explanation': 'Retornar apenas dados que o cliente realmente precisa'
                    },
                    {
                        'title': '2. Mascarar Dados Sensíveis',
                        'code': '''# Mascarar CPF, cartão de crédito
cpf = "123.456.789-00"
masked_cpf = "***456.789-**"

# Email
email = "user@example.com"
masked_email = "u***@example.com"''',
                        'explanation': 'Quando dados devem ser mostrados, mascarar'
                    },
                ],
                'validation': '''# Verificar response
curl https://api.com/users/me -H "Auth: token" | jq
→ NÃO deve conter: password, token, ssn, credit_card''',
                'references': [
                    'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'
                ]
            },
        }
    
    def generate_guide(self, vulnerability_name, finding_details=None):
        """
        Generate remediation guide for a vulnerability
        
        Args:
            vulnerability_name: str - Name of vulnerability
            finding_details: dict - Specific finding details
        
        Returns:
            str: HTML formatted remediation guide
        """
        # Find matching guide
        guide = None
        for vuln_type, guide_data in self.guides.items():
            if vuln_type.lower() in vulnerability_name.lower():
                guide = guide_data
                break
        
        if not guide:
            return self._generate_generic_guide(vulnerability_name)
        
        # Generate detailed guide
        html = f"""
<br><br>
<strong>🔧 GUIA DE REMEDIAÇÃO COMPLETA:</strong><br><br>

<strong>Prioridade:</strong> {guide['priority']}<br>
<strong>Timeline:</strong> Corrigir em {guide['timeline']}<br>
<strong>Dificuldade:</strong> {guide['difficulty']}<br><br>

<strong>PASSOS PARA CORREÇÃO:</strong><br><br>
"""
        
        for step in guide['steps']:
            html += f"<strong>{step['title']}</strong><br>"
            
            if 'before' in step:
                html += f"""
<strong>ANTES (Vulnerável):</strong><br>
<code>{self._escape_html(step['before'])}</code><br><br>

<strong>DEPOIS (Seguro):</strong><br>
<code>{self._escape_html(step['after'])}</code><br><br>
"""
            elif 'code' in step:
                html += f"<code>{self._escape_html(step['code'])}</code><br><br>"
            
            html += f"<em>{step['explanation']}</em><br><br>"
        
        # Validation
        html += f"""
<strong>✅ VALIDAÇÃO (Testar o Fix):</strong><br>
<code>{self._escape_html(guide['validation'])}</code><br><br>
"""
        
        # References
        html += "<strong>📚 REFERÊNCIAS OFICIAIS:</strong><br>"
        for ref in guide['references']:
            html += f"• {ref}<br>"
        
        return html
    
    def _generate_generic_guide(self, vulnerability_name):
        """Generate generic remediation guide"""
        return f"""
<br><br>
<strong>🔧 RECOMENDAÇÕES GERAIS DE REMEDIAÇÃO:</strong><br><br>

1. Consultar documentação oficial da tecnologia<br>
2. Aplicar princípio do menor privilégio<br>
3. Validar todos os inputs<br>
4. Usar bibliotecas/frameworks atualizados<br>
5. Implementar defense in depth<br><br>

<strong>Referências:</strong><br>
• OWASP Top 10: https://owasp.org/www-project-top-ten/<br>
• CWE Database: https://cwe.mitre.org/
"""
    
    def _escape_html(self, text):
        """Escape HTML for safe display"""
        return text.replace('<', '&lt;').replace('>', '&gt;')
    
    def get_timeline_color(self, priority):
        """Get color code for timeline"""
        colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
        }
        return colors.get(priority, '⚪')
