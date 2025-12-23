"""
Módulo de Verificação de Vazamentos
Integração com HaveIBeenPwned API
"""

import hashlib
import requests
from typing import Dict, List, Any
from datetime import datetime
import time


class BreachChecker:
    """
    Cliente para API HaveIBeenPwned
    """
    
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    HEADERS = {
        'User-Agent': 'Validador-SEC-v2.0',
        'hibp-api-key': None  # Será configurado com env var
    }
    
    def __init__(self, api_key: str = None):
        """
        Inicializa o checker
        
        Args:
            api_key: Chave da API HIBP (opcional para algumas consultas)
        """
        if api_key:
            self.HEADERS['hibp-api-key'] = api_key
        
        self._cache = {}
        self._last_request = 0
        self._rate_limit_delay = 1.5  # Segundos entre requests
    
    def _respect_rate_limit(self):
        """Respeita rate limit da API (1.5s entre requests)"""
        elapsed = time.time() - self._last_request
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)
        self._last_request = time.time()
    
    def check_email(self, email: str) -> Dict[str, Any]:
        """
        Verifica se um e-mail foi comprometido
        
        Args:
            email: Endereço de e-mail a verificar
        
        Returns:
            Dict com breaches encontradas
        """
        # Validar formato de e-mail
        if '@' not in email or '.' not in email.split('@')[1]:
            return {
                'email': email,
                'status': 'invalid_email',
                'breaches': [],
                'error': 'Formato de e-mail inválido'
            }
        
        # Verificar cache
        cache_key = f"email_{email.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        result = {
            'email': email,
            'status': 'checking',
            'breaches': [],
            'total_breaches': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            self._respect_rate_limit()
            
            # Endpoint: /breachedaccount/{account}
            url = f"{self.BASE_URL}/breachedaccount/{email}"
            
            response = requests.get(
                url,
                headers=self.HEADERS,
                timeout=15
            )
            
            if response.status_code == 200:
                # E-mail encontrado em breaches
                breaches_data = response.json()
                
                result['breaches'] = [
                    {
                        'name': breach.get('Name'),
                        'title': breach.get('Title'),
                        'domain': breach.get('Domain'),
                        'breach_date': breach.get('BreachDate'),
                        'added_date': breach.get('AddedDate'),
                        'pwn_count': breach.get('PwnCount'),
                        'description': breach.get('Description', ''),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified'),
                        'is_sensitive': breach.get('IsSensitive')
                    }
                    for breach in breaches_data
                ]
                
                result['total_breaches'] = len(result['breaches'])
                result['status'] = 'compromised'
                
            elif response.status_code == 404:
                # E-mail não encontrado em breaches
                result['status'] = 'clean'
                result['total_breaches'] = 0
                
            elif response.status_code == 401:
                result['status'] = 'api_key_required'
                result['error'] = 'API key necessária para consultas de e-mail'
                
            elif response.status_code == 429:
                result['status'] = 'rate_limited'
                result['error'] = 'Rate limit excedido, tente novamente em alguns segundos'
                
            else:
                result['status'] = 'error'
                result['error'] = f'HTTP {response.status_code}'
            
            # Cachear resultado
            self._cache[cache_key] = result
            
        except requests.RequestException as e:
            result['status'] = 'error'
            result['error'] = f'Erro de conexão: {str(e)}'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def check_password(self, password: str) -> Dict[str, Any]:
        """
        Verifica se uma senha foi comprometida usando k-anonymity
        
        Args:
            password: Senha a verificar
        
        Returns:
            Dict com resultado da verificação
        """
        result = {
            'status': 'checking',
            'compromised': False,
            'times_seen': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Hash SHA-1 da senha
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Pegar os primeiros 5 caracteres (k-anonymity)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Verificar cache
            cache_key = f"pwd_{prefix}"
            
            # Consultar API de Passwords (não requer API key)
            self._respect_rate_limit()
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # Procurar o sufixo na resposta
                hashes = response.text.split('\r\n')
                
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        
                        if hash_suffix == suffix:
                            result['compromised'] = True
                            result['times_seen'] = int(count)
                            result['status'] = 'compromised'
                            break
                
                if not result['compromised']:
                    result['status'] = 'clean'
                    
            else:
                result['status'] = 'error'
                result['error'] = f'HTTP {response.status_code}'
                
        except requests.RequestException as e:
            result['status'] = 'error'
            result['error'] = f'Erro de conexão: {str(e)}'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result


# Funções standalone para facilitar uso
def check_email_breach(email: str, api_key: str = None) -> Dict[str, Any]:
    """
    Wrapper para verificação de e-mail
    """
    checker = BreachChecker(api_key)
    return checker.check_email(email)


def check_password_breach(password: str) -> Dict[str, Any]:
    """
    Wrapper para verificação de senha
    """
    checker = BreachChecker()
    return checker.check_password(password)


def get_breach_results_for_scanner(email: str, api_key: str = None) -> List[Dict[str, str]]:
    """
    Retorna resultados formatados para o scanner do Validador SEC
    
    Args:
        email: E-mail a verificar (extraído do domínio ou fornecido)
        api_key: Chave API HIBP
    
    Returns:
        Lista de dicts no formato do scanner
    """
    result = check_email_breach(email, api_key)
    scanner_results = []
    
    if result['status'] == 'compromised':
        total = result['total_breaches']
        
        # Resultado principal - Formato HTML rico
        breaches_preview = result['breaches'][:3]  # Primeiros 3
        
        details_html = f"""
        <strong>🚨 E-MAIL ENCONTRADO EM VAZAMENTOS PÚBLICOS</strong><br>
        <div style='margin-top: 10px; padding: 10px; background: rgba(255, 56, 96, 0.1); border-left: 3px solid #ff3860; border-radius: 4px;'>
           ⚠️ <strong>ALERTA CRÍTICO:</strong> Este e-mail foi exposto em <span style='color: #ff3860; font-size: 1.1em;'>{total}</span> vazamento(s) de dados!
        </div>
        <br>
        <strong>📊 Vazamentos Mais Críticos:</strong><br>
        """
        
        for i, breach in enumerate(breaches_preview, 1):
            verified_badge = "✅ Verificado" if breach.get('is_verified') else "⚠️ Não verificado"
            pwn_count = breach.get('pwn_count', 0)
            
            details_html += f"""
            <div style='margin-top: 8px; padding: 10px; background: rgba(255, 85, 85, 0.08); border-left: 2px solid #ff5555; border-radius: 3px;'>
                <strong>{i}. {breach.get('title', 'Desconhecido')}</strong> {verified_badge}<br>
                <div style='padding-left: 15px; margin-top: 5px; font-size: 0.9em;'>
                    📅 <strong>Data do vazamento:</strong> {breach.get('breach_date', 'N/A')}<br>
                    🌐 <strong>Domínio:</strong> {breach.get('domain', 'N/A')}<br>
                    👥 <strong>Contas afetadas:</strong> <span style='color: #ff5555;'>{pwn_count:,}</span> contas<br>
                    📦 <strong>Dados expostos:</strong> {', '.join(breach.get('data_classes', [])[:6])}<br>
                </div>
            </div>
            """
        
        if total > 3:
            details_html += f"""
            <div style='margin-top: 8px; padding: 8px; background: rgba(255, 160, 0, 0.1); border-radius: 3px; text-align: center;'>
                ⚠️ +{total - 3} vazamento(s) adicional(is) encontrado(s)
            </div>
            """
        
        scanner_results.append({
            'vulnerability': f'📧 E-mail em Vazamentos Públicos ({total})',
            'status': 'Vulnerable',
            'severity': 'Critical' if total > 10 else 'High' if total > 5 else 'Medium',
            'category': 'Vazamentos',
            'details': details_html,
            'recommendation': '🔐 AÇÃO IMEDIATA: (1) Trocar senha em TODAS as contas que usam este e-mail, (2) Habilitar autenticação de dois fatores (2FA), (3) Monitorar atividades suspeitas'
        })
    
    elif result['status'] == 'clean':
        scanner_results.append({
            'vulnerability': '📧 Verificação de Vazamentos',
            'status': 'Safe',
            'severity': 'Info',
            'category': 'Vazamentos',
            'details': """
            <strong>✅ E-MAIL NÃO ENCONTRADO EM VAZAMENTOS</strong><br>
            <div style='margin-top: 10px; padding: 10px; background: rgba(0, 255, 157, 0.1); border-left: 3px solid #00ff9d; border-radius: 4px;'>
                ✨ <strong>Boas notícias!</strong> Este e-mail não foi encontrado em vazamentos públicos conhecidos<br>
                pelo banco de dados do <strong>HaveIBeenPwned</strong> (<span style='font-size: 0.9em;'>maior base pública de vazamentos</span>)
            </div>
            <br>
            <div style='font-size: 0.9em; color: #94a3b8;'>
                💡 <strong>Dica:</strong> Continue mantendo boas práticas de segurança como senhas fortes e únicas para cada serviço
            </div>
            """,
            'recommendation': '✅ Continue mantendo boas práticas de segurança'
        })
    
    elif result['status'] == 'api_key_required':
        scanner_results.append({
            'vulnerability': '🔑 Verificação de Vazamentos (API Key Necessária)',
            'status': 'Info',
            'severity': 'Info',
            'category': 'Vazamentos',
            'details': """
            <strong>ℹ️ API KEY NECESSÁRIA</strong><br>
            <div style='margin-top: 10px; padding: 10px; background: rgba(0, 170, 255, 0.1); border-left: 3px solid #00aaff; border-radius: 4px;'>
                Para verificar se este e-mail foi comprometido, é necessário configurar uma chave de API do <strong>HaveIBeenPwned</strong>
            </div>
            <br>
            <strong>📝 Como configurar:</strong><br>
            <div style='margin-top: 5px; padding-left: 15px; font-family: monospace; font-size: 0.9em;'>
                1. Obtenha uma chave em: <a href='https://haveibeenpwned.com/API/Key' target='_blank' style='color: #00aaff;'>haveibeenpwned.com/API/Key</a><br>
                2. Configure a variável de ambiente:<br>
                   <code style='background: #1a1d29; padding: 2px 6px; border-radius: 3px;'>set HIBP_API_KEY=sua-chave-aqui</code>
            </div>
            """,
            'recommendation': 'Configure HIBP_API_KEY para habilitar verificação de vazamentos'
        })
    
    elif result['status'] == 'error':
        scanner_results.append({
            'vulnerability': '⚠️ Verificação de Vazamentos',
            'status': 'Error',
            'severity': 'Info',
            'category': 'Vazamentos',
            'details': f"""
            <strong>⚠️ ERRO NA VERIFICAÇÃO</strong><br>
            <div style='margin-top: 10px; padding: 10px; background: rgba(255, 160, 0, 0.1); border-left: 3px solid #ffaa00; border-radius: 4px;'>
                Não foi possível consultar o banco de dados de vazamentos
            </div>
            <br>
            <div style='padding-left: 15px; font-size: 0.9em;'>
                🔴 <strong>Erro:</strong> {result.get('error', 'Desconhecido')}<br>
                <br>
                <strong>Possíveis causas:</strong><br>
                • Conexão com internet instável<br>
                • Rate limit da API excedido<br>
                • Serviço temporariamente indisponível
            </div>
            """,
            'recommendation': 'Verifique a conexão com internet e tente novamente em alguns minutos'
        })
    
    return scanner_results


if __name__ == '__main__':
    # Teste rápido
    print("🧪 Testando Verificador de Vazamentos...\n")
    
    # Teste de senha (não requer API key)
    print("1️⃣ Testando senha 'password123':")
    pwd_result = check_password_breach('password123')
    print(f"   Status: {pwd_result['status']}")
    if pwd_result['compromised']:
        print(f"   ⚠️ Senha comprometida! Vista {pwd_result['times_seen']:,} vezes em vazamentos")
    else:
        print(f"   ✅ Senha não encontrada em vazamentos")
    
    print("\n2️⃣ Testando e-mail (pode requerer API key):")
    print("   Nota: Teste manual com e-mail real se tiver API key configurada")
    
    # Exemplo de uso
    # result = check_email_breach('test@example.com', api_key='YOUR_KEY')
    # print(f"   Breaches: {result['total_breaches']}")
