"""
Motor OSINT - Open Source Intelligence
Sistema inteligente para investigações modulares
"""

from typing import Dict, List, Any, Callable
from datetime import datetime
import json


class OsintEngine:
    """
    Motor de investigação OSINT com suporte a múltiplas missões
    """
    
    # Tipos de missão suportados
    MISSION_TYPES = {
        'email': 'Investigação de E-mail',
        'domain': 'Auditoria de Domínio',
        'phishing': 'Detecção de Phishing',
        'person': 'Investigação de Pessoa',
        'phone': 'Análise de Telefone'
    }
    
    def __init__(self, mission_type: str, target: str, options: Dict[str, Any] = None):
        """
        Inicializa o motor OSINT
        
        Args:
            mission_type: Tipo de missão ('email', 'domain', 'phishing', 'person', 'phone')
            target: Alvo da investigação
            options: Opções adicionais da missão
        """
        if mission_type not in self.MISSION_TYPES:
            raise ValueError(f"Tipo de missão inválido: {mission_type}")
        
        self.mission_type = mission_type
        self.target = target
        self.options = options or {}
        self.results = {}
        self.progress_callback: Callable[[int, str], None] = None
        self.status = 'initialized'
        self.start_time = None
        self.end_time = None
    
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        """Define callback para updates de progresso"""
        self.progress_callback = callback
    
    def _update_progress(self, percent: int, message: str):
        """Atualiza progresso da investigação"""
        if self.progress_callback:
            try:
                self.progress_callback(percent, message)
            except:
                pass
    
    def execute_mission(self) -> Dict[str, Any]:
        """
        Executa a missão selecionada
        
        Returns:
            Dict com resultados completos da investigação
        """
        self.start_time = datetime.now()
        self.status = 'running'
        self._update_progress(0, 'Iniciando investigação...')
        
        try:
            # Mapear missão para método
            mission_methods = {
                'email': self._investigate_email,
                'domain': self._audit_domain,
                'phishing': self._detect_phishing,
                'person': self._investigate_person,
                'phone': self._analyze_phone
            }
            
            # Executar missão
            mission_func = mission_methods[self.mission_type]
            self.results = mission_func()
            
            # Finalizar
            self.end_time = datetime.now()
            self.status = 'completed'
            self._update_progress(100, 'Investigação concluída!')
            
            # Adicionar metadata
            self.results['metadata'] = {
                'mission_type': self.mission_type,
                'mission_name': self.MISSION_TYPES[self.mission_type],
                'target': self.target,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration_seconds': (self.end_time - self.start_time).total_seconds(),
                'status': self.status
            }
            
            return self.results
            
        except Exception as e:
            self.status = 'error'
            self.end_time = datetime.now()
            self._update_progress(100, f'Erro: {str(e)}')
            
            return {
                'error': str(e),
                'status': 'error',
                'metadata': {
                    'mission_type': self.mission_type,
                    'target': self.target,
                    'start_time': self.start_time.isoformat() if self.start_time else None,
                    'end_time': self.end_time.isoformat(),
                    'status': 'error'
                }
            }
    
    # ==========================================
    # MISSÕES INDIVIDUAIS
    # ==========================================
    
    def _investigate_email(self) -> Dict[str, Any]:
        """
        Missão 1: Investigação de E-mail
        """
        from modules.breach_checker import check_email_breach, check_password_breach
        import os
        
        self._update_progress(10, 'Validando formato do e-mail...')
        
        result = {
            'email': self.target,
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        # Validação básica
        if '@' not in self.target:
            result['error'] = 'Formato de e-mail inválido'
            return result
        
        # 1. Verificar vazamentos
        self._update_progress(30, 'Consultando base de vazamentos...')
        api_key = os.environ.get('HIBP_API_KEY')
        breach_result = check_email_breach(self.target, api_key)
        
        if breach_result['status'] == 'compromised':
            result['findings'].append({
                'type': 'data_breach',
                'severity': 'high',
                'title': 'E-mail encontrado em vazamentos',
                'description': f"{breach_result['total_breaches']} vazamento(s) detectado(s)",
                'data': breach_result['breaches']
            })
            result['recommendations'].append('Trocar senha imediatamente em todas as contas associadas')
            result['recommendations'].append('Habilitar autenticação de dois fatores (2FA)')
        elif breach_result['status'] == 'clean':
            result['findings'].append({
                'type': 'data_breach',
                'severity': 'info',
                'title': 'Verificação de vazamentos',
                'description': 'E-mail não encontrado em vazamentos públicos conhecidos'
            })
        
        # 1.5 Verificar Gravatar (Profile Pic)
        try:
            import hashlib
            import requests
            email_md5 = hashlib.md5(self.target.strip().lower().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_md5}?d=404"
            
            r = requests.get(gravatar_url, timeout=3)
            if r.status_code == 200:
                result['findings'].append({
                    'type': 'social_profile',
                    'title': 'Perfil Gravatar (Foto Pública)',
                    'description': 'Avatar público encontrado.',
                    'severity': 'info',
                    'data': {
                        'image_url': gravatar_url,
                        'profile_url': f"https://en.gravatar.com/{email_md5}",
                        'platform': 'Gravatar'
                    }
                })
        except:
            pass
        
        # 2. Extrair domínio e validar
        self._update_progress(60, 'Analisando domínio do e-mail...')
        domain = self.target.split('@')[1]
        
        from modules.domain_validator import validate_domain
        domain_info = validate_domain(domain)
        
        result['findings'].append({
            'type': 'domain_info',
            'severity': 'info',
            'title': 'Informações do Domínio',
            'description': f"Análise do domínio {domain}",
            'data': {
                'domain': domain,
                'dns': domain_info.get('dns'),
                'ssl': domain_info.get('ssl'),
                'geo': domain_info.get('geo_ip')
            }
        })
        
        # 3. Username search (opcional - se habilitado)
        if self.options.get('search_username'):
            self._update_progress(80, 'Buscando username em redes sociais (Sherlock/Maigret)...')
            username = self.target.split('@')[0]
            
            # Executar Sherlock
            self._update_progress(85, f'Sherlock analisando "{username}"...')
            sherlock_res = self._run_sherlock(username)
            if sherlock_res['available']:
                result['findings'].append({
                    'type': 'sherlock_scan',
                    'severity': 'info',
                    'title': f'🕵️ Sherlock Scan: {username}',
                    'description': sherlock_res['description'],
                    'data': sherlock_res
                })
            
            # Executar Maigret
            self._update_progress(90, f'Maigret analisando "{username}"...')
            maigret_res = self._run_maigret(username)
            if maigret_res['available']:
                result['findings'].append({
                    'type': 'maigret_scan',
                    'severity': 'info',
                    'title': f'🕵️ Maigret Scan: {username}',
                    'description': maigret_res['description'],
                    'data': maigret_res
                })
        
        # Summary
        result['summary'] = {
            'total_findings': len(result['findings']),
            'total_breaches': breach_result.get('total_breaches', 0),
            'risk_level': 'high' if breach_result.get('total_breaches', 0) > 0 else 'low'
        }
        
        self._update_progress(100, 'Investigação de e-mail concluída')
        return result
    
    def _audit_domain(self) -> Dict[str, Any]:
        """
        Missão 2: Auditoria de Domínio
        """
        from modules.domain_validator import validate_domain
        from modules.phishing_detector import detect_phishing
        
        self._update_progress(10, 'Iniciando auditoria de domínio...')
        
        result = {
            'domain': self.target,
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        # 1. Validação completa de domínio
        self._update_progress(30, 'Coletando informações WHOIS, DNS e SSL...')
        domain_data = validate_domain(self.target)
        
        # SSL Analysis
        ssl = domain_data.get('ssl', {})
        if ssl.get('status') == 'valid':
            days_remaining = ssl.get('days_remaining', 0)
            severity = 'info' if days_remaining > 30 else 'warning'
            
            result['findings'].append({
                'type': 'ssl_certificate',
                'severity': severity,
                'title': 'Certificado SSL/TLS',
                'description': f"Válido por mais {days_remaining} dias",
                'data': ssl
            })
            
            if days_remaining < 30:
                result['recommendations'].append('Renovar certificado SSL em breve')
        else:
            result['findings'].append({
                'type': 'ssl_certificate',
                'severity': 'critical',
                'title': 'Certificado SSL Inválido',
                'description': ssl.get('error', 'Erro desconhecido'),
                'data': ssl
            })
            result['recommendations'].append('Instalar certificado SSL válido imediatamente')
        
        # DNS Analysis
        self._update_progress(50, 'Analisando registros DNS...')
        dns = domain_data.get('dns', {})
        result['findings'].append({
            'type': 'dns_records',
            'severity': 'info',
            'title': 'Resolução DNS',
            'description': f"IP(s): {', '.join(dns.get('A', []) or [])}",
            'data': dns
        })
        
        # Subdomains (Se disponíveis)
        subdomains = domain_data.get('subdomains', [])
        if subdomains:
            result['findings'].append({
                'type': 'subdomain_enumeration',
                'severity': 'info',
                'title': f'Subdomínios Encontrados ({len(subdomains)})',
                'description': f"Enumeração passiva detectou {len(subdomains)} subdomínios",
                'data': {'subdomains': subdomains}
            })
        
        # Geo-IP
        geo = domain_data.get('geo_ip', {})
        if geo.get('status') == 'success':
            result['findings'].append({
                'type': 'geolocation',
                'severity': 'info',
                'title': 'Localização do Servidor',
                'description': f"{geo.get('city')}, {geo.get('country')}",
                'data': geo
            })
        
        # 2. Análise de Phishing
        self._update_progress(70, 'Verificando indicadores de phishing...')
        phishing_data = detect_phishing(self.target)
        
        if phishing_data['is_suspicious']:
            result['findings'].append({
                'type': 'phishing_indicators',
                'severity': phishing_data['risk_level'],
                'title': 'Indicadores de Phishing Detectados',
                'description': f"Score de risco: {phishing_data['risk_score']}/100",
                'data': phishing_data
            })
            result['recommendations'].append('Verificar legitimidade do domínio antes de interagir')
        
        # 3. Subdomains (se habilitado)
        
        # Summary
        result['summary'] = {
            'total_findings': len(result['findings']),
            'ssl_valid': ssl.get('status') == 'valid',
            'dns_resolves': bool(dns.get('A')),
            'is_suspicious': phishing_data['is_suspicious'],
            'risk_score': phishing_data['risk_score']
        }
        
        self._update_progress(100, 'Auditoria de domínio concluída')
        return result
    
    def _detect_phishing(self) -> Dict[str, Any]:
        """
        Missão 3: Detecção de Phishing / Takedown
        """
        from modules.phishing_detector import PhishingDetector
        
        self._update_progress(10, 'Analisando domínio suspeito...')
        
        detector = PhishingDetector()
        result = {
            'target': self.target,
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        # 1. Análise de phishing
        self._update_progress(30, 'Verificando indicadores de phishing...')
        phishing_data = detector.detect_phishing(self.target)
        
        result['findings'].append({
            'type': 'phishing_analysis',
            'severity': phishing_data['risk_level'],
            'title': 'Análise de Phishing',
            'description': f"Score: {phishing_data['risk_score']}/100",
            'data': phishing_data
        })
        
        # 2. Gerar variações de typosquatting
        self._update_progress(60, 'Gerando variações de typosquatting...')
        variations = detector.generate_typosquatting_variations(self.target)
        
        result['findings'].append({
            'type': 'typosquatting',
            'severity': 'info',
            'title': 'Variações de Typosquatting',
            'description': f"{len(variations)} variações geradas",
            'data': {'variations': variations[:20]}  # Limitar a 20
        })
        
        # 3. Recomendações
        if phishing_data['is_suspicious']:
            result['recommendations'].append('Domínio apresenta características suspeitas')
            result['recommendations'].append('Evitar fornecer credenciais ou dados pessoais')
            result['recommendations'].append('Verificar URL cuidadosamente antes de clicar')
        
        # Summary
        result['summary'] = {
            'is_suspicious': phishing_data['is_suspicious'],
            'risk_score': phishing_data['risk_score'],
            'risk_level': phishing_data['risk_level'],
            'total_variations': len(variations)
        }
        
        self._update_progress(100, 'Análise de phishing concluída')
        return result
    
    def _investigate_person(self) -> Dict[str, Any]:
        """
        Missão 4: Investigação de Pessoa/Username
        """
        self._update_progress(10, 'Iniciando investigação...')
        
        result = {
            'target': self.target,
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        # 1. Validação de username/nome
        self._update_progress(15, 'Analisando username...')
        
        # SANITIZAÇÃO AUTOMÁTICA
        original_target = self.target
        username = self.target.strip().lower()
        cleaned_username = ''.join(c for c in username if c.isalnum() or c in '._-')
        
        if username != cleaned_username:
            username = cleaned_username
            self.target = username  # Atualiza target global para ferramentas usarem
            result['findings'].append({
                'type': 'autocorrect',
                'severity': 'warning',
                'title': 'Auto-Preenchimento',
                'description': f'O alvo continha caracteres inválidos para username (espaços/símbolos).',
                'data': {
                    'original': original_target,
                    'cleaned': username,
                    'message': 'Espaços removidos automaticamente para análise.'
                }
            })
        
        # Análise básica do username
        result['findings'].append({
            'type': 'username_analysis',
            'severity': 'info',
            'title': 'Análise de Username',
            'description': f'Username analisado: {username}',
            'data': {
                'length': len(username),
                'has_numbers': any(c.isdigit() for c in username),
                'has_special': any(not c.isalnum() and c != '_' for c in username),
                'common_patterns': self._detect_username_patterns(username)
            }
        })
        
        # 2. Tentar usar Sherlock (se instalado)
        self._update_progress(25, 'Verificando Sherlock...')
        sherlock_results = self._run_sherlock(username)
        
        if sherlock_results['available']:
            result['findings'].append({
                'type': 'sherlock_scan',
                'severity': 'info',
                'title': '🔍 Sherlock - Busca Avançada',
                'description': sherlock_results['description'],
                'data': sherlock_results
            })
        
        # 3. Tentar usar Maigret (se instalado)
        self._update_progress(40, 'Verificando Maigret...')
        maigret_results = self._run_maigret(username)
        
        if maigret_results['available']:
            result['findings'].append({
                'type': 'maigret_scan',
                'severity': 'info',
                'title': '🔍 Maigret - Busca Profunda',
                'description': maigret_results['description'],
                'data': maigret_results
            })
        
        # 4. Busca manual em redes sociais (fallback se ferramentas não disponíveis)
        if not sherlock_results['available'] and not maigret_results['available']:
            self._update_progress(50, 'Buscando manualmente em redes sociais...')
            social_networks = {
                'GitHub': f'https://github.com/{username}',
                'Twitter': f'https://twitter.com/{username}',
                'Instagram': f'https://instagram.com/{username}',
                'LinkedIn': f'https://linkedin.com/in/{username}',
                'Facebook': f'https://facebook.com/{username}',
                'Reddit': f'https://reddit.com/user/{username}',
                'YouTube': f'https://youtube.com/@{username}',
                'TikTok': f'https://tiktok.com/@{username}'
            }
            
            detected_profiles = []
            for network, url in social_networks.items():
                try:
                    import requests
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    
                    if response.status_code in [200, 301, 302]:
                        detected_profiles.append({
                            'network': network,
                            'url': url,
                            'status': 'possibly_exists'
                        })
                except:
                    pass  # Ignora erros de conexão
            
            if detected_profiles:
                result['findings'].append({
                    'type': 'manual_search',
                    'severity': 'info',
                    'title': 'Busca Manual em Redes Sociais',
                    'description': f'{len(detected_profiles)} perfil(is) possivelmente encontrado(s)',
                    'data': {'profiles': detected_profiles}
                })
        
        # 5. Padrões detectados
        self._update_progress(80, 'Analisando padrões...')
        patterns = self._detect_username_patterns(username)
        if patterns:
            result['findings'].append({
                'type': 'pattern_analysis',
                'severity': 'info',
                'title': 'Padrões Detectados',
                'description': f'{len(patterns)} padrão(ões) detectado(s)',
                'data': {'patterns': patterns, 'username': username}
            })
        
        # 6. Recomendações
        if not sherlock_results['available'] and not maigret_results['available']:
            result['recommendations'].append('💡 Para investigação mais completa, instale Sherlock ou Maigret:')
            result['recommendations'].append('   pip install sherlock-project')
            result['recommendations'].append('   pip install maigret')
        
        result['recommendations'].append('Sempre verifique manualmente os perfis encontrados')
        
        # Summary
        total_profiles = 0
        if sherlock_results['available']:
            total_profiles += sherlock_results.get('profiles_found', 0)
        if maigret_results['available']:
            total_profiles += maigret_results.get('profiles_found', 0)
        
        result['summary'] = {
            'username': username,
            'sherlock_available': sherlock_results['available'],
            'maigret_available': maigret_results['available'],
            'total_profiles_found': total_profiles,
            'status': 'completed'
        }
        
        # 7. Verificação Manual Obrigatória
        result['findings'].append({
            'type': 'manual_verification',
            'severity': 'warning',
            'title': '⚠️ Verificação Manual (Anti-Bot)',
            'description': 'Redes que bloqueiam bots ativamente. Verifique clicando abaixo:',
            'data': {'username': username}
        })
        
        self._update_progress(100, 'Investigação de pessoa concluída')
        return result
    
    def _run_sherlock(self, username: str) -> Dict[str, Any]:
        """Executa Sherlock via módulo Python (Versão Permissiva & Debug)"""
        result = {'available': False, 'profiles': [], 'description': '', 'error': None}
        
        username = username.strip().replace(' ', '')
        if not username: return result
        
        try:
            import subprocess
            import sys
            import os
            import json
            
            # Configurar ENV para forçar UTF-8 e evitar crash em emoji
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            
            # Aumentei timeout por site para 15s e removi output file por enquanto (confiar no stdout)
            cmd = [sys.executable, '-m', 'sherlock_project', username, '--print-found', '--timeout', '5']
            
            # Executar com timeout global generoso
            process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180, env=env)
            
            # EM OSINT, returncode != 0 não significa zero resultados. Vamos ler o output sempre.
            result['available'] = True # Se rodou, está disponível
            
            # Parsear STDOUT
            profiles = []
            output_lines = process.stdout.split('\n')
            for line in output_lines:
                # Formato: "[+] Site: URL"
                if '[+]' in line and ': ' in line:
                    parts = line.split(': ', 1)
                    if len(parts) >= 2:
                        site = parts[0].replace('[+]', '').strip()
                        url = parts[1].strip()
                        profiles.append({'site': site, 'url': url, 'status': 'found'})
            
            result['profiles'] = profiles
            result['profiles_found'] = len(profiles)
            
            if profiles:
                result['description'] = f'✅ Sherlock encontrou {len(profiles)} perfil(is)'
            else:
                # Se não achou nada, mostrar DEBUG para o usuário entender o porquê
                debug_msg = process.stderr[:300] if process.stderr else "Sem output de erro"
                if "ConnectionError" in debug_msg: debug_msg = "Problemas de Conexão com sites"
                result['description'] = f'⚠️ Sherlock rodou mas não achou perfis. (Log: {debug_msg})'
                # Se erro critico
                if process.returncode != 0:
                    result['error'] = f"Exit Code {process.returncode}. Log: {debug_msg}"

        except Exception as e:
            result['error'] = f"Erro Execução: {str(e)}"
            
        return result

    def _run_maigret(self, username: str) -> Dict[str, Any]:
        """Executa Maigret via módulo Python (Versão Permissiva & Debug)"""
        result = {'available': False, 'profiles': [], 'description': '', 'error': None}
        
        username = username.strip().replace(' ', '')
        if not username: return result
        
        try:
            import sys
            import subprocess
            import glob
            import os
            import json
            
            # --json simple gera na pasta atual
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            
            cmd = [sys.executable, '-m', 'maigret', username, '--json', 'simple', '--timeout', '10', '--max-connections', '50', '--no-progressbar', '--retries', '1']
            
            process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=240, env=env) # 4 min max

            # Maigret costuma retornar erro se 1 site falhar. Ignorar returncode se tiver JSON.
            result['available'] = True
            
            # 1. Tentar achar JSON (Método Preferido)
            # O Maigret pode gerar report_<username>.json ou report_<username>_<timestamp>.json
            list_of_files = glob.glob(f'report_{username}*.json')
            
            profiles = []
            if list_of_files:
                # Pegar o mais recente
                latest_file = max(list_of_files, key=os.path.getctime)
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Adaptação para múltiplos formatos do Maigret
                        for key, info in data.items():
                            # Formato dict aninhado
                            if isinstance(info, dict):
                                url = info.get('url_user') or info.get('url')
                                status = info.get('status')
                                # As vezes status fica dentro de um sub-dict 'status'
                                if isinstance(status, dict): status = status.get('status')
                                
                                if (status == 'found' or status == 'claim') and url:
                                    profiles.append({'site': key, 'url': url, 'status': 'found'})
                            
                    # Tentar limpar
                    os.remove(latest_file)
                except:
                    pass

            # 2. Fallback: STDOUT Melhorado
            if not profiles:
                 for line in process.stdout.split('\n'):
                     line = line.strip()
                     # Formato: "[+] Facebook: https://..."
                     if line.startswith('[+]') and ': ' in line:
                         try:
                             # Remove '[+] ' e separa no primeiro ': '
                             content = line.replace('[+]', '').strip()
                             site_name, url = content.split(': ', 1)
                             # Limpar URL (as vezes vem com infos extras)
                             url = url.split(' ')[0] 
                             profiles.append({'site': site_name, 'url': url, 'status': 'found'})
                         except:
                             continue

            result['profiles'] = profiles
            result['profiles_found'] = len(profiles)
            
            if profiles:
                result['description'] = f'✅ Maigret encontrou {len(profiles)} perfil(is)'
            else:
                 debug_msg = process.stderr[:300] if process.stderr else (process.stdout[:300] if process.stdout else "Sem output")
                 result['description'] = f'⚠️ Maigret terminou sem confirmar perfis. (Log: {debug_msg})'

        except Exception as e:
            result['error'] = f"Erro Execução: {str(e)}"
            
        return result
    
    def _detect_username_patterns(self, username: str) -> List[str]:
        """Detect username patterns"""
        patterns = []
        
        if any(year in username for year in ['19', '20']):
            patterns.append('Possível ano de nascimento no username')
        
        if len(username) < 4:
            patterns.append('Username muito curto (baixa complexidade)')
        
        if username.isdigit():
            patterns.append('Username apenas numérico')
        
        if '_' in username or '.' in username:
            patterns.append('Username com separadores (_, .)')
        
        common_words = ['admin', 'root', 'user', 'test', 'master', 'super']
        if any(word in username.lower() for word in common_words):
            patterns.append('Contém palavra comum (admin, root, etc)')
        
        return patterns
    
    def _analyze_phone(self) -> Dict[str, Any]:
        """
        Missão 5: Análise de Telefone
        """
        self._update_progress(10, 'Analisando número de telefone...')
        
        result = {
            'target': self.target,
            'findings': [],
            'summary': {},
            'recommendations': []
        }
        
        # Tentar usar phonenumbers (biblioteca completa)
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier, timezone
            
            self._update_progress(20, 'Usando phonenumbers para análise completa...')
            
            # Parse do número
            try:
                # Tentar parse com país padrão (Brasil)
                try:
                    parsed = phonenumbers.parse(self.target, "BR")
                except:
                    # Tentar sem país padrão
                    parsed = phonenumbers.parse(self.target, None)
                
                # Validação
                is_valid = phonenumbers.is_valid_number(parsed)
                is_possible = phonenumbers.is_possible_number(parsed)
                
                # Informações básicas
                country_code = parsed.country_code
                national_number = parsed.national_number
                
                # Formatações
                e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                international = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                
                # Região/País
                region_code = phonenumbers.region_code_for_number(parsed)
                location = geocoder.description_for_number(parsed, "pt_BR")
                
                # Operadora (carrier)
                operator = carrier.name_for_number(parsed, "pt_BR")
                
                # Tipo de número
                number_type = phonenumbers.number_type(parsed)
                type_names = {
                    phonenumbers.PhoneNumberType.MOBILE: 'Celular',
                    phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixo',
                    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixo ou Celular',
                    phonenumbers.PhoneNumberType.TOLL_FREE: 'Número Gratuito',
                    phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Número Premium',
                    phonenumbers.PhoneNumberType.VOIP: 'VoIP',
                    phonenumbers.PhoneNumberType.UNKNOWN: 'Desconhecido'
                }
                phone_type = type_names.get(number_type, 'Desconhecido')
                
                # Timezone
                timezones = timezone.time_zones_for_number(parsed)
                
                # Adicionar resultado principal
                result['findings'].append({
                    'type': 'phonenumbers_analysis',
                    'severity': 'info',
                    'title': '📱 Análise Completa com PhoneNumbers',
                    'description': f'Número analisado e validado com sucesso',
                    'data': {
                        'is_valid': is_valid,
                        'is_possible': is_possible,
                        'country_code': f'+{country_code}',
                        'region': region_code,
                        'location': location or 'Não disponível',
                        'operator': operator or 'Não identificado',
                        'type': phone_type,
                        'formats': {
                            'e164': e164,
                            'international': international,
                            'national': national
                        },
                        'timezones': list(timezones) if timezones else []
                    }
                })
                
                # Validação
                if is_valid:
                    result['findings'].append({
                        'type': 'validation',
                        'severity': 'info',
                        'title': 'Validação de Número',
                        'description': '✅ Número válido e ativo',
                        'data': {
                            'is_valid': True,
                            'is_possible': is_possible
                        }
                    })
                else:
                    result['findings'].append({
                        'type': 'validation',
                        'severity': 'warning',
                        'title': 'Validação de Número',
                        'description': '⚠️ Número inválido ou incorreto',
                        'data': {
                            'is_valid': False,
                            'is_possible': is_possible
                        }
                    })
                
                # Summary
                result['summary'] = {
                    'is_valid': is_valid,
                    'country': region_code,
                    'location': location,
                    'operator': operator,
                    'type': phone_type,
                    'format': international,
                    'status': 'complete_analysis',
                    'tool': 'phonenumbers'
                }
                
                # Recomendações
                if not is_valid:
                    result['recommendations'].append('Verifique se o número está correto')
                if region_code == 'BR' and operator:
                    result['recommendations'].append(f'Operadora identificada: {operator}')
                
            except phonenumbers.NumberParseException as e:
                # Erro no parse do número
                result['findings'].append({
                    'type': 'parse_error',
                    'severity': 'warning',
                    'title': 'Erro ao Analisar Número',
                    'description': f'Não foi possível interpretar o número: {str(e)}',
                    'data': {
                        'error': str(e),
                        'provided_number': self.target
                    }
                })
                
                result['recommendations'].append('Verifique o formato do número')
                result['recommendations'].append('Use formato internacional: +XX XXXX-XXXX')
                
                result['summary'] = {
                    'status': 'parse_error',
                    'tool': 'phonenumbers'
                }
        
        except ImportError:
            # phonenumbers não instalado - análise básica
            self._update_progress(30, 'Fazendo análise básica...')
            
            # Limpar número (remover espaços, traços, parênteses)
            phone_clean = ''.join(c for c in self.target if c.isdigit() or c == '+')
            
            is_valid = False
            country = 'Desconhecido'
            phone_type = 'Desconhecido'
            
            # Análise básica de padrão brasileiro
            if phone_clean.startswith('+55') or phone_clean.startswith('55'):
                country = 'Brasil'
                clean_br = phone_clean.replace('+55', '').replace('55', '')
                
                if len(clean_br) == 11:  # Celular BR
                    is_valid = True
                    phone_type = 'Celular'
                    ddd = clean_br[:2]
                    result['findings'].append({
                        'type': 'phone_analysis',
                        'severity': 'info',
                        'title': 'Análise Básica de Número Brasileiro',
                       'description': f'DDD: {ddd}, Tipo: Celular',
                        'data': {
                            'country': country,
                            'ddd': ddd,
                            'type': phone_type,
                            'format': f'({ddd}) {clean_br[2]}{clean_br[3:7]}-{clean_br[7:]}'
                        }
                    })
                elif len(clean_br) == 10:  # Fixo BR
                    is_valid = True
                    phone_type = 'Fixo'
                    ddd = clean_br[:2]
                    result['findings'].append({
                        'type': 'phone_analysis',
                        'severity': 'info',
                        'title': 'Análise Básica de Número Brasileiro',
                        'description': f'DDD: {ddd}, Tipo: Fixo',
                        'data': {
                            'country': country,
                            'ddd': ddd,
                            'type': phone_type,
                            'format': f'({ddd}) {clean_br[2:6]}-{clean_br[6:]}'
                        }
                    })
            
            # Análise internacional genérica
            elif phone_clean.startswith('+'):
                country_code = phone_clean[1:3] if len(phone_clean) > 2 else phone_clean[1:]
                
                country_codes = {
                    '1': 'EUA/Canadá',
                    '44': 'Reino Unido',
                    '33': 'França',
                    '49': 'Alemanha',
                    '34': 'Espanha',
                    '39': 'Itália',
                    '351': 'Portugal',
                    '54': 'Argentina',
                    '52': 'México'
                }
                
                country = country_codes.get(country_code, f'Código +{country_code}')
                is_valid = len(phone_clean) >= 10
                
                result['findings'].append({
                    'type': 'phone_analysis',
                    'severity': 'info',
                    'title': 'Análise Básica Internacional',
                    'description': f'País/Região: {country}',
                    'data': {
                        'country': country,
                        'country_code': country_code,
                        'full_number': phone_clean
                    }
                })
            
            # Validação
            if is_valid:
                result['findings'].append({
                    'type': 'validation',
                    'severity': 'info',
                    'title': 'Validação de Formato',
                    'description': '✅ Formato reconhecido',
                    'data': {
                        'is_valid': True,
                        'cleaned_number': phone_clean
                    }
                })
            else:
                result['findings'].append({
                    'type': 'validation',
                    'severity': 'warning',
                    'title': 'Validação de Formato',
                    'description': '⚠️ Formato não reconhecido',
                    'data': {
                        'is_valid': False,
                        'provided_number': self.target
                    }
                })
            
            # Recomendações
            result['recommendations'].append('💡 Para análise completa, instale: pip install phonenumbers')
            result['recommendations'].append('Com phonenumbers você terá: operadora, região exata, validação real, etc')
            
            result['summary'] = {
                'is_valid': is_valid,
                'country': country,
                'type': phone_type,
                'cleaned': phone_clean,
                'status': 'basic_analysis',
                'tool': 'builtin'
            }
        
        self._update_progress(100, 'Análise de telefone concluída')
        return result


# Funções auxiliares
def execute_osint_mission(mission_type: str, target: str, options: Dict = None, 
                         progress_callback: Callable = None) -> Dict[str, Any]:
    """
    Wrapper para executar missão OSINT
    
    Args:
        mission_type: Tipo de missão
        target: Alvo da investigação
        options: Opções adicionais
        progress_callback: Função de callback para progresso
    
    Returns:
        Resultados da investigação
    """
    engine = OsintEngine(mission_type, target, options)
    
    if progress_callback:
        engine.set_progress_callback(progress_callback)
    
    return engine.execute_mission()


if __name__ == '__main__':
    # Teste rápido
    print("🔍 Testando Motor OSINT\n")
    
    def print_progress(percent, message):
        print(f"[{percent:3d}%] {message}")
    
    # Teste missão de e-mail
    print("1. Teste: Investigação de E-mail")
    result = execute_osint_mission(
        'email',
        'test@example.com',
        {'search_username': False},
        print_progress
    )
    print(f"   Resultados: {result['summary']}\n")
    
    # Teste missão de domínio
    print("2. Teste: Auditoria de Domínio")
    result = execute_osint_mission(
        'domain',
        'google.com',
        {'subdomain_enum': False},
        print_progress
    )
    print(f"   Resultados: {result['summary']}\n")
    
    print("✅ Testes concluídos!")
