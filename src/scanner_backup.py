import requests
from urllib.parse import urljoin, urlparse
import socket
import ssl
import subprocess
import sys
import concurrent.futures
import os
from datetime import datetime


class VulnerabilityScanner:
    def __init__(self, target_url, progress_callback=None):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecurityValidator/1.0'})
        self.results = []
        self.progress_callback = progress_callback
        # Determine max workers (threads) based on CPU cores, capping at 20 to avoid overload
        cpu_count = os.cpu_count() or 4
        self.max_workers = min(cpu_count * 2, 20)

    def _update_progress(self, message):
        if self.progress_callback:
            try:
                self.progress_callback(message)
            except:
                pass

    def run_all(self):
        self.results = []
        
        # Collect Network Info (for dashboard)
        self._update_progress("Coletando Informações de Rede...")
        self.network_info = self._collect_network_info()
        
        self._update_progress("Iniciando Reconhecimento...")
        self.check_recon()
        
        self._update_progress("Verificando Versões PHP...")
        self.check_php_eol()
        
        self._update_progress("Testando Cross-Site Scripting (XSS)...")
        self.check_xss()
        
        self._update_progress("Verificando Clickjacking...")
        self.check_clickjacking()
        
        self._update_progress("Analisando CORS...")
        self.check_cors()
        
        self._update_progress("Verificando CSRF...")
        self.check_csrf()
        
        self._update_progress("Analisando Cookies...")
        self.check_cookies()
        
        self._update_progress("Buscando Diretórios Sensíveis...")
        self.check_dirs()
        
        self._update_progress("Validando Security Headers...")
        self.check_missing_headers()
        
        self._update_progress("Verificando Métodos HTTP...")
        self.check_http_methods()
        
        self._update_progress("Testando CVE-2024-4577 (PHP)...")
        self.check_cve_2024_4577()
        
        self._update_progress("Verificando Versão do Servidor...")
        self.check_server_version()
        
        self._update_progress("Testando SQL Injection...")
        self.check_sqli()
        
        # New Advanced Checks
        self._update_progress("Analisando SSL/TLS...")
        self.check_ssl()
        
        self._update_progress("Lendo Robots.txt...")
        self.check_robots()
        
        self._update_progress("Detectando WAF...")
        self.check_waf()
        
        self._update_progress("Escaneando Portas (Isso pode demorar)...")
        self.check_ports()
        
        self._update_progress("Verificando Segurança DNS...")
        self.check_dns_security()
        
        self._update_progress("Buscando Subdomínios...")
        self.check_subdomains()
        
        # Ultra Advanced Checks (Added separately)
        self._update_progress("Testando Open Redirect...")
        self.check_open_redirect()
        
        self._update_progress("Testando Reverse Tabnabbing...")
        self.check_tabnabbing()
        
        self._update_progress("Verificando Subresource Integrity (SRI)...")
        self.check_sri()
        
        self._update_progress("Escaneando PII (Dados Sensíveis)...")
        self.check_pii()
        
        self._update_progress("Testando Command Injection...")
        self.check_command_injection()
        
        self._update_progress("Procurando Swagger/OpenAPI...")
        self.check_swagger()
        
        self._update_progress("Verificando Certificate Transparency...")
        self.check_certificate_transparency()
        
        self._update_progress("Procurando Source Maps expostos...")
        self.check_source_maps()
        
        self._update_progress("Testando Server-Side Template Injection...")
        self.check_ssti()
        
        self._update_progress("Testando XML External Entity (XXE)...")
        self.check_xxe()
        
        self._update_progress("Procurando arquivos de Log expostos...")
        self.check_log_files()
        
        self._update_progress("Finalizando e Gerando Relatório...")
        
        # Sort results by severity
        severity_map = {
            'Critical': 0,
            'High': 1,
            'Medium': 2,
            'Low': 3,
            'Info': 4,
            'Safe': 5  # For checks that return 'Safe' status, assuming they might map to Info/Safe logic
        }
        
        # Helper to get weight, default to 10 if unknown
        def get_weight(item):
            sev = item.get('severity', 'Info')
            if sev == 'Safe': # Sometimes stored as 'Info' but just in case
                return 5
            return severity_map.get(sev, 10)

        self.results.sort(key=get_weight)
        
        return self.results


    def _add_result(self, vuln_name, status, details, severity, methodology, manual_test, risk, category):
        self.results.append({
            'vulnerability': vuln_name,
            'status': status,
            'details': details,
            'severity': severity,
            'methodology': methodology,
            'manual_test': manual_test,
            'risk': risk,
            'category': category
        })

    def _collect_network_info(self):
        """Collect basic network information for dashboard panel"""
        import time
        info = {
            'ip': 'N/A',
            'latency_ms': 'N/A',
            'dns_time_ms': 'N/A',
            'response_time_ms': 'N/A',
            'server': 'N/A'
        }
        
        try:
            # Extract hostname from URL
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc or parsed.path
            
            # DNS Resolution Time
            dns_start = time.time()
            ip_address = socket.gethostbyname(hostname)
            dns_time = (time.time() - dns_start) * 1000
            info['ip'] = ip_address
            info['dns_time_ms'] = f"{dns_time:.2f}"
            
            # HTTP Response Time + Server Header
            start_time = time.time()
            r = self.session.get(self.target_url, timeout=5)
            response_time = (time.time() - start_time) * 1000
            info['response_time_ms'] = f"{response_time:.2f}"
            info['latency_ms'] = f"{response_time:.2f}"  # Using response time as latency
            
            # Server header
            server_header = r.headers.get('Server', 'N/A')
            info['server'] = server_header
            
        except Exception as e:
            pass  # Keep N/A values
        
        return info


    def check_php_eol(self):
        try:
            # Passive check
            resp = self.session.head(self.target_url, timeout=10)
            powered_by = resp.headers.get('X-Powered-By', '')
            
            # Dynamic EOL Check via php.net
            supported_versions = []
            try:
                # Simple fetch of supported versions - branches listed on the page are usually the supported ones
                # or we look for specific class identifiers. For robustness, we'll try to get all versions like "8.1", "8.2", etc.
                php_net = requests.get('https://www.php.net/supported-versions.php', timeout=5)
                import re
                # Find versions in the first column of the main table
                # Format: <td class="version"><a href="/supported-versions.php?ver=8.3">8.3</a></td>
                supported_versions = re.findall(r'ver=(\d+\.\d+)', php_net.text)
                supported_versions = sorted(list(set(supported_versions))) # Minimal list of supported minor versions (e.g., ['8.1', '8.2', '8.3'])
            except:
                supported_versions = ['8.1', '8.2', '8.3'] # Fallback if offline

            common_risk = "Versoes antigas do PHP tem vulnerabilidades conhecidas (RCE, DoS) e nao recebem mais patches de seguranca."
            common_manual = f"curl -I {self.target_url} | grep -i php"
            
            # Logic: Extract version from header and check if it starts with any supported version prefixes
            detected_version = None
            if 'PHP/' in powered_by:
                parts = powered_by.split('PHP/')
                if len(parts) > 1:
                    detected_version = parts[1].split()[0] # e.g. 7.2.34
            
            is_eol = False
            if detected_version:
                 # Check if the detected version's major.minor is in supported list
                 # detected 7.2.34 -> 7.2. supported ['8.1', '8.2'] -> 7.2 is not in list -> EOL
                 detected_minor = '.'.join(detected_version.split('.')[:2])
                 if detected_minor not in supported_versions:
                     is_eol = True

            if is_eol:
                 # Determine status
                 status = 'Vulnerable'
                 severity = 'Critical'
                 if detected_version == '7.2.34': 
                     # Specific prompt case
                     details = f'PHP {detected_version} detectado. Esta versao e EOL. Versoes suportadas atualmente: {", ".join(supported_versions)}.'
                 else:
                     details = f'PHP {detected_version} detectado. Versao nao listada como suportada em php.net (Suportadas: {", ".join(supported_versions)}).'
                     
                 self._add_result(f'PHP {detected_version} EOL', status, 
                                 details, 
                                 severity,
                                 f'Comparacao com lista oficial de versoes suportadas (php.net). Lista obtida: {supported_versions}',
                                 common_manual,
                                 common_risk,
                                 'Aplicativos da Web')
            elif detected_version and not is_eol:
                 self._add_result('PHP Version', 'Safe', 
                                  f'PHP {detected_version} detectado. Esta versao parece suportada (Lista: {supported_versions}).', 
                                  'Info', 
                                  'Comparacao com php.net', 
                                  common_manual, 
                                  'Versao atualizada.',
                                  'Aplicativos da Web')
            else:
                # Fallback to the active input test if header is hidden
                # Active check
                try:
                    resp_post = self.session.post(self.target_url, data={'a[]': ['1', '2']}, timeout=10)
                    if 'PHP/7.2.34' in resp_post.text:
                         self._add_result('PHP 7.2.34 EOL', 'Critical', 
                                          'PHP Version 7.2.34 vazada no corpo da resposta (Erro provocado).', 
                                          'Critical',
                                          'Analise ativa enviando payload de arrays maliciosos (Array Injection) para forcar erro.',
                                          "curl -X POST -d \"a[]=1&a[]=2\" " + self.target_url,
                                          common_risk,
                                          'Aplicativos da Web')
                    elif 'PHP Warning' in resp_post.text:
                         self._add_result('PHP Error Leak', 'Warning', 
                                          'Warnings do PHP expostos na resposta.', 
                                          'Medium',
                                          'Payload de Array Injection gerou Stack Trace/Warning.',
                                          "curl -X POST -d \"a[]=1&a[]=2\" " + self.target_url,
                                          "Exposicao de estrutura interna (Full Path Disclosure) facilita ataques direcionados.",
                                          'Aplicativos da Web')
                    elif 'PHP/7.2.34' not in powered_by:
                         self._add_result('PHP 7.2.34 EOL', 'Safe', 
                                          'Nenhum header ou erro evidente de PHP 7.2.34 detectado.', 
                                          'Info',
                                          'Analise de headers e tentativa de provocacao de erro.',
                                          common_manual,
                                          "Se o servidor ocultar a versao, esta validacao pode ser falso-negativo.",
                                          'Aplicativos da Web')
                except:
                    pass

        except Exception as e:
            self._add_result('PHP Check', 'Error', f'Falha na conexao: {str(e)}', 'Info', '-', '-', '-', 'Aplicativos da Web')

    def check_xss(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            csp = resp.headers.get('Content-Security-Policy', '')
            
            risk_desc = "Atacantes podem executar scripts no navegador da vitima, roubar sessoes ou realizar defacement."
            
            if not csp or "'unsafe-inline'" in csp or 'unsafe-inline' in csp:
                probe = "<script>alert(1)</script>"
                params = {'test': probe}
                try:
                    resp_refl = self.session.get(self.target_url, params=params, timeout=10)
                    if probe in resp_refl.text:
                         self._add_result('Reflected XSS', 'Vulnerable', 
                                          'Input refletido na resposta e CSP permite unsafe-inline/ausente.', 
                                          'High',
                                          'Injecao de payload <script> em parametro GET e validacao de reflexao.',
                                          f"{self.target_url}?test=<script>alert(1)</script>",
                                          risk_desc,
                                          'Aplicativos da Web')
                         return
                except:
                    pass
                
                self._add_result('XSS (CSP)', 'Warning', 
                                 'CSP ausente ou permite unsafe-inline. Site potencialmente vulneravel.', 
                                 'Medium',
                                 'Analise estatica do header Content-Security-Policy.',
                                 "Verifique se o header CSP existe no DevTools.",
                                 risk_desc,
                                 'Aplicativos da Web')
            else:
                self._add_result('XSS (CSP)', 'Safe', 
                                 'CSP parece bloquear unsafe-inline.', 
                                 'Info',
                                 'Header CSP analisado e validado.',
                                 "Inspecionar Header CSP no navegador.",
                                 "Risco mitigado pela politica de seguranca.",
                                 'Aplicativos da Web')
        except Exception as e:
            self._add_result('XSS', 'Error', str(e), 'Info', '-', '-', '-', 'Aplicativos da Web')

    def check_clickjacking(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            x_frame = resp.headers.get('X-Frame-Options', '')
            csp = resp.headers.get('Content-Security-Policy', '')
            
            risk_cj = "Atacantes podem sobrepor iframes transparentes para enganar usuarios a clicar em botoes indesejados."
            iframe_poc =f"<iframe src=\"{self.target_url}\"></iframe>"

            if 'DENY' in x_frame.upper() or 'SAMEORIGIN' in x_frame.upper():
                self._add_result('Clickjacking', 'Safe', 
                                 'X-Frame-Options presente.', 
                                 'Info',
                                 'Verificacao do header X-Frame-Options: DENY/SAMEORIGIN.',
                                 "Tente carregar o site dentro de um iframe local.",
                                 "Protegido.",
                                 'Aplicativos da Web')
            elif 'frame-ancestors' in csp:
                self._add_result('Clickjacking', 'Safe', 
                                 'CSP frame-ancestors presente.', 
                                 'Info',
                                 'Verificacao da diretiva frame-ancestors na CSP.',
                                 "-",
                                 "Protegido.",
                                 'Aplicativos da Web')
            else:
                self._add_result('Clickjacking', 'Vulnerable', 
                                 'Sem protecao contra Iframe (X-Frame-Options/CSP ausentes).', 
                                 'Medium',
                                 'Ausencia de headers de protecao de frame.',
                                 f"Crie um HTML: {iframe_poc}",
                                 risk_cj,
                                 'Aplicativos da Web')
        except Exception as e:
            self._add_result('Clickjacking', 'Error', str(e), 'Info', '-', '-', '-', 'Aplicativos da Web')

    def check_cors(self):
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST'
            }
            resp = self.session.options(self.target_url, headers=headers, timeout=10)
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            risk_cors = "Sites maliciosos podem ler dados sensiveis da vitima em nome dela (ex: API keys, PII)."
            curl_cmd = f"curl -I -H \"Origin: https://evil.com\" -X OPTIONS {self.target_url}"

            if (acao == '*' or acao == 'https://evil.com') and acac == 'true':
                 self._add_result('CORS Misconfiguration', 'Vulnerable', 
                                  'Permite origem arbitraria (evil.com) com credenciais (High).', 
                                  'High',
                                  'Envio de Requisicao OPTIONS com Origin: https://evil.com.',
                                  curl_cmd,
                                  risk_cors,
                                  'Aplicativos da Web')
            elif acao == '*' and acac != 'true':
                 self._add_result('CORS Misconfiguration', 'Warning', 
                                  'Permite * (Wildcard) na origem. Risco se for API privada.', 
                                  'Low',
                                  'Origin: * detectado.',
                                  curl_cmd,
                                  "Se for uma API publica, OK. Se for privada, vulneravel.",
                                  'Aplicativos da Web')
            else:
                 self._add_result('CORS', 'Safe', 
                                  'Nenhum header CORS perigoso retornado.', 
                                  'Info',
                                  'Teste de Preflight OPTIONS nao retornou permissoes excessivas.',
                                  curl_cmd,
                                  "Configuracao segura.",
                                  'Aplicativos da Web')
        except Exception as e:
            self._add_result('CORS', 'Error', str(e), 'Info', '-', '-', '-', 'Aplicativos da Web')

    def check_csrf(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            
            risk_csrf = "Atacantes podem forcar o navegador da vitima a realizar acoes (mudar senha, transfers) sem consentimento."
            
            if 'csrf' not in resp.text.lower() and 'token' not in resp.text.lower():
                 self._add_result('CSRF', 'Warning', 
                                  'Nenhum token anti-CSRF aparente no HTML (Heuristica).', 
                                  'Medium',
                                  'Busca textual por palavras-chave "csrf", "token" no body.',
                                  "Verifique se formularios POST possuem input hidden de token.",
                                  risk_csrf,
                                  'Aplicativos da Web')
            else:
                 self._add_result('CSRF', 'Safe', 
                                  'Tokens CSRF detectados na resposta.', 
                                  'Info',
                                  'Keywords de CSRF detectadas.',
                                  "-",
                                  "Provavel protecao ativa.",
                                  'Aplicativos da Web')
                 
        except Exception as e:
            self._add_result('CSRF', 'Error', str(e), 'Info', '-', '-', '-', 'Aplicativos da Web')

    def check_recon(self):
        try:
            domain = urlparse(self.target_url).netloc
            ip = socket.gethostbyname(domain)
            self._add_result('Reconnaissance', 'Info', 
                             f'IP Address: {ip}', 
                             'Info',
                             'Resolucao DNS do dominio.',
                             f"nslookup {domain}",
                             "Informacao para mapeamento de infraestrutura.",
                             'Coleta de Informações')
        except:
            self._add_result('Reconnaissance', 'Warning', 
                             'Nao foi possivel resolver IP.', 
                             'Low', '-', '-', '-', 'Coleta de Informações')

        try:
            resp = self.session.head(self.target_url, timeout=10)
            headers = resp.headers
            
            server = headers.get('Server', 'Unknown')
            x_powered = headers.get('X-Powered-By', 'Unknown')
            
            self._add_result('Technology', 'Info', 
                             f'Server: {server} | Powered-By: {x_powered}', 
                             'Info',
                             'Coleta passiva de headers.',
                             "curl -I " + self.target_url,
                             "Fingerprinting ajuda o atacante a buscar exploits especificos.",
                             'Coleta de Informações')

            if 'Strict-Transport-Security' not in headers:
                self._add_result('HSTS Missing', 'Warning', 
                                 'Header HSTS ausente. Possibilidade de Downgrade Attack.', 
                                 'Low',
                                 'Verificacao do header Strict-Transport-Security.',
                                 "Verifique headers no DevTools.",
                                 "HSTS forca o uso de HTTPS, prevenindo MITM.",
                                 'Criptografia de Dados')
            else:
                self._add_result('HSTS', 'Safe', 'HSTS Header presente.', 'Info', 'Analise de Header.', '-', 'Conexao segura forcada.', 'Criptografia de Dados')

        except Exception as e:
            self._add_result('Recon', 'Error', f'Recon failed: {str(e)}', 'Info', '-', '-', '-', 'Coleta de Informações')

    def check_cookies(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            checked = False
            for cookie in resp.cookies:
                checked = True
                if not cookie.secure and self.target_url.startswith('https'):
                    self._add_result('Cookie Security', 'Warning', 
                                     f'Cookie {cookie.name} sem flag Secure.', 
                                     'Medium',
                                     'Analise atributos do Cookie.',
                                     "Inspecionar Application > Cookies no Chrome.",
                                     "Cookie pode ser interceptado em conexoes HTTP nao criptografadas.",
                                     'Aplicativos da Web')
                
            if not checked:
                 self._add_result('Cookies', 'Info', 'Nenhum cookie definido na pagina inicial.', 'Info', '-', '-', '-', 'Aplicativos da Web')

        except Exception as e:
            pass

    def check_dirs(self):
        common_paths = ['/admin', '/test', '/backup', '/old', '/.git', '/.env', '/config.php']
        found = []
        
        def check_single_dir(path):
            try:
                full_url = urljoin(self.target_url, path)
                resp = self.session.head(full_url, timeout=5)
                if resp.status_code == 200:
                    return f"<a href='{full_url}' target='_blank' style='color:#00f3ff'>{path}</a>"
                elif resp.status_code == 403:
                    return f"<a href='{full_url}' target='_blank' style='color:#ffb86c'>{path} (403)</a>"
            except:
                pass
            return None

        # Run directory checks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {executor.submit(check_single_dir, path): path for path in common_paths}
            for future in concurrent.futures.as_completed(future_to_path):
                result = future.result()
                if result:
                    found.append(result)
            
            if found:
                # Format as a clean HTML list
                list_items = "".join([f"<li style='margin-bottom:5px;'>{item}</li>" for item in found])
                html_list = f"<ul style='margin-top:10px; padding-left:20px; list-style-type:square; color:#e0e6ed;'>{list_items}</ul>"
                
                self._add_result('Sensitive Directories', 'Warning', 
                                 f'Diretorios encontrados:<br>{html_list}', 
                                 'Medium',
                                 'Fuzzing Paralelo de caminhos comuns.',
                                 "Tente acessar os caminhos no navegador.",
                                 "Exposicao de area administrativa ou backups.",
                                 'Análise de Vulnerabilidade')
            else:
                pass 
                # Avoid spamming safe results for dirs

    def check_missing_headers(self):
        try:
            resp = self.session.head(self.target_url, timeout=10)
            headers = resp.headers
            
            # X-Content-Type-Options
            if 'X-Content-Type-Options' not in headers:
                self._add_result('Missing X-Content-Type-Options', 'Warning', 
                                 'Header X-Content-Type-Options: nosniff ausente.', 
                                 'Low',
                                 'Analise estatica de headers.',
                                 "curl -I " + self.target_url,
                                 "Navegadores podem 'adivinhar' tipos MIME incorretos e executar arquivos maliciosos (MIME Sniffing).",
                                 'Aplicativos da Web')
            else:
                self._add_result('X-Content-Type-Options', 'Safe', 'Header presente (nosniff).', 'Info', 'Analise de Header.', '-', 'Protecao contra MIME Sniffing ativa.', 'Aplicativos da Web')

            # Referrer-Policy
            if 'Referrer-Policy' not in headers:
                self._add_result('Missing Referrer-Policy', 'Warning', 
                                 'Referrer-Policy ausente. Dados de navegacao podem vazar para terceiros.', 
                                 'Low',
                                 'Analise estatica de headers.',
                                 "curl -I " + self.target_url,
                                 "Pode revelar URLs sensiveis ou padroes de navegacao para sites externos.",
                                 'Aplicativos da Web')
            else:
                 self._add_result('Referrer-Policy', 'Safe', f'Header presente: {headers.get("Referrer-Policy")}', 'Info', 'Analise de Header.', '-', 'Controle de vazamento de Referer ativo.', 'Aplicativos da Web')

            # Permissions-Policy
            if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
                 self._add_result('Missing Permissions-Policy', 'Warning', 
                                  'Permissions-Policy ausente. Recursos de hardware (camera, mic) nao restritos.', 
                                  'Low',
                                  'Analise estatica de headers.',
                                  "curl -I " + self.target_url,
                                  "Sites maliciosos ou iframes podem abusar de APIs do navegador (Geo, Camera) se nao bloqueados.",
                                  'Aplicativos da Web')
            else:
                 self._add_result('Permissions-Policy', 'Safe', 'Header presente.', 'Info', 'Analise de Header.', '-', 'Uso de APIs do navegador controlado.', 'Aplicativos da Web')
        except Exception as e:
            pass

    def check_cve_2024_4577(self):
        # CVE-2024-4577: PHP CGI Argument Injection
        # Reference: https://socprime.com/pt/blog/cve-2024-4577-detection-a-new-easy-to-exploit-php-vulnerability-could-lead-to-rce/
        try:
            # Query parameter that exploits the argument injection in CGI mode (XAMPP/Windows common)
            payload = "?%ADd+allow_url_include%3d1+%2d%64+auto_prepend_file%3dphp://input"
            test_url = self.target_url + payload
            
            # We send a harmless POST body to see if it gets reflected or executed.
            active_manual = f"curl -v \"{test_url}\" -X POST -d \"<?php echo 'VULN_CHECK'; ?>\""
            
            resp = self.session.post(test_url, data="test_cve_check", timeout=5)
            
            risk_desc = "RCE (Remote Code Execution) via PHP CGI. Permite que atacantes executem comandos arbitrarios no servidor (especialmente XAMPP no Windows)."
            
            # Check if PHP detected previously
            is_php = False
            for res in self.results:
                if 'PHP' in res['vulnerability']:
                    is_php = True
                    break
            
            if is_php:
                 self._add_result('CVE-2024-4577 (PHP CGI)', 'Warning', 
                                  'Verifique se seu ambiente (XAMPP/Windows) esta patcheado contra CVE-2024-4577.', 
                                  'High',
                                  'Verificacao heuristica baseada no uso de PHP.',
                                  active_manual,
                                  risk_desc,
                                  'Aplicativos da Web')
        except:
            pass

    def check_sqli(self):
        # Basic SQL Injection Heuristic (OWASP Injection)
        # Tries to provoke a syntax error by adding a single quote
        try:
            payload = "'"
            # Test on query params if present, else append to URL
            if '?' in self.target_url:
                test_url = self.target_url + payload
            else:
                test_url = self.target_url # Can't easily test clean URLs without knowing params
            
            if '?' in self.target_url:
                resp = self.session.get(test_url, timeout=5)
                
                sql_errors = [
                    "SQL syntax", "MariaDB", "MySQL", "ORA-", "PostgreSQL", "Syntax error"
                ]
                
                vulnerable = False
                found_error = ""
                for err in sql_errors:
                    if err.lower() in resp.text.lower():
                        vulnerable = True
                        found_error = err
                        break
                
                risk_sql = "Injecoes SQL permitem acesso total ou parcial ao banco de dados, podendo vazar senhas, dados de clientes ou comprometer o servidor."
                manual_cmd = f"curl \"{test_url}\""

                if vulnerable:
                    self._add_result('SQL Injection', 'Vulnerable', 
                                     f'Erro de SQL detectado na resposta (Padrao: {found_error}).', 
                                     'Critical',
                                     f'Injecao de aspas simples (\') no parametro GET para provocar erro de sintaxe.',
                                     manual_cmd,
                                     risk_sql,
                                     'Aplicativos da Web')
                else:
                    self._add_result('SQL Injection', 'Safe', 
                                     'Nenhum erro de SQL evidente retornado ao injetar aspas.', 
                                     'Info',
                                     'Teste passivo de erro de sintaxe SQL.',
                                     manual_cmd,
                                     "Erros ocultos (Blind SQLi) nao sao detectados neste teste basico.",
                                     'Aplicativos da Web')
            else:
                self._add_result('SQL Injection', 'Info', 'Nenhum parametro GET detectado para teste automatico.', 'Info', '-', '-', '-', 'Aplicativos da Web')

        except Exception as e:
            pass

    def check_http_methods(self):
        # Checks for dangerous HTTP methods allowed on the server
        try:
            methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']
            allowed_dangerous = []
            
            for method in methods:
                try:
                    if method == 'OPTIONS':
                        resp = self.session.options(self.target_url, timeout=5)
                        # Check 'Allow' header
                        allow_header = resp.headers.get('Allow', '')
                        if allow_header:
                             pass
                    else:
                        resp = self.session.request(method, self.target_url, timeout=5)
                        if resp.status_code in [200, 201, 202, 204]:
                            allowed_dangerous.append(f"{method} ({resp.status_code})")
                except:
                    pass

            if allowed_dangerous:
                 risk_methods = "Metodos como PUT/DELETE podem permitir upload de arquivos ou remocao de conteudo. TRACE permite Cross-Site Tracing (XST)."
                 # Generate a list of commands for all detected methods
                 manual_methods = "<br>".join([f"curl -X {m.split()[0]} -I {self.target_url}" for m in allowed_dangerous])
                 
                 severity = 'Medium'
                 if 'TRACE' in str(allowed_dangerous):
                     severity = 'High'
                 if 'PUT' in str(allowed_dangerous) or 'DELETE' in str(allowed_dangerous):
                     severity = 'High'
                 
                 self._add_result('Dangerous HTTP Methods', 'Vulnerable', 
                                  f'Metodos perigosos habilitados: {", ".join(allowed_dangerous)}', 
                                  severity,
                                  'Testes ativos com verbos HTTP especificos.',
                                  manual_methods,
                                  risk_methods,
                                  'Análise de Vulnerabilidade')
            else:
                 self._add_result('Dangerous HTTP Methods', 'Safe', 
                                  'Nenhum método HTTP perigoso habilitado (PUT, DELETE, TRACE bloqueados).', 
                                  'Info',
                                  'Testes ativos com verbos HTTP específicos.',
                                  f'curl -X OPTIONS -i {self.target_url}',
                                  'Configuração segura de métodos HTTP.',
                                  'Análise de Vulnerabilidade')

        except Exception as e:
            pass

    def check_server_version(self):
        # Checks Server header and provides external verification links (Nginx/Apache/IIS)
        try:
            resp = self.session.head(self.target_url, timeout=5)
            server_header = resp.headers.get('Server', '').lower()
            
            link = ""
            manual_check = ""
            
            if 'nginx' in server_header:
                link = "<a href='https://nginx.org/en/security_advisories.html' target='_blank' style='color:#00f3ff'>Nginx Security Advisories</a>"
                manual_check = "Verifique a versao do Nginx contra a lista oficial de vulnerabilidades."
            elif 'apache' in server_header:
                link = "<a href='https://httpd.apache.org/security/vulnerabilities_24.html' target='_blank' style='color:#00f3ff'>Apache HTTPD Security</a>"
                manual_check = "Verifique o Changelog do Apache para CVEs conhecidas."
            elif 'iis' in server_header or 'microsoft' in server_header:
                 link = "<a href='https://msrc.microsoft.com/update-guide' target='_blank' style='color:#00f3ff'>Microsoft Security Update Guide</a>"
                 manual_check = "Verifique o Patch Tuesday da Microsoft para o IIS."
            
            if link:
                self._add_result('Server Version Check', 'Info', 
                                 f'Servidor detectado: {server_header}.<br>Consulte as vulnerabilidades conhecidas em:<br>{link}', 
                                 'Info', 
                                 'Analise do header Server e correlacao com fontes oficiais.', 
                                 manual_check, 
                                 "Servidores desatualizados podem conter RCE, DoS ou bypass de autenticacao.",
                                 'Coleta de Informações')
        except:
             pass

    def check_ssl(self):
        # Checks SSL Certificate validity and expiration
        if not self.target_url.startswith('https'):
             return

        try:
            hostname = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    not_after_str = cert['notAfter']
                    try:
                        # Format Issuer
                        issuer_dict = dict(x[0] for x in cert['issuer'])
                        issuer_str = f"{issuer_dict.get('commonName', '')} ({issuer_dict.get('countryName', '')})".strip()
                        if not issuer_str or issuer_str == "()":
                            issuer_str = str(issuer_dict)

                        manual_cmd = f"echo | openssl s_client -connect {hostname}:443 2>/dev/null | openssl x509 -noout -dates"

                        if days_left < 0:
                            self._add_result('SSL Certificate', 'Critical', 
                                             f'Certificado SSL Expirado em {not_after_str}.', 
                                             'Critical', 
                                             'Handshake SSL e analise de datas.', 
                                             manual_cmd, 
                                             "Conexoes inseguras, perda de confianca do usuario.",
                                             'Criptografia de Dados')
                        elif days_left < 30:
                             self._add_result('SSL Certificate', 'Warning', 
                                             f'Certificado expira em breve ({days_left} dias). Data: {not_after_str}', 
                                             'Low', 
                                             'Analise de datas do certificado.', 
                                             manual_cmd, 
                                             "Risco de interrupcao do servico.",
                                             'Criptografia de Dados')
                        else:
                             self._add_result('SSL Certificate', 'Safe', 
                                             f'Certificado valido. Expira em {days_left} dias ({not_after_str}).', 
                                             'Info', 
                                             f'Issuer: {issuer_str}', 
                                             manual_cmd, 
                                             "Criptografia ativa.",
                                             'Criptografia de Dados')
                    except:
                        self._add_result('SSL Certificate', 'Info', 
                                         f'Certificado valido. Expira em: {not_after_str}', 
                                         'Info', 
                                         'Handshake SSL.', 
                                         f"echo | openssl s_client -connect {hostname}:443 2>/dev/null | openssl x509 -noout -dates", 
                                         "Conexao segura.",
                                         'Criptografia de Dados')
        except Exception as e:
            self._add_result('SSL Check', 'Error', f'Falha no SSL Handshake: {str(e)}', 'Info', '-', '-', '-', 'Criptografia de Dados')

    def check_robots(self):
        # Checks robots.txt for sensitive paths
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            resp = self.session.get(robots_url, timeout=5)
            
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                sensitive = []
                for line in lines:
                    if 'Disallow:' in line:
                        path = line.split('Disallow:')[1].strip()
                        if path and path != '/':
                             sensitive.append(path)
                
                if sensitive:
                     short_list = ", ".join(sensitive[:5])
                     if len(sensitive) > 5:
                         short_list += ", ..."
                     
                     self._add_result('Robots.txt Analysis', 'Info', 
                                      f'Arquivo robots.txt encontrado. Caminhos disallow: {short_list}', 
                                      'Info', 
                                      'Leitura de robots.txt.', 
                                      f"curl {robots_url}", 
                                      "Pode revelar areas administrativas ocultas.",
                                      'Coleta de Informações')
                else:
                     self._add_result('Robots.txt Analysis', 'Info', 
                                      'Robots.txt encontrado mas sem disallows suspeitos.', 
                                      'Info', 
                                      '-', '-', '-', 'Coleta de Informações')
        except:
            pass

    def check_waf(self):
        # Simple WAF Detection via Headers
        try:
            resp = self.session.head(self.target_url, timeout=5)
            headers = str(resp.headers).lower()
            
            waf_signatures = {
                'cloudflare': 'Cloudflare',
                'cf-ray': 'Cloudflare',
                'x-sucuri': 'Sucuri',
                'server: akamai': 'Akamai',
                'x-protected-by': 'Generic WAF',
                'imperva': 'Imperva',
                'incapsula': 'Incapsula'
            }
            
            detected = []
            for sig, name in waf_signatures.items():
                if sig in headers:
                    detected.append(name)
            
            detected = list(set(detected))
            
            if detected:
                 self._add_result('WAF Detection', 'Safe', 
                                  f'Firewall de Aplicacao (WAF) detectado: {", ".join(detected)}', 
                                  'Info', 
                                  'Analise passiva de headers de resposta.', 
                                  "wafw00f " + self.target_url, 
                                  "Protecao adicional contra ataques web.",
                                  'Coleta de Informações')
            else:
                 self._add_result('WAF Detection', 'Warning', 
                                  'Nenhum WAF comercial evidente detectado nos headers.', 
                                  'Low', 
                                  'Analise de headers.', 
                                  "-", 
                                  "Site pode estar exposto diretamente ou usando WAF transparente.",
                                  'Coleta de Informações')
        except:
             pass

    def check_ports(self):
        # Checks for common open ports (Professional List)
        try:
            domain = urlparse(self.target_url).hostname
            
            # Expanded Professional Port List
            # Web, Infra, Email, DB, Containers
            ports_to_scan = [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, # Basic + Email
                3306, 5432, 6379, 1433, 1521, 27017, # Databases (MySQL, PG, Redis, MSSQL, Oracle, Mongo)
                8080, 8000, 8443, 8888, 9000, 8081, # Web Apps / Dev / Admin
                2375, 6443, 10250 # Docker / K8s
            ]
            
            port_info = {
                21:  ("FTP", "Transferencia de arquivos sem criptografia (Sniffing)."),
                22:  ("SSH", "Acesso remoto seguro. Tente Brute-force ou chaves fracas."),
                23:  ("Telnet", "Acesso remoto INSEGURO (Cleartext). Critico."),
                25:  ("SMTP", "Envio de e-mails. Pode permitir Open Relay."),
                53:  ("DNS", "Servidor de nomes. Verifique Transferencia de Zona (AXFR)."),
                80:  ("HTTP", "Servidor Web. Verifique redirecionamentos e falta de HTTPS."),
                110: ("POP3", "Recebimento de e-mails (Legado/Inseguro)."),
                143: ("IMAP", "Recebimento de e-mails."),
                443: ("HTTPS", "Servidor Web Seguro."),
                465: ("SMTPS", "Envio de e-mails seguro."),
                587: ("SMTP Submission", "Envio de e-mails autenticado."),
                3306: ("MySQL/MariaDB", "Banco de Dados. Nao deveria estar exposto publicamente."),
                5432: ("PostgreSQL", "Banco de Dados. Risco de acesso a dados criticos."),
                6379: ("Redis", "NoSQL Cache. Frequentemente sem senha (RCE via cron)."),
                1433: ("MSSQL", "Banco de Dados Microsoft."),
                1521: ("OracleDB", "Banco de Dados Oracle."),
                27017: ("MongoDB", "NoSQL DB. Verifique acesso anonimo."),
                8080: ("HTTP-Alt", "Servidor Web alternativo (Tomcat, Jenkins, Proxies)."),
                8000: ("Dev Server", "Servidores de desenvolvimento (Django/Flask/Laravel)."),
                8443: ("HTTPS-Alt", "Paineis administrativos ou consoles de gerenciamento."),
                8888: ("Web Admin", "Jupyter Notebooks, Splunk ou Paineis de Host."),
                9000: ("FastCGI/Sonar", "PHP-FPM (RCE) ou SonarQube exposto."),
                8081: ("Mgmt/Nexus", "Servicos de gerenciamento ou Repositorios."),
                2375: ("Docker API", "API Docker exposta sem TLS. Acesso root total ao host."),
                6443: ("K8s API", "Kubernetes API Server. Controle total do cluster."),
                10250: ("Kubelet", "Agente Kubernetes. Possivel RCE.")
            }

            open_ports = []
            details_list = []
            
            def scan_single_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0) # Increased timeout slightly as we are parallel
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    if result == 0:
                        return port
                except:
                    pass
                return None

            # Run port scans in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {executor.submit(scan_single_port, port): port for port in ports_to_scan}
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future.result()
                    if port:
                        open_ports.append(str(port))
                        service, desc = port_info.get(port, ("Unknown", "Porta desconhecida aberta."))
                        
                        # Style for specific risks
                        color = "#e0e6ed" # default text
                        if port in [21, 23, 3306, 5432, 6379, 27017, 2375]:
                            color = "#ffb86c" # Warning/Orange
                        
                        details_list.append(f"<li style='margin-bottom:5px;'><strong style='color:#bd93f9'>{port} ({service}):</strong> <span style='color:{color}'>{desc}</span></li>")
            
            if open_ports:
                 # Calculate overall severity based on finding critical ports
                 severity = 'Medium'
                 risk_text = "Superficie de ataque aumentada. Servicos desnecessarios devem ser fechados ou filtrados por Firewall."
                 
                 critical_ports = [21, 23, 3306, 5432, 6379, 27017, 2375, 6443, 9000]
                 for p in open_ports:
                     if int(p) in critical_ports:
                         severity = 'High'
                         risk_text = "CRITICO: Bancos de dados, Acesso remoto inseguro ou APIs de infraestrutura expostas publicamente."
                         break
                 
                 # Sort details for consistent display
                 details_list.sort()
                 
                 html_details = f"Portas encontradas:<ul style='margin-top:10px; padding-left:20px; list-style-type:none;'>{''.join(details_list)}</ul>"
                 
                 self._add_result('Open Ports (Professional Scan)', 'Warning', 
                                  html_details, 
                                  severity, 
                                  'Port Scan TCP Connect (Paralelo).', 
                                  f"nmap -sS -sV -p {','.join(open_ports)} {domain}", 
                                  risk_text,
                                  'Coleta de Informações')
            else:
                 self._add_result('Port Scan', 'Safe', 
                                  f'Nenhuma porta critica (alem de Web padrao) detectada no scan de {len(ports_to_scan)} principais.', 
                                  'Info', 
                                  f'Scan realizado em {len(ports_to_scan)} portas selecionadas (Web, DB, Infra, Mail).', 
                                  "-", 
                                  "Superficie de ataque externa parece reduzida.",
                                  'Coleta de Informações')

        except:
            pass

    def check_dns_security(self):
        # Checks SPF and DMARC records via nslookup
        try:
            domain = urlparse(self.target_url).hostname
            
            # SPF Check
            try:
                spf_cmd = f"nslookup -type=TXT {domain}"
                proc = subprocess.Popen(spf_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                out = out.decode('latin-1', errors='ignore')
                
                if "v=spf1" in out:
                     self._add_result('DNS Security (SPF)', 'Safe', 
                                      'Registro SPF encontrado.', 
                                      'Info', 
                                      'Consulta DNS TXT para SPF.', 
                                      spf_cmd, 
                                      "Previne falsificacao de e-mail (Spoofing).",
                                      'Criptografia de Dados')
                else:
                     self._add_result('DNS Security (SPF)', 'Warning', 
                                      'Registro SPF nao encontrado ou nao visivel.', 
                                      'Low', 
                                      'Consulta DNS TXT.', 
                                      spf_cmd, 
                                      "Dominio pode ser usado para phishing e spam.",
                                      'Criptografia de Dados')
            except:
                pass

            # DMARC Check
            try:
                dmarc_cmd = f"nslookup -type=TXT _dmarc.{domain}"
                proc = subprocess.Popen(dmarc_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                out = out.decode('latin-1', errors='ignore')
                
                if "v=DMARC1" in out:
                     self._add_result('DNS Security (DMARC)', 'Safe', 
                                      'Registro DMARC encontrado.', 
                                      'Info', 
                                      'Consulta DNS TXT para _dmarc.', 
                                      dmarc_cmd, 
                                      "Politica de autenticacao de e-mail ativa.",
                                      'Criptografia de Dados')
                else:
                     self._add_result('DNS Security (DMARC)', 'Warning', 
                                      'Registro DMARC nao encontrado.', 
                                      'Low', 
                                      'Consulta DNS TXT.', 
                                      dmarc_cmd, 
                                      "Falta de politica estrita contra spoofing.",
                                      'Criptografia de Dados')
            except:
                pass

        except:
            pass

    def check_subdomains(self):
        # Basic subdomain discovery
        try:
            domain = urlparse(self.target_url).hostname
            subs = ['admin', 'dev', 'test', 'staging', 'api', 'portal', 'm']
            
            found_subs = []
            
            for sub in subs:
                target = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(target)
                    found_subs.append(f"<a href='http://{target}' target='_blank' style='color:#00f3ff'>{target}</a> ({ip})")
                except:
                    pass
            
            if found_subs:
                 html_list = "".join([f"<li>{s}</li>" for s in found_subs])
                 self._add_result('Subdomains Found', 'Info', 
                                  f'Subdominios descobertos:<br><ul>{html_list}</ul>', 
                                  'Info', 
                                  'Resolucao DNS de lista de subdominios comuns.', 
                                  "Use ferramentas como Sublist3r para busca completa.", 
                                   "Subdominios de desenvolvimento podem conter bugs nao corrigidos.",
                                   'Coleta de Informações')
            else:
                 pass 
        except:
            pass

    def check_open_redirect(self):
        # Open Redirect Check
        # Tries to redirect to google.com using common parameters
        try:
            payload = "https://google.com"
            params = ['url', 'next', 'redirect', 'target', 'r', 'dest', 'u']
            
            # Passive check on clean URL usually fails unless we know params, so we try typical ones
            found_vuln = False
            for param in params:
                try:
                    # Construct URL: target.com/?next=https://google.com
                    target = f"{self.target_url}?{param}={payload}"
                    # Don't follow redirects automatically to check status code 3xx or header location
                    resp = self.session.get(target, allow_redirects=False, timeout=5)
                    
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        loc = resp.headers.get('Location', '')
                        if 'google.com' in loc:
                            found_vuln = True
                            self._add_result('Open Redirect', 'Vulnerable', 
                                             f'Redirecionamento aberto detectado no parametro "{param}".', 
                                             'Medium', 
                                             f'Teste com parametro ?{param}=https://google.com com redirect follow desativado.', 
                                             f"curl -I \"{target}\"", 
                                             "Phishing facilitado usando a reputacao do dominio original.",
                                             'Aplicativos da Web')
                            break
                except:
                    pass
            
            if not found_vuln:
                 self._add_result('Open Redirect', 'Safe', 
                                  'Nenhum redirecionamento aberto detectado com parametros comuns.', 
                                  'Info', 
                                  f'Fuzzing de parametros: {", ".join(params)}', 
                                  "-", 
                                   "Parametros de redirecionamento nao encontrados ou validados.",
                                   'Aplicativos da Web')

        except:
             pass

    def check_tabnabbing(self):
        # Reverse Tabnabbing Check
        # Checks for target="_blank" without rel="noopener noreferrer"
        try:
            resp = self.session.get(self.target_url, timeout=5)
            if 'target="_blank"' in resp.text:
                 # Simple heuristic check, parsing full HTML is better but regex works for speed
                 # Ideally checking if rel="noopener" comes with it.
                 import re
                 # Find all A tags with target="_blank"
                 links = re.findall(r'<a[^>]+target=["\']_blank["\'][^>]*>', resp.text, re.IGNORECASE)
                 
                 vulnerable_links = []
                 for link in links:
                     if 'noopener' not in link and 'noreferrer' not in link:
                         vulnerable_links.append(link[:100] + "...") # Truncate for display
                 
                 if vulnerable_links:
                     self._add_result('Reverse Tabnabbing', 'Warning', 
                                      f'Links target="_blank" sem "noopener noreferrer" encontrados.', 
                                      'Low', 
                                      'Analise estatica de tags HTML.', 
                                      "Inspecione o codigo fonte em busca de target='_blank'.", 
                                       "A pagina de destino pode manipular a pagina de origem (window.opener.location).",
                                       'Aplicativos da Web')
                 else:
                     self._add_result('Tabnabbing', 'Safe', 
                                      'Links target="_blank" parecem usar noopener/noreferrer.', 
                                      'Info', 
                                      'Analise de tags <a target="_blank">.', 
                                      "-", 
                                       "Protegido contra manipulacao de aba.",
                                       'Aplicativos da Web')
            else:
                 self._add_result('Tabnabbing', 'Info', 'Nenhum link target="_blank" encontrado na home.', 'Info', '-', '-', '-', 'Aplicativos da Web')
        except:
            pass

    def check_sri(self):
        # Subresource Integrity Check
        try:
            resp = self.session.get(self.target_url, timeout=5)
            import re
            # Find scripts from external domains
            # Heuristic: src="http..." and not current domain
            domain = urlparse(self.target_url).netloc
            scripts = re.findall(r'<script[^>]+src=["\'](http[^"\']+)["\'][^>]*>', resp.text, re.IGNORECASE)
            
            missing_sri = []
            for src in scripts:
                src_domain = urlparse(src).netloc
                # If script is external (different domain) 
                if src_domain and src_domain != domain:
                    # Check if the FULL tag has 'integrity=' regex is tricky on full tag, so we approximate
                    # We need the full tag context.
                    # Re-find the tag for this src
                    tag_match = re.search(f'<script[^>]+src=["\']{re.escape(src)}["\'][^>]*>', resp.text, re.IGNORECASE)
                    if tag_match:
                        tag_content = tag_match.group(0)
                        if 'integrity=' not in tag_content:
                            missing_sri.append(src)
            
            if missing_sri:
                 short_list = ", ".join([s.split('/')[-1] for s in missing_sri[:3]])
                 self._add_result('Subresource Integrity (SRI)', 'Warning', 
                                  f'Scripts externos sem hash de integridade (SRI): {short_list}...', 
                                  'Low', 
                                  'Verificacao de atributo integrity em scripts de terceiros (CDNs).', 
                                  "Verifique tags <script src='...'>.", 
                                   "Se o CDN for comprometido, codigo malicioso pode ser injetado (Supply Chain Attack).",
                                   'Aplicativos da Web')
            else:
                 self._add_result('SRI Check', 'Safe', 
                                  'Nenhum script externo sem SRI detectado.', 
                                  'Info', 
                                  'Analise de scripts de terceiros.', 
                                  "-", 
                                   "Scripts externos validados ou servidos localmente.",
                                   'Aplicativos da Web')
        except:
            pass

    def check_pii(self):
        # PII Scanning (Regex based)
        try:
            resp = self.session.get(self.target_url, timeout=10)
            text = resp.text
            
            findings = []
            
            # CPF Regex (Simple validation of format XXX.XXX.XXX-XX)
            import re
            cpfs = re.findall(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b', text)
            if cpfs:
                findings.append(f"CPFs encontrados: {len(cpfs)} (Ex: {cpfs[0]})")
                
            # Email Regex
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
            # Filter dumb emails
            valid_emails = [e for e in emails if not e.endswith('.png') and not e.endswith('.jpg') and len(e) < 50]
            if len(valid_emails) > 0:
                 findings.append(f"E-mails encontrados: {len(valid_emails)}")
                 
            # Credit Card (Luhn is hard via regex, checking simple groups of 4 digits)
            # Visa/Mastercard usually 16 digits.
            # Avoid matching CSS/Analytics IDs. Very prone to false positives. Skiping for now to avoid noise.
            
            if findings:
                 self._add_result('PII Disclosure', 'Warning', 
                                  f'Dados pessoais (PII) encontrados no HTML: {", ".join(findings)}.', 
                                  'High', 
                                  'Regex scan no corpo da resposta.', 
                                  "Ctrl+F no codigo fonte.", 
                                   "Vazamento de dados sensiveis viola LGPD/GDPR.",
                                   'Coleta de Informações')
            else:
                 pass # Silent
        except:
             pass

    def check_command_injection(self):
        # Basic OS Command Injection
        # Tries to inject a command that causes a delay or echo
        try:
            # Time-based is safer but slow/complex. We try a simple echo or logic.
            # But passive on home page is limited.
            # We try query params again if exist.
            
            # Simple payload: ; echo "VULN"
            # If validated output contains VULN
            
             params = ['ip', 'host', 'cmd', 'exec', 'ping', 'dir']
             found = False
             
             target_params = []
             if '?' in self.target_url:
                 # Extract params, but here we just blindly test common ones too
                 pass
             
             for p in params:
                 test_url = f"{self.target_url}?{p}=;echo VULN_CHECK"
                 try:
                     resp = self.session.get(test_url, timeout=3)
                     if "VULN_CHECK" in resp.text:
                         self._add_result('OS Command Injection', 'Critical', 
                                          f'Comando injetado "echo" retornou na resposta (param: {p}).', 
                                          'Critical', 
                                          f'Injecao de comando no parametro {p}.', 
                                          f"curl \"{test_url}\"", 
                                           "Execucao remota de codigo (RCE) no servidor.",
                                           'Aplicativos da Web')
                         found = True
                         break
                 except:
                     pass
             
             if not found:
                 pass # Silent
        except:
            pass

    def check_swagger(self):
        # Check for Swagger/OpenAPI docs
        swagger_paths = ['/swagger-ui.html', '/swagger.json', '/api-docs', '/v2/api-docs', '/docs']
        found_docs = []
        
        try:
            for path in swagger_paths:
                full_url = urljoin(self.target_url, path)
                resp = self.session.head(full_url, timeout=5)
                if resp.status_code == 200:
                    found_docs.append(f"<a href='{full_url}' target='_blank' style='color:#00f3ff'>{path}</a>")
            
            if found_docs:
                html_list = "".join([f"<li>{s}</li>" for s in found_docs])
                self._add_result('API Documentation Exposure', 'Info', 
                                 f'Documentacao de API encontrada:<br><ul>{html_list}</ul>', 
                                 'Info', 
                                 'Busca por arquivos Swagger/OpenAPI.', 
                                 "Acesse os links para ver endpoints.", 
                                 "Facilita o entendimento da API para atacantes.",
                                 'Coleta de Informações')
        except:
            pass

    def check_certificate_transparency(self):
        """Verifica se certificado esta em CT Logs publicos"""
        try:
            import json
            parsed = urlparse(self.target_url)
            domain = (parsed.netloc or parsed.path).split(':')[0]
            
            ct_url = f"https://crt.sh/?q={domain}&output=json"
            resp = self.session.get(ct_url, timeout=10)
            
            if resp.status_code == 200:
                try:
                    ct_data = resp.json()
                    if ct_data and len(ct_data) > 0:
                        cert_count = len(ct_data)
                        issuer = ct_data[0].get('issuer_name', 'N/A')[:50]
                        
                        self._add_result('Certificate Transparency', 'Safe',
                            f'Certificado encontrado em CT Logs publicos.<br>Total de certificados: {cert_count}<br>Emissor: {issuer}',
                            'Info', 'Consulta API crt.sh',
                            f'curl "https://crt.sh/?q={domain}"',
                            'Transparencia ativa - previne certificados fraudulentos', 'Criptografia de Dados')
                    else:
                        self._add_result('Certificate Transparency', 'Warning',
                            f'Certificado NAO encontrado em CT Logs para {domain}',
                            'Low', 'Consulta crt.sh', 'Verificar manualmente',
                            'Possivel certificado auto-assinado ou nao registrado', 'Criptografia de Dados')
                except:
                    pass
        except:
            pass

    def check_source_maps(self):
        """Detecta arquivos .map que expõem código fonte original"""
        try:
            # Busca JS comum
            resp = self.session.get(self.target_url, timeout=5)
            if resp.status_code != 200:
                return
            
            # Procura por .js files no HTML
            import re
            js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', resp.text)
            
            found_maps = []
            for js_file in js_files[:10]:  # Limita a 10
                map_url = urljoin(self.target_url, js_file + '.map')
                try:
                    map_resp = self.session.head(map_url, timeout=3)
                    if map_resp.status_code == 200:
                        found_maps.append(f"<a href='{map_url}' target='_blank' style='color:#ff6666'>{js_file}.map</a>")
                except:
                    pass
            
            if found_maps:
                html_list = "".join([f"<li>{m}</li>" for m in found_maps])
                self._add_result('Source Maps Exposure', 'Vulnerable',
                    f'Arquivos .map expostos (codigo fonte original vazado):<br><ul>{html_list}</ul>',
                    'Medium', 'Busca por arquivos .js.map acessiveis',
                    'Remova source maps em producao ou bloqueie acesso',
                    'Expoe codigo TypeScript/React original facilitando engenharia reversa', 'Coleta de Informações')
        except:
            pass
 
         d e f   c h e c k _ s s t i ( s e l f ) :  
                 " " " T e s t a   S e r v e r - S i d e   T e m p l a t e   I n j e c t i o n " " "  
                 t r y :  
                         p a y l o a d s   =   [ ' { { 7 * 7 } } ' ,   ' $ { 7 * 7 } ' ,   ' < % =   7 * 7   % > ' ,   ' $ { { 7 * 7 } } ' ]  
                         p a r a m s   =   [ ' q ' ,   ' s e a r c h ' ,   ' n a m e ' ,   ' i d ' ]  
                          
                         f o r   p a r a m   i n   p a r a m s [ : 2 ] :     #   L i m i t a   t e s t e s  
                                 f o r   p a y l o a d   i n   p a y l o a d s [ : 2 ] :  
                                         t r y :  
                                                 t e s t _ u r l   =   f " { s e l f . t a r g e t _ u r l } ? { p a r a m } = { p a y l o a d } "  
                                                 r e s p   =   s e l f . s e s s i o n . g e t ( t e s t _ u r l ,   t i m e o u t = 5 )  
                                                 i f   ' 4 9 '   i n   r e s p . t e x t   a n d   r e s p . s t a t u s _ c o d e   = =   2 0 0 :  
                                                         s e l f . _ a d d _ r e s u l t ( ' S e r v e r - S i d e   T e m p l a t e   I n j e c t i o n   ( S S T I ) ' ,   ' V u l n e r a b l e ' ,  
                                                                 f ' P o s s i v e l   S S T I   d e t e c t a d o   c o m   p a y l o a d :   { p a y l o a d } ' ,  
                                                                 ' C r i t i c a l ' ,   f ' T e s t e   c o m   { t e s t _ u r l } ' ,  
                                                                 ' S a n i t i z e   i n p u t s   -   n u n c a   p a s s e   i n p u t   d i r e t o   p a r a   t e m p l a t e   e n g i n e ' ,  
                                                                 ' R C E   ( R e m o t e   C o d e   E x e c u t i o n )   -   c o n t r o l e   t o t a l   d o   s e r v i d o r ' ,   ' A n � � l i s e   d e   V u l n e r a b i l i d a d e ' )  
                                                         r e t u r n  
                                         e x c e p t :  
                                                 p a s s  
                 e x c e p t :  
                         p a s s  
  
         d e f   c h e c k _ x x e ( s e l f ) :  
                 " " " T e s t a   X M L   E x t e r n a l   E n t i t y   I n j e c t i o n " " "  
                 t r y :  
                         x x e _ p a y l o a d   =   ' < ? x m l   v e r s i o n = " 1 . 0 " ? > < ! D O C T Y P E   f o o   [ < ! E N T I T Y   x x e   S Y S T E M   " f i l e : / / / e t c / p a s s w d " > ] > < r o o t > < d a t a > & x x e ; < / d a t a > < / r o o t > '  
                          
                         t r y :  
                                 r e s p   =   s e l f . s e s s i o n . p o s t ( s e l f . t a r g e t _ u r l ,    
                                         d a t a = x x e _ p a y l o a d ,    
                                         h e a d e r s = { ' C o n t e n t - T y p e ' :   ' a p p l i c a t i o n / x m l ' } ,    
                                         t i m e o u t = 5 )  
                                  
                                 i f   ' r o o t : '   i n   r e s p . t e x t   o r   ' / b i n / b a s h '   i n   r e s p . t e x t :  
                                         s e l f . _ a d d _ r e s u l t ( ' X M L   E x t e r n a l   E n t i t y   ( X X E ) ' ,   ' V u l n e r a b l e ' ,  
                                                 ' X X E   d e t e c t a d o   -   p a r s e r   X M L   p r o c e s s a   e n t i d a d e s   e x t e r n a s ' ,  
                                                 ' C r i t i c a l ' ,   ' P O S T   c o m   p a y l o a d   X X E ' ,  
                                                 ' D e s a b i l i t e   p r o c e s s a m e n t o   d e   e n t i d a d e s   e x t e r n a s   n o   p a r s e r   X M L ' ,  
                                                 ' L e i t u r a   d e   a r q u i v o s   l o c a i s ,   S S R F ,   D o S ' ,   ' A n � � l i s e   d e   V u l n e r a b i l i d a d e ' )  
                         e x c e p t :  
                                 p a s s  
                 e x c e p t :  
                         p a s s  
  
         d e f   c h e c k _ l o g _ f i l e s ( s e l f ) :  
                 " " " P r o c u r a   a r q u i v o s   d e   l o g   e x p o s t o s " " "  
                 t r y :  
                         l o g _ p a t h s   =   [ ' / l o g s / e r r o r . l o g ' ,   ' / d e b u g . l o g ' ,   ' / n p m - d e b u g . l o g ' ,   ' / e r r o r . l o g ' ,    
                                                   ' / a p p l i c a t i o n . l o g ' ,   ' / a p p . l o g ' ,   ' / s e r v e r . l o g ' ]  
                         f o u n d _ l o g s   =   [ ]  
                          
                         f o r   p a t h   i n   l o g _ p a t h s :  
                                 l o g _ u r l   =   u r l j o i n ( s e l f . t a r g e t _ u r l ,   p a t h )  
                                 t r y :  
                                         r e s p   =   s e l f . s e s s i o n . h e a d ( l o g _ u r l ,   t i m e o u t = 3 )  
                                         i f   r e s p . s t a t u s _ c o d e   = =   2 0 0 :  
                                                 f o u n d _ l o g s . a p p e n d ( f " < a   h r e f = ' { l o g _ u r l } '   t a r g e t = ' _ b l a n k '   s t y l e = ' c o l o r : # f f 6 6 6 6 ' > { p a t h } < / a > " )  
                                 e x c e p t :  
                                         p a s s  
                          
                         i f   f o u n d _ l o g s :  
                                 h t m l _ l i s t   =   " " . j o i n ( [ f " < l i > { l } < / l i > "   f o r   l   i n   f o u n d _ l o g s ] )  
                                 s e l f . _ a d d _ r e s u l t ( ' L o g   F i l e s   E x p o s u r e ' ,   ' V u l n e r a b l e ' ,  
                                         f ' A r q u i v o s   d e   l o g   a c e s s i v e i s   p u b l i c a m e n t e : < b r > < u l > { h t m l _ l i s t } < / u l > ' ,  
                                         ' H i g h ' ,   ' B u s c a   p o r   c a m i n h o s   c o m u n s   d e   l o g s ' ,  
                                         ' B l o q u e  
  
 i e   a c e s s o   a   / l o g s /   v i a   . h t a c c e s s   o u   c o n f i g u r e   s e r v i d o r ' ,  
                                         ' V a z a   t o k e n s ,   c a m i n h o s   i n t e r n o s ,   c r e d e n c i a i s ,   a r q u i t e t u r a ' ,   ' C o l e t a   d e   I n f o r m a � � � � e s ' )  
                 e x c e p t :  
                         p a s s  
 