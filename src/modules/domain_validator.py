"""
Módulo de Validação de Domínios
Inclui: WHOIS, DNS, SSL/TLS, Geo-IP
"""

import socket
import ssl
import requests
from datetime import datetime
from typing import Dict, List, Any
import re


def validate_domain(domain: str) -> Dict[str, Any]:
    """
    Valida um domínio completamente
    
    Args:
        domain: Domínio a validar (ex: 'exemplo.com')
    
    Returns:
        Dict com todos os dados de validação
    """
    # Limpar domínio
    domain = clean_domain(domain)
    
    results = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'whois': get_whois_info(domain),
        'dns': check_dns(domain),
        'subdomains': enumerate_subdomains(domain),
        'ssl': check_ssl(domain),
        'geo_ip': get_geo_ip(domain),
        'status': 'completed'
    }
    
    return results


def clean_domain(domain: str) -> str:
    """Remove protocolo e path do domínio"""
    domain = domain.lower().strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    return domain


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Obtém informações WHOIS do domínio
    Versão simplificada - será expandida com python-whois
    """
    try:
        # Por enquanto, retorna estrutura básica
        # TODO: Implementar com python-whois após instalação
        return {
            'available': False,
            'registrar': 'Pending implementation',
            'creation_date': None,
            'expiration_date': None,
            'status': 'pending_library'
        }
    except Exception as e:
        return {
            'error': str(e),
            'status': 'error'
        }


def check_dns(domain: str) -> Dict[str, Any]:
    """
    Verifica registros DNS do domínio
    """
    dns_results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'TXT': [],
        'NS': [],
        'status': 'ok'
    }
    
    try:
        # Registro A (IPv4)
        try:
            ip = socket.gethostbyname(domain)
            dns_results['A'].append(ip)
        except socket.gaierror:
            dns_results['A'] = None
        
        # TODO: Implementar outros registros com dnspython
        # Por enquanto, apenas A record básico
        
        return dns_results
        
    except Exception as e:
        dns_results['status'] = 'error'
        dns_results['error'] = str(e)
        return dns_results


def check_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Verifica certificado SSL/TLS do domínio
    """
    ssl_info = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'version': None,
        'not_before': None,
        'not_after': None,
        'days_remaining': None,
        'san': [],
        'status': 'checking'
    }
    
    try:
        # Criar contexto SSL
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extrair informações do certificado
                ssl_info['valid'] = True
                ssl_info['version'] = ssock.version()
                
                # Issuer (Emissor)
                issuer = dict(x[0] for x in cert['issuer'])
                ssl_info['issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Subject (Assunto)
                subject = dict(x[0] for x in cert['subject'])
                ssl_info['subject'] = subject.get('commonName', domain)
                
                # Datas de validade
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                
                ssl_info['not_before'] = not_before
                ssl_info['not_after'] = not_after
                
                # Calcular dias restantes
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days
                ssl_info['days_remaining'] = days_remaining
                
                # Subject Alternative Names
                san = cert.get('subjectAltName', [])
                ssl_info['san'] = [x[1] for x in san if x[0] == 'DNS']
                
                ssl_info['status'] = 'valid'
                
                # Alertas
                if days_remaining < 30:
                    ssl_info['warning'] = f'Certificado expira em {days_remaining} dias'
                
    except ssl.SSLError as e:
        ssl_info['status'] = 'ssl_error'
        ssl_info['error'] = str(e)
    except socket.timeout:
        ssl_info['status'] = 'timeout'
        ssl_info['error'] = 'Timeout ao conectar'
    except Exception as e:
        ssl_info['status'] = 'error'
        ssl_info['error'] = str(e)
    
    return ssl_info


def get_geo_ip(domain: str) -> Dict[str, Any]:
    """
    Obtém localização geográfica do IP do domínio
    Usa API pública ip-api.com (sem necessidade de key)
    """
    geo_info = {
        'ip': None,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'isp': None,
        'org': None,
        'status': 'checking'
    }
    
    try:
        # Resolver IP
        ip = socket.gethostbyname(domain)
        geo_info['ip'] = ip
        
        # Consultar API de geolocalização
        response = requests.get(
            f'http://ip-api.com/json/{ip}',
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                geo_info['country'] = data.get('country')
                geo_info['country_code'] = data.get('countryCode')
                geo_info['region'] = data.get('regionName')
                geo_info['city'] = data.get('city')
                geo_info['isp'] = data.get('isp')
                geo_info['org'] = data.get('org')
                geo_info['lat'] = data.get('lat')
                geo_info['lon'] = data.get('lon')
                geo_info['status'] = 'success'
            else:
                geo_info['status'] = 'not_found'
        else:
            geo_info['status'] = 'api_error'
            
    except socket.gaierror:
        geo_info['status'] = 'dns_error'
        geo_info['error'] = 'Não foi possível resolver o domínio'
    except requests.RequestException as e:
        geo_info['status'] = 'error'
        geo_info['error'] = str(e)
    except Exception as e:
        geo_info['status'] = 'error'
        geo_info['error'] = str(e)
    
    return geo_info


def format_domain_report(validation_data: Dict[str, Any]) -> str:
    """
    Formata os dados de validação em texto legível
    """
    domain = validation_data['domain']
    report = [f"=== Relatório de Validação: {domain} ===\n"]
    
    # WHOIS
    whois = validation_data.get('whois', {})
    report.append("📋 WHOIS:")
    report.append(f"  Status: {whois.get('status', 'unknown')}")
    
    # DNS
    dns = validation_data.get('dns', {})
    report.append("\n🌐 DNS:")
    if dns.get('A'):
        report.append(f"  IP (A): {', '.join(dns['A'])}")
    
    # SSL
    ssl_data = validation_data.get('ssl', {})
    report.append("\n🔒 SSL/TLS:")
    report.append(f"  Status: {ssl_data.get('status', 'unknown')}")
    if ssl_data.get('valid'):
        report.append(f"  Emissor: {ssl_data.get('issuer')}")
        report.append(f"  Válido até: {ssl_data.get('not_after')}")
        report.append(f"  Dias restantes: {ssl_data.get('days_remaining')}")
    
    # Geo-IP
    geo = validation_data.get('geo_ip', {})
    report.append("\n🌍 Localização:")
    if geo.get('status') == 'success':
        report.append(f"  IP: {geo.get('ip')}")
        report.append(f"  País: {geo.get('country')} ({geo.get('country_code')})")
        report.append(f"  Cidade: {geo.get('city')}")
        report.append(f"  ISP: {geo.get('isp')}")
    else:
        report.append(f"  Status: {geo.get('status')}")
    
    return '\n'.join(report)


# Função auxiliar para integração com o scanner
def get_domain_validation_results(domain: str) -> List[Dict[str, str]]:
    """
    Retorna resultados formatados para o scanner do Validador SEC
    
    Returns:
        Lista de dicts no formato esperado pelo scanner
    """
    validation = validate_domain(domain)
    results = []
    
    # 1. SSL/TLS Analysis
    ssl_data = validation.get('ssl', {})
    if ssl_data.get('status') == 'valid':
        days = ssl_data.get('days_remaining', 999)
        severity = 'Info'
        status = 'Safe'
        
        if days < 30:
            severity = 'Medium'
            status = 'Warning'
        if days < 7:
            severity = 'High'
            status = 'Warning'
        
        # Formatar detalhes em HTML
        details_html = f"""
        <strong>✅ Certificado SSL Válido</strong><br>
        <div style='margin-top: 8px; padding-left: 15px;'>
            📌 <strong>Emissor:</strong> {ssl_data.get('issuer', 'Desconhecido')}<br>
            🔐 <strong>Versão:</strong> {ssl_data.get('version', 'N/A')}<br>
            📅 <strong>Válido de:</strong> {ssl_data.get('not_before', 'N/A')}<br>
            📅 <strong>Válido até:</strong> {ssl_data.get('not_after', 'N/A')}<br>
            ⏰ <strong>Dias restantes:</strong> <span style='color: {"#ff6600" if days < 30 else "#00ff9d"};'>{days} dias</span>
        </div>
        """
        
        if ssl_data.get('san'):
            details_html += f"""
            <div style='margin-top: 8px; padding-left: 15px;'>
                🌐 <strong>Domínios alternativos (SAN):</strong><br>
                <div style='padding-left: 10px; font-size: 0.9em;'>{', '.join(ssl_data['san'][:5])}</div>
            </div>
            """
        
        results.append({
            'vulnerability': '🔒 Análise SSL/TLS Completa',
            'status': status,
            'severity': severity,
            'category': 'Domínio',
            'details': details_html,
            'recommendation': 'Renovar certificado' if days < 30 else 'Certificado em bom estado'
        })
    else:
        results.append({
            'vulnerability': '🔒 Análise SSL/TLS',
            'status': 'Vulnerable',
            'severity': 'High',
            'category': 'Domínio',
            'details': f"""
            <strong>❌ Certificado Inválido ou Inexistente</strong><br>
            <div style='margin-top: 8px; padding-left: 15px;'>
                ⚠️ <strong>Erro:</strong> {ssl_data.get('error', 'Certificado não encontrado')}<br>
                🔴 <strong>Status:</strong> {ssl_data.get('status', 'error')}
            </div>
            """,
            'recommendation': 'Instalar certificado SSL válido de uma Autoridade Certificadora confiável (Let\'s Encrypt, DigiCert, etc)'
        })
    
    # 2. Geo-IP & Server Location
    geo = validation.get('geo_ip', {})
    if geo.get('status') == 'success':
        details_html = f"""
        <strong>🌍 Localização Geográfica do Servidor</strong><br>
        <div style='margin-top: 8px; padding-left: 15px;'>
            🖥️ <strong>IP:</strong> {geo.get('ip', 'N/A')}<br>
            🌐 <strong>País:</strong> {geo.get('country', 'N/A')} ({geo.get('country_code', 'N/A')})<br>
            🏙️ <strong>Região/Cidade:</strong> {geo.get('region', 'N/A')} / {geo.get('city', 'N/A')}<br>
            🏢 <strong>ISP:</strong> {geo.get('isp', 'N/A')}<br>
            🏛️ <strong>Organização:</strong> {geo.get('org', 'N/A')}
        </div>
        """
        
        if geo.get('lat') and geo.get('lon'):
            details_html += f"""
            <div style='margin-top: 8px; padding-left: 15px;'>
                📍 <strong>Coordenadas:</strong> {geo.get('lat')}, {geo.get('lon')}
            </div>
            """
        
        results.append({
            'vulnerability': '🌍 Informações Geográficas',
            'status': 'Info',
            'severity': 'Info',
            'category': 'Domínio',
            'details': details_html,
            'recommendation': 'Dados informativos sobre localização do servidor'
        })
    
    # 3. DNS Resolution
    dns = validation.get('dns', {})
    if dns.get('A'):
        ips_list = dns.get('A', [])
        details_html = f"""
        <strong>🌐 Resolução DNS Bem-Sucedida</strong><br>
        <div style='margin-top: 8px; padding-left: 15px;'>
            📡 <strong>Registros A (IPv4):</strong><br>
            <div style='padding-left: 10px;'>
                {', '.join([f'<code>{ip}</code>' for ip in ips_list])}
            </div>
        </div>
        """
        
        results.append({
            'vulnerability': '🌐 Análise DNS',
            'status': 'Safe',
            'severity': 'Info',
            'category': 'Domínio',
            'details': details_html,
            'recommendation': 'DNS configurado corretamente'
        })
    else:
        results.append({
            'vulnerability': '🌐 Análise DNS',
            'status': 'Warning',
            'severity': 'Medium',
            'category': 'Domínio',
            'details': """
            <strong>⚠️ Problema na Resolução DNS</strong><br>
            <div style='margin-top: 8px; padding-left: 15px;'>
                Não foi possível resolver o domínio para um endereço IP
            </div>
            """,
            'recommendation': 'Verificar configurações de DNS'
        })
    
    # 4. Subdomains Enumeration (NOVO - FALTAVA ISSO!)
    subdomains = validation.get('subdomains', [])
    if subdomains and len(subdomains) > 0:
        # Criar lista HTML dos subdomínios
        subs_html_list = '<br>'.join([f'• <code>{sub}</code>' for sub in subdomains[:20]])
        
        details_html = f"""
        <strong>🔍 Subdomínios Descobertos</strong><br>
        <div style='margin-top: 8px; padding-left: 15px;'>
            📊 <strong>Total encontrado:</strong> {len(subdomains)} subdomínios<br>
            🌐 <strong>Método:</strong> Certificate Transparency (crt.sh)<br><br>
            <strong>Lista de Subdomínios:</strong><br>
            <div style='padding-left: 10px; font-size: 0.9em; max-height: 200px; overflow-y: auto; margin-top: 5px;'>
                {subs_html_list}
            </div>
        </div>
        """
        
        if len(subdomains) > 20:
            details_html += f"""
            <div style='margin-top: 8px; padding-left: 15px; color: #94a3b8; font-size: 0.85em;'>
                ℹ️ Mostrando 20 de {len(subdomains)} subdomínios encontrados
            </div>
            """
        
        results.append({
            'vulnerability': '🔍 Enumeração de Subdomínios',
            'status': 'Info',
            'severity': 'Info',
            'category': 'Domínio',
            'details': details_html,
            'recommendation': 'Revisar subdomínios expostos e verificar se todos devem estar públicos'
        })
    
    # 5. WHOIS Info  
    whois = validation.get('whois', {})
    if whois.get('status') != 'pending_library':
        details_html = f"""
        <strong>📋 Informações WHOIS</strong><br>
        <div style='margin-top: 8px; padding-left: 15px;'>
            🏢 <strong>Registrador:</strong> {whois.get('registrar', 'N/A')}<br>
            📅 <strong>Data de criação:</strong> {whois.get('creation_date', 'N/A')}<br>
            📅 <strong>Data de expiração:</strong> {whois.get('expiration_date', 'N/A')}
        </div>
        """
        
        results.append({
            'vulnerability': '📋 Registro WHOIS',
            'status': 'Info',
            'severity': 'Info',
            'category': 'Domínio',
            'details': details_html,
            'recommendation': 'Dados de registro do domínio'
        })
    
    return results


def enumerate_subdomains(domain: str) -> List[str]:
    """
    Enumeração passiva de subdomínios usando Certificate Transparency (crt.sh)
    Rápido, passivo e não sobrecarrega a rede local.
    """
    subdomains = set()
    try:
        # User-Agent para evitar bloqueio
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                # crt.sh pode retornar multiplos dominios por linha
                for sub in name_value.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and '*' not in sub:
                         subdomains.add(sub)
    except Exception:
        # Falha silenciosa em caso de API offline
        pass
        
    # Retorna lista ordenada, top 50
    return sorted(list(subdomains))[:50]


if __name__ == '__main__':
    # Teste rápido
    print("🧪 Testando Validador de Domínios...\n")
    
    test_domain = "google.com"
    print(f"Testando: {test_domain}\n")
    
    result = validate_domain(test_domain)
    print(format_domain_report(result))
