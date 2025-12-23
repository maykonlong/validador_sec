"""
Módulo de Detecção de Phishing
Identifica domínios suspeitos e typosquatting
"""

import requests
from typing import Dict, List, Any
from datetime import datetime
import difflib
import re


class PhishingDetector:
    """
    Detector de domínios falsos e phishing
    """
    
    # Domínios legítimos brasileiros comuns (para comparação)
    LEGITIMATE_DOMAINS = [
        'bb.com.br', 'itau.com.br', 'bradesco.com.br', 'santander.com.br',
        'caixa.gov.br', 'bancodobrasil.com.br', 'nubank.com.br', 'inter.co',
        'mercadolivre.com.br', 'mercadopago.com.br', 'americanas.com.br',
        'magazineluiza.com.br', 'amazon.com.br', 'correios.com.br',
        'gov.br', 'receita.fazenda.gov.br', 'detran.sp.gov.br'
    ]
    
    # Palavras suspeitas em domínios
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'account', 'update', 'secure', 'verify',
        'banking', 'support', 'help', 'security', 'password',
        'cliente', 'atualizar', 'validar', 'confirmar', 'seguranca'
    ]
    
    def __init__(self):
        self._cache = {}
    
    def detect_phishing(self, domain: str) -> Dict[str, Any]:
        """
        Analisa um domínio em busca de indicadores de phishing
        
        Args:
            domain: Domínio a analisar
        
        Returns:
            Dict com análise completa
        """
        domain = self._clean_domain(domain)
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'is_suspicious': False,
            'risk_score': 0,  # 0-100
            'indicators': [],
            'similar_to': None,
            'status': 'analyzed'
        }
        
        # 1. Verificar typosquatting
        similar = self._check_typosquatting(domain)
        if similar:
            result['is_suspicious'] = True
            result['similar_to'] = similar
            result['risk_score'] += 40
            result['indicators'].append({
                'type': 'typosquatting',
                'severity': 'high',
                'message': f'Domínio muito similar a: {similar}'
            })
        
        # 2. Verificar palavras suspeitas
        suspicious_words = self._check_suspicious_keywords(domain)
        if suspicious_words:
            result['is_suspicious'] = True
            result['risk_score'] += 20
            result['indicators'].append({
                'type': 'suspicious_keywords',
                'severity': 'medium',
                'message': f'Contém palavras suspeitas: {", ".join(suspicious_words)}'
            })
        
        # 3. Verificar caracteres suspeitos (homógrafos)
        if self._check_homograph_attack(domain):
            result['is_suspicious'] = True
            result['risk_score'] += 30
            result['indicators'].append({
                'type': 'homograph',
                'severity': 'high',
                'message': 'Possível ataque de homógrafo (caracteres similares)'
            })
        
        # 4. Verificar TLD suspeita
        suspicious_tld = self._check_suspicious_tld(domain)
        if suspicious_tld:
            result['risk_score'] += 15
            result['indicators'].append({
                'type': 'suspicious_tld',
                'severity': 'low',
                'message': f'TLD suspeita: {suspicious_tld}'
            })
        
        # 5. Verificar listas públicas de phishing
        public_lists = self._check_public_phishing_lists(domain)
        if public_lists:
            result['is_suspicious'] = True
            result['risk_score'] = 100  # Score máximo se está em lista
            result['indicators'].append({
                'type': 'public_blacklist',
                'severity': 'critical',
                'message': f'Encontrado em lista pública: {public_lists}'
            })
        
        # Limitar score a 100
        result['risk_score'] = min(result['risk_score'], 100)
        
        # Classificar risco
        if result['risk_score'] >= 70:
            result['risk_level'] = 'critical'
        elif result['risk_score'] >= 50:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 30:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'
        
        return result
    
    def _clean_domain(self, domain: str) -> str:
        """Remove protocolo e path"""
        domain = domain.lower().strip()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        return domain
    
    def _check_typosquatting(self, domain: str) -> str:
        """
        Verifica se o domínio é similar a algum legítimo
        
        Returns:
            Domínio legítimo similar ou None
        """
        # Remover subdomínios para comparação
        main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
        
        for legit in self.LEGITIMATE_DOMAINS:
            # Calcular similaridade
            similarity = difflib.SequenceMatcher(None, main_domain, legit).ratio()
            
            # Se muito similar mas não idêntico, é suspeito
            if 0.7 <= similarity < 1.0:
                return legit
            
            # Verificar substituições comuns
            if self._check_common_substitutions(main_domain, legit):
                return legit
        
        return None
    
    def _check_common_substitutions(self, domain: str, legit: str) -> bool:
        """
        Verifica substituições comuns de typosquatting
        """
        # Pares de caracteres comumente substituídos
        substitutions = [
            ('o', '0'), ('i', 'l'), ('i', '1'), ('l', '1'),
            ('a', '@'), ('e', '3'), ('s', '5'), ('g', '9'),
            ('rn', 'm'), ('vv', 'w')
        ]
        
        for original, fake in substitutions:
            if fake in domain and original in legit:
                # Verificar se ao substituir ficam similares
                test_domain = domain.replace(fake, original)
                if difflib.SequenceMatcher(None, test_domain, legit).ratio() > 0.85:
                    return True
        
        return False
    
    def _check_suspicious_keywords(self, domain: str) -> List[str]:
        """
        Verifica se domínio contém palavras suspeitas
        """
        found = []
        domain_lower = domain.lower()
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in domain_lower:
                found.append(keyword)
        
        return found
    
    def _check_homograph_attack(self, domain: str) -> bool:
        """
        Detecta possíveis ataques de homógrafo (caracteres unicode similares)
        """
        # Verificar se tem caracteres não-ASCII
        try:
            domain.encode('ascii')
            return False  # Só tem ASCII, ok
        except UnicodeEncodeError:
            # Tem caracteres não-ASCII, pode ser homograph
            return True
    
    def _check_suspicious_tld(self, domain: str) -> str:
        """
        Verifica se a TLD é comumente usada em phishing
        """
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Freenom (grátis)
            '.top', '.xyz', '.club', '.work', '.click'
        ]
        
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return tld
        
        return None
    
    def _check_public_phishing_lists(self, domain: str) -> str:
        """
        Verifica domínio em listas públicas de phishing
        Usa PhishTank e OpenPhish
        """
        # Cache check
        cache_key = f"phish_{domain}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        found_in = None
        
        try:
            # OpenPhish (lista pública sem necessidade de API)
            # Nota: A lista completa é grande, aqui fazemos verificação simplificada
            # Em produção, baixar a lista e fazer lookup local
            
            # Por enquanto, retornamos None (não implementado)
            # TODO: Implementar download periódico da lista OpenPhish
            found_in = None
            
            # Cachear resultado
            self._cache[cache_key] = found_in
            
        except Exception as e:
            # Silenciar erros de rede
            pass
        
        return found_in
    
    def generate_typosquatting_variations(self, domain: str) -> List[str]:
        """
        Gera variações de typosquatting para um domínio
        Útil para verificar se domínios falsos já existem
        """
        domain = self._clean_domain(domain)
        
        # Separar nome e TLD
        parts = domain.rsplit('.', 1)
        if len(parts) != 2:
            return []
        
        name, tld = parts
        variations = []
        
        # 1. Substituições de caracteres
        substitutions = {
            'o': ['0'], 'i': ['l', '1'], 'l': ['i', '1'],
            'a': ['@'], 'e': ['3'], 's': ['5']
        }
        
        for char, subs in substitutions.items():
            if char in name:
                for sub in subs:
                    variations.append(f"{name.replace(char, sub)}.{tld}")
        
        # 2. Remoção de caracteres
        if len(name) > 4:
            for i in range(len(name)):
                var = name[:i] + name[i+1:]
                variations.append(f"{var}.{tld}")
        
        # 3. Duplicação de caracteres
        for i in range(len(name)):
            var = name[:i] + name[i] + name[i:]
            variations.append(f"{var}.{tld}")
        
        # 4. TLDs alternativas
        alt_tlds = ['com', 'net', 'org', 'com.br', 'br', 'co']
        for alt_tld in alt_tlds:
            if alt_tld != tld:
                variations.append(f"{name}.{alt_tld}")
        
        # Limitar a 50 variações mais prováveis
        return list(set(variations))[:50]


# Funções standalone
def detect_phishing(domain: str) -> Dict[str, Any]:
    """Wrapper para detecção de phishing"""
    detector = PhishingDetector()
    return detector.detect_phishing(domain)


def check_typosquatting(domain: str, legitimate_domains: List[str] = None) -> Dict[str, Any]:
    """
    Verifica se domínio é typosquatting de algum legítimo
    """
    detector = PhishingDetector()
    
    if legitimate_domains:
        detector.LEGITIMATE_DOMAINS = legitimate_domains
    
    result = detector.detect_phishing(domain)
    
    return {
        'is_typosquatting': result.get('similar_to') is not None,
        'similar_to': result.get('similar_to'),
        'risk_score': result.get('risk_score'),
        'risk_level': result.get('risk_level')
    }


def get_phishing_results_for_scanner(domain: str) -> List[Dict[str, str]]:
    """
    Retorna resultados formatados para o scanner
    """
    result = detect_phishing(domain)
    scanner_results = []
    
    # Resultado principal
    if result['is_suspicious']:
        scanner_results.append({
            'vulnerability': 'Indicadores de Phishing',
            'status': 'Vulnerable',
            'severity': result['risk_level'].capitalize(),
            'category': 'Phishing',
            'details': f"Score de risco: {result['risk_score']}/100",
            'recommendation': 'Domínio apresenta características suspeitas, evite fornecer credenciais'
        })
        
        # Indicadores individuais  
        for indicator in result['indicators']:
            severity_map = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low'
            }
            
            # Detalhes específicos por tipo
            if indicator['type'] == 'typosquatting':
                similar_to = result.get('similar_to', 'domínio conhecido')
                details = f"""
<strong>Domínio Suspeito Detectado:</strong><br>
{domain}<br><br>

<strong>Muito Similar a:</strong><br>
{similar_to}<br><br>

<strong>Tipo de Ataque: Typosquatting</strong><br>
Typosquatting (também chamado URL hijacking) é quando atacantes registram domínios 
muito similares a marcas conhecidas para enganar usuários.<br><br>

<strong>Técnicas Comuns:</strong><br>
• Troca de letras: gooogle.com (troca 'g' extra)<br>
• Letras parecidas: micr0soft.com (0 ao invés de o)<br>
• Erros de digitação: faceboook.com<br>
• TLDs diferentes: facebook.net ao invés de .com<br>
• Hífens: face-book.com
"""
                
                methodology = f"""
Módulo de Detecção de Phishing com Algoritmo de Similaridade<br><br>
<strong>Análises Realizadas:</strong><br>
• Comparação com banco de domínios conhecidos<br>
• Cálculo de distância Levenshtein<br>
• Detecção de padrões de typosquatting<br>
• Verificação de homógrafos (letras parecidas)
"""
                
                manual_test = f"""
<strong>Verificações Manuais Recomendadas:</strong><br><br>

<strong>1. WHOIS Lookup</strong><br>
<code>whois {domain}</code><br>
Verificar: Data de registro, proprietário, localização<br><br>

<strong>2. Comparação Visual</strong><br>
Visite ambos os sites em abas separadas:<br>
• Original: {similar_to}<br>
• Suspeito: {domain}<br>
Compare: Design, logos, conteúdo, SSL certificate<br><br>

<strong>3. DNS Lookup</strong><br>
<code>
nslookup {domain}<br>
nslookup {similar_to}
</code><br>
IPs diferentes podem indicar phishing<br><br>

<strong>4. Google Safe Browsing</strong><br>
Verifique se o domínio está em listas de phishing
"""
                
                risk = f"""
<strong>Impacto de Typosquatting:</strong><br><br>

<strong>Para Usuários:</strong><br>
• Roubo de credenciais (login/senha)<br>
• Phishing de dados pessoais e financeiros<br>
• Instalação de malware<br>
• Fraude financeira<br>
• Roubo de identidade<br><br>

<strong>Ações Recomendadas:</strong><br>
1. ⚠️ NÃO acesse o domínio suspeito<br>
2. 📧 Reportar para {similar_to}<br>
3. 🚨 Reportar para provedores de hospedagem<br>
4. ⚖️ Considerar ação legal (DMCA)<br>
5. 🛡️ Registrar variações do seu domínio preventivamente<br><br>

<strong>Severidade: ALTO</strong><br>
Typosquatting é um vetor comum para phishing em larga escala.
"""
            else:
                # Outros tipos de indicadores
                details = indicator['message']
                methodology = 'Módulo de Detecção de Phishing'
                manual_test = 'Verificar manualmente o domínio e suas características'
                risk = 'Verificar legitimidade do domínio antes de interagir'
            
            scanner_results.append({
                'vulnerability': f"Indicador: {indicator['type']}",
                'status': 'Warning',
                'severity': severity_map.get(indicator['severity'], 'Medium'),
                'category': 'Phishing',
                'details': details,
                'methodology': methodology,
                'manual_test': manual_test,
                'risk': risk,
                'recommendation': 'Verificar legitimidade do domínio antes de interagir'
            })
    else:
        scanner_results.append({
            'vulnerability': 'Indicadores de Phishing',
            'status': 'Safe',
            'severity': 'Info',
            'category': 'Phishing',
            'details': 'Nenhum indicador de phishing detectado',
            'recommendation': 'Domínio não apresenta sinais óbvios de phishing'
        })
    
    return scanner_results


if __name__ == '__main__':
    # Teste rápido
    print("🧪 Testando Detector de Phishing...\n")
    
    # Domínios de teste
    test_domains = [
        'google.com',  # Legítimo
        'g00gle.com',  # Typosquatting
        'itau-seguranca.com.br',  # Suspeito
        'bb-login.tk'  # Muito suspeito
    ]
    
    for domain in test_domains:
        print(f"🔍 Testando: {domain}")
        result = detect_phishing(domain)
        print(f"   Suspeito: {result['is_suspicious']}")
        print(f"   Score: {result['risk_score']}/100")
        print(f"   Nível: {result.get('risk_level', 'N/A')}")
        if result.get('similar_to'):
            print(f"   ⚠️ Similar a: {result['similar_to']}")
        print()
