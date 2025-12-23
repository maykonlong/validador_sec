"""
Context Analyzer - Ajusta severidade baseado em contexto
Aumenta precisão diferenciando endpoints críticos de menos sensíveis
"""

class ContextAnalyzer:
    """Analisa contexto de URLs e ajusta severidade de findings."""
    
    def detect_context(self, url):
        """
        Detecta contexto do endpoint.
        
        Returns:
            dict: Contexto detectado
        """
        url_lower = url.lower()
        
        context = {
            'is_admin_endpoint': self._is_admin(url_lower),
            'is_api_endpoint': self._is_api(url_lower),
            'is_auth_endpoint': self._is_auth(url_lower),
            'is_public_endpoint': self._is_public(url_lower),
            'handles_user_data': self._handles_user_data(url_lower),
            'is_financial': self._is_financial(url_lower),
            'url': url,
        }
        
        return context
    
    def _is_admin(self, url):
        """Detecta endpoints administrativos."""
        admin_patterns = [
            '/admin', '/administrator', '/manage', '/dashboard',
            '/panel', '/cpanel', '/backoffice', '/console'
        ]
        return any(pattern in url for pattern in admin_patterns)
    
    def _is_api(self, url):
        """Detecta endpoints de API."""
        api_patterns = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']
        return any(pattern in url for pattern in api_patterns)
    
    def _is_auth(self, url):
        """Detecta endpoints de autenticação."""
        auth_patterns = [
            '/login', '/signin', '/auth', '/oauth',
            '/register', '/signup', '/password'
        ]
        return any(pattern in url for pattern in auth_patterns)
    
    def _is_public(self, url):
        """Detecta endpoints públicos."""
        public_patterns = [
            '/public', '/static', '/assets', '/css',
            '/js', '/images', '/img', '/favicon'
        ]
        return any(pattern in url for pattern in public_patterns)
    
    def _handles_user_data(self, url):
        """Detecta se lida com dados de usuário."""
        user_patterns = [
            '/user', '/profile', '/account', '/customer',
            '/member', '/settings', '/preferences'
        ]
        return any(pattern in url for pattern in user_patterns)
    
    def _is_financial(self, url):
        """Detecta endpoints financeiros."""
        financial_patterns = [
            '/payment', '/checkout', '/billing', '/invoice',
            '/transaction', '/wallet', '/bank', '/card'
        ]
        return any(pattern in url for pattern in financial_patterns)
    
    def adjust_severity(self, base_severity, context):
        """
        Ajusta severidade baseado no contexto.
        
        Args:
            base_severity: str - Low/Medium/High/Critical
            context: dict - Contexto do endpoint
        
        Returns:
            str: Severidade ajustada
        """
        severity_map = {
            'Info': 0,
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4,
        }
        
        current_level = severity_map.get(base_severity, 2)
        
        # Upgrade conditions
        upgrades = 0
        
        # Admin endpoint: +1 level
        if context.get('is_admin_endpoint'):
            upgrades += 1
        
        # Financial endpoint: +1 level
        if context.get('is_financial'):
            upgrades += 1
        
        # Auth endpoint + High: → Critical
        if context.get('is_auth_endpoint') and current_level >= 3:
            upgrades += 1
        
        # User data: +0.5 level (rounded)
        if context.get('handles_user_data'):
            upgrades += 0.5
        
        # Downgrade conditions
        downgrades = 0
        
        # Public/static endpoint: -1 level
        if context.get('is_public_endpoint'):
            downgrades += 1
        
        # Calculate final level
        final_level = int(current_level + upgrades - downgrades)
        final_level = max(0, min(4, final_level))  # Clamp 0-4
        
        # Convert back to string
        reverse_map = {v: k for k, v in severity_map.items()}
        adjusted_severity = reverse_map.get(final_level, base_severity)
        
        return adjusted_severity
    
    def get_context_description(self, context):
        """
        Gera descrição legível do contexto.
        
        Returns:
            str: Descrição do contexto
        """
        descriptions = []
        
        if context.get('is_admin_endpoint'):
            descriptions.append('⚠️ Endpoint Administrativo')
        if context.get('is_financial'):
            descriptions.append('💳 Endpoint Financeiro')
        if context.get('is_auth_endpoint'):
            descriptions.append('🔐 Endpoint de Autenticação')
        if context.get('handles_user_data'):
            descriptions.append('👤 Lida com Dados de Usuário')
        if context.get('is_api_endpoint'):
            descriptions.append('🔌 API Endpoint')
        if context.get('is_public_endpoint'):
            descriptions.append('🌐 Endpoint Público')
        
        return ' | '.join(descriptions) if descriptions else 'Endpoint Padrão'
