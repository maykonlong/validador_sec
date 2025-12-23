"""
Progressive Tester - Testa progressivamente do leve ao agressivo
Minimiza impacto e maximiza confiança através de testes em fases
"""

class ProgressiveTester:
    """Framework para testes progressivos (passive → active → aggressive)."""
    
    # Test levels
    PASSIVE = 'passive'
    ACTIVE = 'active'
    AGGRESSIVE = 'aggressive'
    
    def __init__(self):
        self.current_level = self.PASSIVE
        self.test_results = []
    
    def should_escalate(self, initial_result):
        """
        Decide se deve escalar para próximo nível.
        
        Args:
            initial_result: dict - Resultado do teste inicial
        
        Returns:
            bool: True se deve escalar
        """
        # Escalar se suspeita foi encontrada
        if initial_result.get('suspected'):
            return True
        
        # Escalar se evidência parcial
        if initial_result.get('partial_evidence'):
            return True
        
        return False
    
    def test_sqli_progressive(self, url, param, validator):
        """
        Testa SQLi progressivamente.
        
        Phase 1 (PASSIVE): Error-based detection
        Phase 2 (ACTIVE): Boolean-based validation  
        Phase 3 (AGGRESSIVE): Time-based validation
        
        Returns:
            dict: Resultado consolidado
        """
        result = {
            'vulnerable': False,
            'technique': None,
            'phases_executed': [],
            'evidence': {}
        }
        
        # Phase 1: Passive (Error-based)
        self.current_level = self.PASSIVE
        result['phases_executed'].append('Error-based (Passive)')
        
        error_found = self._test_sql_error(url, param)
        
        if not error_found:
            # Sem erro, não vale a pena continuar
            return result
        
        # Phase 2: Active (Boolean-based)
        if self.should_escalate({'suspected': error_found}):
            self.current_level = self.ACTIVE
            result['phases_executed'].append('Boolean-based (Active)')
            
            boolean_result = self._test_sql_boolean(url, param, validator)
            
            if boolean_result['vulnerable']:
                result['vulnerable'] = True
                result['technique'] = 'Boolean-based'
                result['evidence'] = boolean_result.get('evidence', {})
                return result
        
        # Phase 3: Aggressive (Time-based)
        if self.should_escalate({'partial_evidence': True}):
            self.current_level = self.AGGRESSIVE
            result['phases_executed'].append('Time-based (Aggressive)')
            
            time_result = self._test_sql_time(url, param, validator)
            
            if time_result['vulnerable']:
                result['vulnerable'] = True
                result['technique'] = 'Time-based blind'
                result['evidence'] = time_result.get('evidence', {})
        
        return result
    
    def _test_sql_error(self, url, param):
        """Phase 1: Error-based (read-only)."""
        # Implementação básica - apenas verifica erro
        return False  # Placeholder
    
    def _test_sql_boolean(self, url, param, validator):
        """Phase 2: Boolean-based (read-only)."""
        if hasattr(validator, '_test_sql_boolean'):
            return validator._test_sql_boolean(url, param)
        return {'vulnerable': False}
    
    def _test_sql_time(self, url, param, validator):
        """Phase 3: Time-based (low-impact)."""
        if hasattr(validator, '_test_sql_time_based'):
            return validator._test_sql_time_based(url, param)
        return {'vulnerable': False}
    
    def test_xss_progressive(self, url, param, validator):
        """
        Testa XSS progressivamente.
        
        Phase 1 (PASSIVE): Reflection detection
        Phase 2 (ACTIVE): Execution validation
        
        Returns:
            dict: Resultado consolidado
        """
        result = {
            'executable': False,
            'phases_executed': [],
            'evidence': {}
        }
        
        # Phase 1: Check reflection
        self.current_level = self.PASSIVE
        result['phases_executed'].append('Reflection (Passive)')
        
        payload = '<script>alert(1)</script>'
        # Simplified check - real implementation would do actual request
        reflected = False  # Placeholder
        
        if not reflected:
            return result
        
        # Phase 2: Validate execution
        if self.should_escalate({'suspected': reflected}):
            self.current_level = self.ACTIVE
            result['phases_executed'].append('Execution (Active)')
            
            if hasattr(validator, 'validate_xss'):
                xss_result = validator.validate_xss(url, param)
                result['executable'] = xss_result.get('executable', False)
                result['evidence'] = xss_result.get('evidence', {})
        
        return result
    
    def get_impact_level(self):
        """
        Retorna impacto do nível atual de testes.
        
        Returns:
            str: Descrição do impacto
        """
        impact_map = {
            self.PASSIVE: 'Nenhum impacto (read-only)',
            self.ACTIVE: 'Baixo impacto (non-destructive)',
            self.AGGRESSIVE: 'Médio impacto (time-delays only)',
        }
        return impact_map.get(self.current_level, 'Desconhecido')
    
    def should_perform_aggressive_tests(self, findings_so_far):
        """
        Decide se testes agressivos devem ser executados.
        
        Args:
            findings_so_far: list - Findings encontrados até agora
        
        Returns:
            bool: True se testes agressivos valem a pena
        """
        # Só fazer testes agressivos se já encontrou várias suspeitas
        suspected_count = sum(1 for f in findings_so_far 
                            if f.get('confidence_label') == 'SUSPECTED')
        
        # Se já tem 3+ suspeitas, vale a pena confirmar com testes agressivos
        return suspected_count >= 3
    
    def get_testing_summary(self):
        """
        Retorna resumo dos testes executados.
        
        Returns:
            dict: Resumo
        """
        return {
            'total_phases': len(self.test_results),
            'highest_level': self.current_level,
            'impact': self.get_impact_level(),
        }
