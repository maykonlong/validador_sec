"""
Confidence Scorer - Calcula confiança para cada finding
Reduz falsos positivos através de scoring inteligente
"""

class ConfidenceScorer:
    """Calcula score de confiança (0.0-1.0) para findings."""
    
    def calculate_confidence(self, finding):
        """
        Calcula confidence score baseado em múltiplos fatores.
        
        Returns:
            float: 0.0-1.0 (0% a 100% de confiança)
        """
        score = 0.0
        
        # Factor 1: Validação foi executada? (+30%)
        if finding.get('validation_performed'):
            score += 0.3
        
        # Factor 2: Múltiplas técnicas confirmaram? (+40%)
        confirmation_techniques = finding.get('confirmation_techniques', 0)
        if confirmation_techniques >= 2:
            score += 0.4
        elif confirmation_techniques == 1:
            score += 0.2
        
        # Factor 3: Evidências detalhadas existem? (+20%)
        evidence = finding.get('evidence', {})
        if evidence and len(evidence) > 0:
            score += 0.2
        
        # Factor 4: PoC funcional incluído? (+10%)
        if finding.get('has_poc') or finding.get('curl_command'):
            score += 0.1
        
        # Cap at 1.0 (100%)
        return min(score, 1.0)
    
    def get_confidence_label(self, confidence):
        """
        Converte score numérico em label descritivo.
        
        Args:
            confidence: float 0.0-1.0
        
        Returns:
            str: CONFIRMED | LIKELY | POSSIBLE | SUSPECTED
        """
        if confidence >= 0.8:
            return 'CONFIRMED'  # 80-100%: Alta certeza
        elif confidence >= 0.5:
            return 'LIKELY'     # 50-80%: Provável
        elif confidence >= 0.3:
            return 'POSSIBLE'   # 30-50%: Possível
        else:
            return 'SUSPECTED'  # 0-30%: Suspeita
    
    def get_confidence_description(self, label):
        """
        Retorna descrição amigável do label.
        """
        descriptions = {
            'CONFIRMED': 'Confirmado por múltiplas técnicas de validação',
            'LIKELY': 'Provável vulnerabilidade com evidências sólidas',
            'POSSIBLE': 'Possível vulnerabilidade, requer validação manual',
            'SUSPECTED': 'Suspeita inicial, alta chance de falso positivo',
        }
        return descriptions.get(label, 'Desconhecido')
    
    def get_priority(self, confidence, severity):
        """
        Combina confidence + severity para prioridade de remediação.
        
        Returns:
            str: P1 (Urgente) | P2 (Alto) | P3 (Médio) | P4 (Baixo)
        """
        # Critical + High confidence = P1
        if severity in ['Critical', 'High'] and confidence >= 0.8:
            return 'P1 - Urgente'
        
        # High + Medium confidence = P2
        if severity in ['Critical', 'High'] and confidence >= 0.5:
            return 'P2 - Alto'
        
        # Medium severity OR lower confidence = P3
        if severity == 'Medium' or (severity == 'High' and confidence >= 0.3):
            return 'P3 - Médio'
        
        # Low severity or very low confidence = P4
        return 'P4 - Baixo'
