"""
Risk Calculator - Calcula risco total do target com nota A-F
Fornece executive summary e métricas agregadas
"""

class RiskCalculator:
    """Calcula risco total baseado em findings."""
    
    SEVERITY_WEIGHTS = {
        'Critical': 10.0,
        'High': 5.0,
        'Medium': 2.0,
        'Low': 0.5,
        'Info': 0.0,
    }
    
    def calculate_risk_score(self, findings):
        """
        Calcula score de risco total (0-100).
        
        Args:
            findings: list - Lista de findings
        
        Returns:
            dict: Score e métricas
        """
        if not findings:
            return {
                'score': 0,
                'grade': 'A',
                'risk_level': 'Muito Baixo',
                'findings_total': 0,
            }
        
        total_score = 0.0
        weighted_findings = []
        
        for finding in findings:
            severity = finding.get('severity', 'Low')
            confidence = finding.get('confidence', 0.5)
            
            # Base score por severidade
            base_score = self.SEVERITY_WEIGHTS.get(severity, 0)
            
            # Ajustar por confidence (só conta se tem alta confiança)
            weighted_score = base_score * confidence
            
            total_score += weighted_score
            weighted_findings.append({
                'name': finding.get('vulnerability'),
                'weighted_score': weighted_score,
            })
        
        # Normalizar para 0-100
        # Assumindo que 5 findings críticos com 100% confidence = score 50
        max_expected = 50.0
        normalized_score = min((total_score / max_expected) * 100, 100)
        
        # Calcular métricas
        severity_counts = self._count_by_severity(findings)
        confidence_avg = self._calculate_avg_confidence(findings)
        
        return {
            'score': round(normalized_score, 1),
            'grade': self._get_grade(normalized_score),
            'risk_level': self._get_risk_level(normalized_score),
            'findings_total': len(findings),
            'severity_breakdown': severity_counts,
            'avg_confidence': round(confidence_avg * 100, 1),
            'top_risks': self._get_top_risks(weighted_findings, 5),
        }
    
    def _get_grade(self, score):
        """
        Converte score em nota A-F.
        
        Args:
            score: float - Score 0-100
        
        Returns:
            str: A-F grade
        """
        if score >= 80:
            return 'F'  # Crítico
        elif score >= 60:
            return 'D'  # Alto Risco
        elif score >= 40:
            return 'C'  # Médio Risco
        elif score >= 20:
            return 'B'  # Baixo Risco
        else:
            return 'A'  # Seguro
    
    def _get_risk_level(self, score):
        """
        Retorna descrição do nível de risco.
        
        Returns:
            str: Nível de risco descritivo
        """
        risk_levels = {
            'F': 'Crítico - Ação imediata necessária',
            'D': 'Alto Risco - Correções urgentes',
            'C': 'Médio Risco - Planejar correções',
            'B': 'Baixo Risco - Monitorar',
            'A': 'Muito Baixo - Seguro',
        }
        grade = self._get_grade(score)
        return risk_levels.get(grade, 'Desconhecido')
    
    def _count_by_severity(self, findings):
        """Conta findings por severidade."""
        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0,
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Low')
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts
    
    def _calculate_avg_confidence(self, findings):
        """Calcula confidence média."""
        if not findings:
            return 0.0
        
        total_confidence = sum(f.get('confidence', 0) for f in findings)
        return total_confidence / len(findings)
    
    def _get_top_risks(self, weighted_findings, top_n=5):
        """
        Retorna top N riscos mais críticos.
        
        Returns:
            list: Top riscos ordenados por score
        """
        sorted_findings = sorted(
            weighted_findings,
            key=lambda x: x['weighted_score'],
            reverse=True
        )
        
        return sorted_findings[:top_n]
    
    def generate_executive_summary(self, risk_data, target_url):
        """
        Gera executive summary para relatório.
        
        Returns:
            str: Summary formatado
        """
        summary = f"""
# Executive Summary - Security Assessment

**Target:** {target_url}
**Risk Score:** {risk_data['score']}/100
**Grade:** {risk_data['grade']}
**Risk Level:** {risk_data['risk_level']}

## Findings Overview
- **Total Findings:** {risk_data['findings_total']}
- **Average Confidence:** {risk_data['avg_confidence']}%

## Severity Breakdown
- **Critical:** {risk_data['severity_breakdown']['Critical']}
- **High:** {risk_data['severity_breakdown']['High']}
- **Medium:** {risk_data['severity_breakdown']['Medium']}
- **Low:** {risk_data['severity_breakdown']['Low']}
- **Info:** {risk_data['severity_breakdown']['Info']}

## Top 5 Critical Risks
"""
        
        for i, risk in enumerate(risk_data['top_risks'], 1):
            summary += f"{i}. {risk['name']} (Score: {risk['weighted_score']:.1f})\n"
        
        return summary
    
    def get_remediation_priority(self, findings):
        """
        Gera lista priorizada de remediação.
        
        Returns:
            dict: Prioridades P1-P4
        """
        by_priority = {
            'P1': [],
            'P2': [],
            'P3': [],
            'P4': [],
        }
        
        for finding in findings:
            priority = finding.get('priority', 'P4 - Baixo')
            priority_level = priority.split(' ')[0]  # Extract P1, P2, etc
            
            if priority_level in by_priority:
                by_priority[priority_level].append(finding.get('vulnerability'))
        
        return by_priority
