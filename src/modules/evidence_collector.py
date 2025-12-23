"""
Evidence Collector - Coleta evidências detalhadas de findings
Aumenta auditabilidade e reprodutibilidade dos testes
"""
from datetime import datetime

class EvidenceCollector:
    """Coleta e organiza evidências de testes de segurança."""
    
    def collect(self, finding_type, test_data):
        """
        Coleta evidências de um teste específico.
        
        Args:
            finding_type: str - Tipo de vulnerabilidade testada
            test_data: dict - Dados do teste realizado
        
        Returns:
            dict: Evidências estruturadas
        """
        evidence = {
            'timestamp': datetime.now().isoformat(),
            'test_type': finding_type,
            'requests': [],
            'responses': [],
            'validation_performed': test_data.get('validation_performed', False),
        }
        
        # Request details
        if 'url' in test_data:
            evidence['requests'].append({
                'url': test_data['url'],
                'method': test_data.get('method', 'GET'),
                'payload': test_data.get('payload', ''),
                'headers': test_data.get('headers', {}),
            })
        
        # Response details
        if 'status' in test_data:
            evidence['responses'].append({
                'status_code': test_data['status'],
                'headers': test_data.get('response_headers', {}),
                'body_snippet': self._truncate_body(test_data.get('body', '')),
                'match_pattern': test_data.get('match_pattern', ''),
            })
        
        # Confirmation tests
        if 'confirmation_tests' in test_data:
            evidence['confirmation_tests'] = test_data['confirmation_tests']
        
        return evidence
    
    def collect_validation_evidence(self, validation_result):
        """
        Coleta evidências de validação (false positive check).
        
        Args:
            validation_result: dict - Resultado da validação
        
        Returns:
            dict: Evidências de validação
        """
        if not validation_result:
            return {}
        
        evidence = validation_result.get('evidence', {})
        
        return {
            'validation_performed': validation_result.get('validation_performed', True),
            'test_name': evidence.get('test_name', 'Unknown'),
            'impact': evidence.get('impact', 'None'),
            'reason': evidence.get('reason', ''),
            'vulnerable': validation_result.get('vulnerable', False),
            'exploitable': validation_result.get('exploitable', False),
            'confirmation_technique': evidence.get('test_name', ''),
            'full_evidence': evidence,
        }
    
    def _truncate_body(self, body, max_length=500):
        """Trunca response body para tamanho gerenciável."""
        if len(body) <= max_length:
            return body
        
        return body[:max_length] + f"... (truncated, total: {len(body)} chars)"
    
    def format_evidence_for_report(self, evidence):
        """
        Formata evidências para exibição em relatório.
        
        Returns:
            str: Texto formatado para relatório
        """
        if not evidence:
            return "Nenhuma evidência coletada."
        
        formatted = []
        
        # Validation info
        if evidence.get('validation_performed'):
            formatted.append(f"<strong>Validação:</strong> {evidence.get('test_name', 'N/A')}")
            formatted.append(f"<strong>Técnica:</strong> {evidence.get('confirmation_technique', 'N/A')}")
            formatted.append(f"<strong>Motivo:</strong> {evidence.get('reason', 'N/A')}")
        
        # Request info
        if 'requests' in evidence and evidence['requests']:
            req = evidence['requests'][0]
            formatted.append(f"<strong>Request URL:</strong> {req.get('url', 'N/A')}")
            formatted.append(f"<strong>Método:</strong> {req.get('method', 'GET')}")
            if req.get('payload'):
                formatted.append(f"<strong>Payload:</strong> {req['payload']}")
        
        # Response info
        if 'responses' in evidence and evidence['responses']:
            resp = evidence['responses'][0]
            formatted.append(f"<strong>Status Code:</strong> {resp.get('status_code', 'N/A')}")
        
        return "<br>".join(formatted)
    
    def get_evidence_summary(self, all_evidences):
        """
        Gera resumo de todas as evidências coletadas.
        
        Returns:
            dict: Estatísticas de evidências
        """
        total_evidences = len(all_evidences)
        validated = sum(1 for ev in all_evidences if ev.get('validation_performed'))
        
        return {
            'total_evidences': total_evidences,
            'validated_findings': validated,
            'validation_rate': validated / max(total_evidences, 1),
            'unvalidated_findings': total_evidences - validated,
        }
