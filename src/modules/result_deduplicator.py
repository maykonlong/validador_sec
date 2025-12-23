"""
Result Deduplicator - Elimina findings duplicados
Reduz ruído em relatórios através de deduplicação inteligente
"""

class ResultDeduplicator:
    """Identifica e remove findings duplicados."""
    
    def __init__(self):
        self.seen_hashes = set()
        self.merged_findings = {}
    
    def is_duplicate(self, finding):
        """
        Verifica se finding já foi reportado.
        
        Returns:
            bool: True se duplicado
        """
        hash_key = self._generate_hash(finding)
        
        if hash_key in self.seen_hashes:
            return True
        
        self.seen_hashes.add(hash_key)
        return False
    
    def _generate_hash(self, finding):
        """
        Gera hash único para finding baseado em:
        - Tipo de vulnerabilidade
        - URL/Endpoint
        - Parâmetro (se aplicável)
        """
        vuln_type = finding.get('vulnerability', '')
        url = finding.get('url', finding.get('details', ''))[:100]  # First 100 chars
        param = finding.get('param', '')
        
        # Criar tuple para hash
        hash_tuple = (
            vuln_type.lower().strip(),
            url.lower().strip(),
            param.lower().strip(),
        )
        
        return hash(str(hash_tuple))
    
    def merge_duplicates(self, findings):
        """
        Merge findings duplicados, combinando evidências.
        
        Returns:
            list: Findings únicos com evidências consolidadas
        """
        merged = {}
        
        for finding in findings:
            key = self._generate_hash(finding)
            
            if key in merged:
                # É duplicata - merge evidências
                existing = merged[key]
                
                # Incrementar contador
                existing['duplicate_count'] = existing.get('duplicate_count', 1) + 1
                
                # Combinar evidências se existirem
                if 'evidence' in finding:
                    if 'evidence' not in existing:
                        existing['evidence'] = []
                    if isinstance(finding['evidence'], dict):
                        existing['evidence'].append(finding['evidence'])
                    elif isinstance(finding['evidence'], list):
                        existing['evidence'].extend(finding['evidence'])
                
                # Usar maior confidence
                if finding.get('confidence', 0) > existing.get('confidence', 0):
                    existing['confidence'] = finding['confidence']
                    existing['confidence_label'] = finding.get('confidence_label')
            else:
                # Primeiro occurrence
                finding['duplicate_count'] = 1
                merged[key] = finding
        
        return list(merged.values())
    
    def get_deduplication_stats(self):
        """
        Retorna estatísticas de deduplicação.
        
        Returns:
            dict: Total processado, únicos, duplicatas removidas
        """
        total_processed = len(self.seen_hashes)
        
        return {
            'total_findings_processed': total_processed,
            'unique_findings': len(self.merged_findings),
            'duplicates_removed': total_processed - len(self.merged_findings),
            'deduplication_rate': (total_processed - len(self.merged_findings)) / max(total_processed, 1),
        }
