"""
Scan Metrics - Coleta e analisa métricas de scan
Fornece insights sobre performance, accuracy e eficiência
"""
import time
from datetime import datetime

class ScanMetrics:
    """Coleta métricas detalhadas do scan."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.metrics = {
            'total_tests': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'validation_confirmations': 0,
            'false_positives_avoided': 0,
            'requests_sent': 0,
            'rate_limit_hits': 0,
            'retry_attempts': 0,
            'duplicates_removed': 0,
            'waf_detected': False,
        }
    
    def start_scan(self):
        """Inicia tracking do scan."""
        self.start_time = time.time()
    
    def end_scan(self):
        """Finaliza tracking do scan."""
        self.end_time = time.time()
    
    def increment(self, metric_name, amount=1):
        """
        Incrementa métrica específica.
        
        Args:
            metric_name: str - Nome da métrica
            amount: int - Quantidade a incrementar
        """
        if metric_name in self.metrics:
            self.metrics[metric_name] += amount
    
    def set_metric(self, metric_name, value):
        """
        Define valor de métrica.
        
        Args:
            metric_name: str - Nome da métrica
            value: any - Valor
        """
        self.metrics[metric_name] = value
    
    def get_duration(self):
        """
        Retorna duração do scan em segundos.
        
        Returns:
            float: Duração em segundos
        """
        if not self.start_time:
            return 0
        
        end = self.end_time or time.time()
        return end - self.start_time
    
    def calculate_rates(self):
        """
        Calcula taxas e percentuais.
        
        Returns:
            dict: Taxas calculadas
        """
        duration = self.get_duration()
        total_tests = self.metrics['total_tests']
        
        return {
            'tests_per_second': total_tests / duration if duration > 0 else 0,
            'success_rate': (self.metrics['successful_tests'] / max(total_tests, 1)) * 100,
            'failure_rate': (self.metrics['failed_tests'] / max(total_tests, 1)) * 100,
            'confirmation_rate': (self.metrics['validation_confirmations'] / max(total_tests, 1)) * 100,
            'false_positive_rate': (self.metrics['false_positives_avoided'] / max(total_tests, 1)) * 100,
            'retry_rate': (self.metrics['retry_attempts'] / max(self.metrics['requests_sent'], 1)) * 100,
        }
    
    def generate_report(self):
        """
        Gera relatório completo de métricas.
        
        Returns:
            dict: Relatório completo
        """
        duration = self.get_duration()
        rates = self.calculate_rates()
        
        return {
            'scan_info': {
                'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
                'duration_seconds': round(duration, 2),
                'duration_formatted': self._format_duration(duration),
            },
            'raw_metrics': self.metrics,
            'calculated_rates': {
                'tests_per_second': round(rates['tests_per_second'], 2),
                'success_rate': f"{round(rates['success_rate'], 1)}%",
                'failure_rate': f"{round(rates['failure_rate'], 1)}%",
                'confirmation_rate': f"{round(rates['confirmation_rate'], 1)}%",
                'false_positive_rate': f"{round(rates['false_positive_rate'], 1)}%",
                'retry_rate': f"{round(rates['retry_rate'], 1)}%",
            },
            'efficiency': {
                'requests_per_test': round(self.metrics['requests_sent'] / max(self.metrics['total_tests'], 1), 2),
                'validations_performed': self.metrics['validation_confirmations'],
                'duplicates_removed': self.metrics['duplicates_removed'],
                'waf_detected': self.metrics['waf_detected'],
            }
        }
    
    def _format_duration(self, seconds):
        """
        Formata duração em formato legível.
        
        Args:
            seconds: float - Duração em segundos
        
        Returns:
            str: Duração formatada (e.g., "2m 30s")
        """
        if seconds < 60:
            return f"{int(seconds)}s"
        
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        
        if minutes < 60:
            return f"{minutes}m {secs}s"
        
        hours = int(minutes // 60)
        mins = int(minutes % 60)
        return f"{hours}h {mins}m {secs}s"
    
    def get_performance_grade(self):
        """
        Calcula nota de performance do scan.
        
        Returns:
            dict: Grade e análise
        """
        rates = self.calculate_rates()
        
        # Score baseado em múltiplos fatores
        score = 0
        
        # Success rate (0-30 points)
        score += (rates['success_rate'] / 100) * 30
        
        # Speed (0-20 points)
        speed_score = min(rates['tests_per_second'] / 10, 1) * 20
        score += speed_score
        
        # Confirmation rate (0-30 points)
        score += (rates['confirmation_rate'] / 100) * 30
        
        # Low retry rate (0-20 points)
        retry_penalty = (rates['retry_rate'] / 100) * 20
        score += 20 - retry_penalty
        
        # Convert to grade
        if score >= 90:
            grade = 'A'
            description = 'Excelente'
        elif score >= 75:
            grade = 'B'
            description = 'Bom'
        elif score >= 60:
            grade = 'C'
            description = 'Satisfatório'
        elif score >= 40:
            grade = 'D'
            description = 'Precisa Melhorias'
        else:
            grade = 'F'
            description = 'Insatisfatório'
        
        return {
            'score': round(score, 1),
            'grade': grade,
            'description': description,
        }
    
    def export_to_json(self):
        """
        Exporta métricas para JSON.
        
        Returns:
            dict: Métricas em formato JSON-friendly
        """
        return self.generate_report()
