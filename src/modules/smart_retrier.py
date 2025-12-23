"""
Smart Retrier - Retry inteligente com exponential backoff e jitter
Aumenta robustez do scanner contra erros de rede temporários
"""
import time
import random
from functools import wraps

class SmartRetrier:
    """Retry automático para requisições com falhas temporárias."""
    
    def __init__(self, max_retries=3, base_delay=1.0):
        """
        Args:
            max_retries: int - Número máximo de tentativas
            base_delay: float - Delay base em segundos
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def retry_with_backoff(self, func, *args, **kwargs):
        """
        Executa função com retry automático.
        
        Args:
            func: Função a executar
            *args, **kwargs: Argumentos para a função
        
        Returns:
            Resultado da função ou None se todas as tentativas falharem
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            
            except (ConnectionError, TimeoutError) as e:
                last_exception = e
                
                if attempt == self.max_retries - 1:
                    # Última tentativa - raise exception
                    return None
                
                # Calculate delay with exponential backoff
                delay = self._calculate_backoff(attempt)
                
                # Wait before retry
                time.sleep(delay)
            
            except Exception as e:
                # Outros erros não são retried
                raise
        
        return None
    
    def _calculate_backoff(self, attempt):
        """
        Calcula delay com exponential backoff + jitter.
        
        Args:
            attempt: int - Número da tentativa (0-indexed)
        
        Returns:
            float: Delay em segundos
        """
        # Exponential backoff: base_delay * (2 ^ attempt)
        backoff = self.base_delay * (2 ** attempt)
        
        # Add random jitter (0-50% of backoff)
        jitter = random.uniform(0, backoff * 0.5)
        
        # Total delay
        total_delay = backoff + jitter
        
        # Cap at 30 seconds
        return min(total_delay, 30.0)
    
    def retry_decorator(self, max_retries=None):
        """
        Decorator para adicionar retry automático a funções.
        
        Usage:
            @retrier.retry_decorator(max_retries=3)
            def my_function():
                # code that might fail
                pass
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                retries = max_retries or self.max_retries
                
                for attempt in range(retries):
                    try:
                        return func(*args, **kwargs)
                    except (ConnectionError, TimeoutError) as e:
                        if attempt == retries - 1:
                            raise
                        
                        delay = self._calculate_backoff(attempt)
                        time.sleep(delay)
                
                return None
            
            return wrapper
        return decorator
    
    def get_retry_stats(self, attempts_made, success):
        """
        Retorna estatísticas de retry.
        
        Returns:
            dict: Estatísticas
        """
        return {
            'attempts_made': attempts_made,
            'success': success,
            'retry_rate': (attempts_made - 1) / max(attempts_made, 1) if not success else 0,
        }
