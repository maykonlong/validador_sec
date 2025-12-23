"""
Smart Rate Limiter - Adapta velocidade baseado em respostas do servidor
Previne bloqueios e otimiza performance automaticamente
"""
import time
import random

class SmartRateLimiter:
    """Rate limiter adaptativo com exponential backoff."""
    
    def __init__(self, initial_delay=0.1):
        """
        Args:
            initial_delay: float - Delay inicial em segundos (padrão: 100ms)
        """
        self.request_delay = initial_delay
        self.consecutive_429s = 0
        self.consecutive_200s = 0
        self.min_delay = 0.05  # 50ms mínimo
        self.max_delay = 5.0   # 5s máximo
    
    def wait(self):
        """Aguarda antes da próxima requisição."""
        if self.request_delay > 0:
            time.sleep(self.request_delay)
    
    def on_response(self, status_code):
        """
        Ajusta delay baseado no status code da resposta.
        
        Args:
            status_code: int - HTTP status code
        """
        if status_code == 429:
            # Rate limited - slow down
            self._handle_rate_limit()
        elif status_code in [200, 201, 202, 204]:
            # Success - speed up gradually
            self._handle_success()
        elif status_code in [500, 502, 503, 504]:
            # Server error - slow down temporarily
            self._handle_server_error()
    
    def _handle_rate_limit(self):
        """Lida com erro 429 (Too Many Requests)."""
        self.consecutive_429s += 1
        self.consecutive_200s = 0
        
        # Exponential backoff: 2x delay
        self.request_delay = min(self.request_delay * 2, self.max_delay)
        
        # Wait extra time after rate limit
        extra_wait = self.request_delay * 3
        time.sleep(extra_wait)
        
        print(f"⚠️ Rate limit detected. Slowing down to {self.request_delay:.2f}s/request")
    
    def _handle_success(self):
        """Lida com resposta bem-sucedida."""
        self.consecutive_200s += 1
        self.consecutive_429s = 0
        
        # Speed up after 10 successful requests
        if self.consecutive_200s >= 10:
            # Reduce delay by 10%
            self.request_delay = max(self.request_delay * 0.9, self.min_delay)
            self.consecutive_200s = 0
    
    def _handle_server_error(self):
        """Lida com erro de servidor (5xx)."""
        # Temporary slowdown
        self.request_delay = min(self.request_delay * 1.5, self.max_delay)
    
    def get_delay_with_jitter(self):
        """
        Retorna delay com jitter (variação aleatória).
        Previne sincronização de requests.
        
        Returns:
            float: Delay em segundos com jitter
        """
        # Add 0-50% random jitter
        jitter = random.uniform(0, self.request_delay * 0.5)
        return self.request_delay + jitter
    
    def reset(self):
        """Reset para estado inicial."""
        self.request_delay = 0.1
        self.consecutive_429s = 0
        self.consecutive_200s = 0
    
    def get_stats(self):
        """
        Retorna estatísticas do rate limiter.
        
        Returns:
            dict: Estatísticas
        """
        return {
            'current_delay': self.request_delay,
            'consecutive_rate_limits': self.consecutive_429s,
            'consecutive_successes': self.consecutive_200s,
            'is_throttled': self.request_delay > 0.5,
        }
