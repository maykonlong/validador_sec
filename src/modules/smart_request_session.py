"""
Smart HTTP Request Wrapper
Integrates SmartRateLimiter and SmartRetrier into all requests
"""

class SmartRequestSession:
    """
    Wrapper around requests.Session that automatically applies:
    - Rate limiting (via SmartRateLimiter)
    - Retries (via SmartRetrier)
    - WAF detection
    """
    
    def __init__(self, base_session, rate_limiter=None, retrier=None):
        self.session = base_session
        self.rate_limiter = rate_limiter
        self.retrier = retrier
    
    def _make_request(self, method, url, **kwargs):
        """Internal method that applies rate limiting and retries"""
        
        # Wait for rate limit
        if self.rate_limiter:
            self.rate_limiter.wait()
        
        # Make request with retry logic
        if self.retrier:
            response = self.retrier.retry_with_backoff(
                lambda: self.session.request(method, url, **kwargs)
            )
        else:
            response = self.session.request(method, url, **kwargs)
        
        # Update rate limiter with response
        if self.rate_limiter and response:
            self.rate_limiter.on_response(response.status_code)
        
        return response
    
    def get(self, url, **kwargs):
        """GET request with rate limiting and retries"""
        return self._make_request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        """POST request with rate limiting and retries"""
        return self._make_request('POST', url, **kwargs)
    
    def put(self, url, **kwargs):
        """PUT request with rate limiting and retries"""
        return self._make_request('PUT', url, **kwargs)
    
    def delete(self, url, **kwargs):
        """DELETE request with rate limiting and retries"""
        return self._make_request('DELETE', url, **kwargs)
    
    def patch(self, url, **kwargs):
        """PATCH request with rate limiting and retries"""
        return self._make_request('PATCH', url, **kwargs)
    
    def head(self, url, **kwargs):
        """HEAD request with rate limiting and retries"""
        return self._make_request('HEAD', url, **kwargs)
    
    def options(self, url, **kwargs):
        """OPTIONS request with rate limiting and retries"""
        return self._make_request('OPTIONS', url, **kwargs)
    
    def request(self, method, url, **kwargs):
        """Generic request with rate limiting and retries"""
        return self._make_request(method, url, **kwargs)
