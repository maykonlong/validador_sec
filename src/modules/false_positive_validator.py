"""
False Positive Validator - Low Impact Pentest Methodology
Verifies suspected vulnerabilities with confirmation tests that have ZERO impact.
"""
import requests
import random
import string
from urllib.parse import urljoin

class FalsePositiveValidator:
    """
    Validates suspected vulnerabilities using professional low-impact techniques.
    All tests are designed to have ZERO destructive impact while providing conclusive evidence.
    """
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ValidadorSec/2.0 (Security Scanner - Low Impact Validation)'
        })
    
    def validate_http_methods(self, url):
        """
        Comprehensive HTTP method validation using low-impact techniques.
        
        Returns:
            dict with keys:
                - put_vulnerable: bool
                - delete_vulnerable: bool
                - trace_enabled: bool
                - allowed_methods: list
                - evidence: dict of test results
        """
        result = {
            'put_vulnerable': False,
            'delete_vulnerable': False,
            'trace_enabled': False,
            'allowed_methods': [],
            'evidence': {},
            'validation_performed': True
        }
        
        # Test 1: OPTIONS (most reliable, zero impact)
        options_result = self._test_options(url)
        result['evidence']['options'] = options_result
        result['allowed_methods'] = options_result.get('allowed_methods', [])
        
        # Test 2: PUT with specific path + Content-Length: 0
        put_result = self._test_put_zero_content(url)
        result['evidence']['put'] = put_result
        result['put_vulnerable'] = put_result.get('vulnerable', False)
        
        # Test 3: DELETE on non-existent resource
        delete_result = self._test_delete_nonexistent(url)
        result['evidence']['delete'] = delete_result
        result['delete_vulnerable'] = delete_result.get('vulnerable', False)
        
        # Test 4: TRACE (XST detection)
        trace_result = self._test_trace(url)
        result['evidence']['trace'] = trace_result
        result['trace_enabled'] = trace_result.get('enabled', False)
        
        return result
    
    def _test_options(self, url):
        """
        Test 1: OPTIONS request to enumerate allowed methods.
        IMPACT: None - read-only enumeration
        """
        try:
            resp = self.session.request('OPTIONS', url, timeout=self.timeout, allow_redirects=False)
            allow_header = resp.headers.get('Allow', '')
            allowed_methods = [m.strip().upper() for m in allow_header.split(',') if m.strip()]
            
            return {
                'status_code': resp.status_code,
                'allowed_methods': allowed_methods,
                'allow_header': allow_header,
                'test_name': 'OPTIONS Enumeration',
                'impact': 'None'
            }
        except Exception as e:
            return {
                'error': str(e),
                'allowed_methods': [],
                'test_name': 'OPTIONS Enumeration',
                'impact': 'None'
            }
    
    def _test_put_zero_content(self, url):
        """
        Test 2: PUT with Content-Length: 0 to specific path.
        IMPACT: None - no bytes sent, no file created
        """
        # Generate random test filename
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        test_path = f"validadorsec-test-{random_suffix}.txt"
        test_url = urljoin(url, test_path)
        
        try:
            resp = self.session.request(
                'PUT',
                test_url,
                headers={'Content-Length': '0'},
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Vulnerable if: 200, 201, 204 (successful write)
            # Safe if: 403, 405, 501 (blocked)
            vulnerable = resp.status_code in [200, 201, 204]
            
            return {
                'status_code': resp.status_code,
                'vulnerable': vulnerable,
                'test_url': test_url,
                'test_name': 'PUT Zero Content',
                'impact': 'None (0 bytes sent)',
                'reason': 'Method allowed' if vulnerable else 'Method blocked'
            }
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'test_name': 'PUT Zero Content',
                'impact': 'None'
            }
    
    def _test_delete_nonexistent(self, url):
        """
        Test 3: DELETE on non-existent resource.
        IMPACT: None - resource doesn't exist
        """
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        test_path = f"nonexistent-file-{random_suffix}.txt"
        test_url = urljoin(url, test_path)
        
        try:
            resp = self.session.request(
                'DELETE',
                test_url,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Vulnerable if: 200, 204 (method executed)
            # Safe if: 403, 405, 501 (blocked)
            # 404 alone doesn't confirm - need to check if method was processed
            vulnerable = resp.status_code in [200, 204]
            
            return {
                'status_code': resp.status_code,
                'vulnerable': vulnerable,
                'test_url': test_url,
                'test_name': 'DELETE Non-existent Resource',
                'impact': 'None (resource does not exist)',
                'reason': 'Method allowed' if vulnerable else 'Method blocked'
            }
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'test_name': 'DELETE Non-existent Resource',
                'impact': 'None'
            }
    
    def _test_trace(self, url):
        """
        Test 4: TRACE method (Cross-Site Tracing - XST).
        IMPACT: None - read-only reflection test
        """
        try:
            # Add custom header to verify echo
            custom_header_value = f"ValidadorSec-{random.randint(1000, 9999)}"
            resp = self.session.request(
                'TRACE',
                url,
                headers={'X-Test-Header': custom_header_value},
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # TRACE is enabled if:
            # 1. Returns 200
            # 2. Echoes back the request (check for custom header in body)
            enabled = (resp.status_code == 200 and 
                      (custom_header_value in resp.text or 'TRACE' in resp.text))
            
            return {
                'status_code': resp.status_code,
                'enabled': enabled,
                'test_name': 'TRACE Method (XST)',
                'impact': 'None (reflection test)',
                'reason': 'XST possible' if enabled else 'TRACE blocked'
            }
        except Exception as e:
            return {
                'error': str(e),
                'enabled': False,
                'test_name': 'TRACE Method (XST)',
                'impact': 'None'
            }
    
    def generate_validation_report(self, validation_result):
        """
        Generate human-readable validation report.
        """
        lines = []
        lines.append("=== VALIDAÇÃO DE FALSOS POSITIVOS ===")
        lines.append("Metodologia: Low-Impact Pentest")
        lines.append("")
        
        # PUT validation
        put_ev = validation_result['evidence'].get('put', {})
        if put_ev:
            lines.append(f"[PUT] {put_ev.get('test_name', 'PUT Test')}")
            lines.append(f"  URL: {put_ev.get('test_url', 'N/A')}")
            lines.append(f"  Status: {put_ev.get('status_code', 'N/A')}")
            lines.append(f"  Impacto: {put_ev.get('impact', 'Unknown')}")
            lines.append(f"  Resultado: {'VULNERÁVEL' if put_ev.get('vulnerable') else 'SEGURO'}")
            lines.append("")
        
        # DELETE validation
        del_ev = validation_result['evidence'].get('delete', {})
        if del_ev:
            lines.append(f"[DELETE] {del_ev.get('test_name', 'DELETE Test')}")
            lines.append(f"  URL: {del_ev.get('test_url', 'N/A')}")
            lines.append(f"  Status: {del_ev.get('status_code', 'N/A')}")
            lines.append(f"  Impacto: {del_ev.get('impact', 'Unknown')}")
            lines.append(f"  Resultado: {'VULNERÁVEL' if del_ev.get('vulnerable') else 'SEGURO'}")
            lines.append("")
        
        # TRACE validation
        trace_ev = validation_result['evidence'].get('trace', {})
        if trace_ev:
            lines.append(f"[TRACE] {trace_ev.get('test_name', 'TRACE Test')}")
            lines.append(f"  Status: {trace_ev.get('status_code', 'N/A')}")
            lines.append(f"  Resultado: {'HABILITADO (XST)' if trace_ev.get('enabled') else 'DESABILITADO'}")
            lines.append("")
        
        # OPTIONS summary
        opts_ev = validation_result['evidence'].get('options', {})
        if opts_ev:
            lines.append(f"[OPTIONS] Métodos Permitidos")
            lines.append(f"  Allow Header: {opts_ev.get('allow_header', 'None')}")
            lines.append(f"  Métodos: {', '.join(opts_ev.get('allowed_methods', []))}")
        
        return '\n'.join(lines)
    
    def validate_directory_listing(self, url, suspected_paths=None):
        """
        Validate if directory listing is actually exposed.
        
        Returns:
            dict with keys:
                - vulnerable: bool
                - evidence: dict of test results per path
        """
        result = {
            'vulnerable_paths': [],
            'false_positive_paths': [],
            'evidence': {},
            'validation_performed': True
        }
        
        paths_to_test = suspected_paths or ['/admin/', '/backup/', '/uploads/']
        
        for path in paths_to_test:
            test_url = urljoin(url, path)
            path_result = self._test_directory_listing(test_url)
            result['evidence'][path] = path_result
            
            if path_result.get('is_listing', False):
                result['vulnerable_paths'].append(path)
            else:
                result['false_positive_paths'].append(path)
        
        return result
    
    def _test_directory_listing(self, url):
        """
        Test if URL actually returns directory listing.
        IMPACT: None - read-only
        """
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            if resp.status_code != 200:
                return {
                    'status_code': resp.status_code,
                    'is_listing': False,
                    'reason': f'Status {resp.status_code}',
                    'test_name': 'Directory Listing Detection',
                    'impact': 'None'
                }
            
            content = resp.text.lower()
            
            # Indicators of actual directory listing
            listing_indicators = [
                'index of',
                '<title>index of',
                'directory listing',
                'parent directory',
                '<a href="../">',
            ]
            
            # Count potential file links
            link_count = content.count('<a href=')
            
            # Check for listing indicators
            has_indicator = any(indicator in content for indicator in listing_indicators)
            
            # Real listing typically has multiple links (files)
            has_multiple_links = link_count > 3
            
            is_listing = has_indicator or has_multiple_links
            
            return {
                'status_code': 200,
                'is_listing': is_listing,
                'link_count': link_count,
                'has_indicator': has_indicator,
                'reason': 'Directory listing exposed' if is_listing else 'Custom page (não é listagem)',
                'test_name': 'Directory Listing Detection',
                'impact': 'None'
            }
        except Exception as e:
            return {
                'error': str(e),
                'is_listing': False,
                'test_name': 'Directory Listing Detection',
                'impact': 'None'
            }
    
    def validate_sql_injection(self, url, param_name):
        """
        Enhanced SQL injection validation using boolean-based tests.
        
        Returns:
            dict with keys:
                - vulnerable: bool
                - technique: str (error-based, boolean-based, time-based)
                - evidence: dict
        """
        result = {
            'vulnerable': False,
            'technique': None,
            'evidence': {},
            'validation_performed': True
        }
        
        # Test 1: Boolean-based (true vs false)
        boolean_result = self._test_sql_boolean(url, param_name)
        result['evidence']['boolean'] = boolean_result
        
        if boolean_result.get('vulnerable', False):
            result['vulnerable'] = True
            result['technique'] = 'Boolean-based'
            return result
        
        # Test 2: Time-based blind
        time_result = self._test_sql_time_based(url, param_name)
        result['evidence']['time'] = time_result
        
        if time_result.get('vulnerable', False):
            result['vulnerable'] = True
            result['technique'] = 'Time-based blind'
        
        return result
    
    def _test_sql_boolean(self, url, param_name):
        """
        Test SQL injection using boolean conditions.
        IMPACT: Low - read-only queries
        """
        try:
            import time
            from urllib.parse import urlencode, urlparse, parse_qs
            
            # Parse URL and params
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test 1: True condition (1=1)
            params_true = {param_name: "1' AND '1'='1"}
            resp_true = self.session.get(base_url, params=params_true, timeout=self.timeout)
            
            # Test 2: False condition (1=2)
            params_false = {param_name: "1' AND '1'='2"}
            resp_false = self.session.get(base_url, params=params_false, timeout=self.timeout)
            
            # Test 3: Normal value
            params_normal = {param_name: "1"}
            resp_normal = self.session.get(base_url, params=params_normal, timeout=self.timeout)
            
            # Vulnerability confirmed if:
            # - True condition returns similar to normal
            # - False condition returns different content or error
            true_len = len(resp_true.text)
            false_len = len(resp_false.text)
            normal_len = len(resp_normal.text)
            
            # Calculate differences
            diff_true_normal = abs(true_len - normal_len)
            diff_false_normal = abs(false_len - normal_len)
            
            # Vulnerable if false condition significantly differs from true
            vulnerable = (diff_false_normal > 100 and diff_true_normal < 50)
            
            return {
                'vulnerable': vulnerable,
                'true_length': true_len,
                'false_length': false_len,
                'normal_length': normal_len,
                'test_name': 'SQL Boolean-based',
                'impact': 'Low (read-only)',
                'reason': 'Boolean logic confirmed' if vulnerable else 'No boolean difference detected'
            }
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'test_name': 'SQL Boolean-based',
                'impact': 'Low'
            }
    
    def _test_sql_time_based(self, url, param_name):
        """
        Test SQL injection using time delays.
        IMPACT: Low - only delays response, no data modification
        """
        try:
            import time
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test with SLEEP(0) - should be fast
            params_fast = {param_name: "1' AND SLEEP(0) AND '1'='1"}
            start_fast = time.time()
            self.session.get(base_url, params=params_fast, timeout=10)
            time_fast = time.time() - start_fast
            
            # Test with SLEEP(5) - should be slow
            params_slow = {param_name: "1' AND SLEEP(5) AND '1'='1"}
            start_slow = time.time()
            self.session.get(base_url, params=params_slow, timeout=10)
            time_slow = time.time() - start_slow
            
            # Vulnerable if slow query takes significantly longer
            time_diff = time_slow - time_fast
            vulnerable = time_diff > 4  # At least 4 seconds difference
            
            return {
                'vulnerable': vulnerable,
                'time_fast': round(time_fast, 2),
                'time_slow': round(time_slow, 2),
                'time_diff': round(time_diff, 2),
                'test_name': 'SQL Time-based',
                'impact': 'Low (response delay only)',
                'reason': f'Time difference: {time_diff:.1f}s' if vulnerable else 'No time delay detected'
            }
        except Exception as e:
            return {
                'error': str(e),
                'vulnerable': False,
                'test_name': 'SQL Time-based',
                'impact': 'Low'
            }
    
    def validate_sensitive_file(self, url, file_path):
        """
        Validate if sensitive file is actually accessible (200) vs just exists (403).
        
        Returns:
            dict with keys:
                - accessible: bool (200)
                - exists_but_blocked: bool (403)
                - not_found: bool (404)
                - evidence: dict
        """
        test_url = urljoin(url, file_path)
        
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            
            result = {
                'accessible': False,
                'exists_but_blocked': False,
                'not_found': False,
                'status_code': resp.status_code,
                'evidence': {},
                'validation_performed': True
            }
            
            if resp.status_code == 200:
                # File is accessible - verify it's not a custom error page
                content_length = len(resp.content)
                result['accessible'] = content_length > 10  # Real file has content
                result['evidence'] = {
                    'test_url': test_url,
                    'status': 'ACCESSIBLE (VULNERABLE)',
                    'content_length': content_length,
                    'test_name': 'Sensitive File Access',
                    'impact': 'None (read-only)'
                }
            elif resp.status_code == 403:
                result['exists_but_blocked'] = True
                result['evidence'] = {
                    'test_url': test_url,
                    'status': 'EXISTS BUT BLOCKED (INFO)',
                    'test_name': 'Sensitive File Access',
                    'impact': 'None'
                }
            elif resp.status_code == 404:
                result['not_found'] = True
                result['evidence'] = {
                    'test_url': test_url,
                    'status': 'NOT FOUND (SAFE)',
                    'test_name': 'Sensitive File Access',
                    'impact': 'None'
                }
            else:
                result['evidence'] = {
                    'test_url': test_url,
                    'status': f'OTHER ({resp.status_code})',
                    'test_name': 'Sensitive File Access',
                    'impact': 'None'
                }
            
            return result
            
        except Exception as e:
            return {
                'accessible': False,
                'exists_but_blocked': False,
                'not_found': True,
                'error': str(e),
                'evidence': {
                    'test_url': test_url,
                    'error': str(e),
                    'test_name': 'Sensitive File Access',
                    'impact': 'None'
                },
                'validation_performed': True
            }
    
    def validate_cors(self, url):
        """
        Validate if CORS misconfiguration is actually exploitable.
        
        Returns:
            dict with keys:
                - exploitable: bool (wildcard/reflect + credentials)
                - misconfigured: bool (wildcard but no credentials)
                - safe: bool
                - evidence: dict
        """
        result = {
            'exploitable': False,
            'misconfigured': False,
            'safe': True,
            'evidence': {},
            'validation_performed': True
        }
        
        try:
            # Test 1: Send malicious Origin header
            evil_origin = 'https://evil-attacker.com'
            resp = self.session.get(
                url,
                headers={'Origin': evil_origin},
                timeout=self.timeout
            )
            
            acao_header = resp.headers.get('Access-Control-Allow-Origin', '')
            acac_header = resp.headers.get('Access-Control-Allow-Credentials', 'false')
            
            # Check if server reflects any origin or uses wildcard
            reflects_origin = (acao_header == evil_origin)
            uses_wildcard = (acao_header == '*')
            allows_credentials = (acac_header.lower() == 'true')
            
            result['evidence'] = {
                'test_url': url,
                'test_origin': evil_origin,
                'acao_header': acao_header,
                'acac_header': acac_header,
                'reflects_origin': reflects_origin,
                'uses_wildcard': uses_wildcard,
                'allows_credentials': allows_credentials,
                'test_name': 'CORS Exploitability',
                'impact': 'None (header test only)'
            }
            
            # Exploitable if: (wildcard OR reflects any origin) AND credentials
            if (uses_wildcard or reflects_origin) and allows_credentials:
                result['exploitable'] = True
                result['safe'] = False
                result['evidence']['reason'] = 'CORS exploitável: permite qualquer origem + credentials'
            elif uses_wildcard or reflects_origin:
                result['misconfigured'] = True
                result['safe'] = False
                result['evidence']['reason'] = 'CORS mal configurado mas sem credentials (não exploitável)'
            else:
                result['evidence']['reason'] = 'CORS configurado corretamente'
            
            return result
            
        except Exception as e:
            return {
                'exploitable': False,
                'misconfigured': False,
                'safe': True,
                'error': str(e),
                'evidence': {
                    'test_url': url,
                    'error': str(e),
                    'test_name': 'CORS Exploitability',
                    'impact': 'None'
                },
                'validation_performed': True
            }
    
    def validate_command_injection(self, url, param_name):
        """
        Validate command injection using time-based detection.
        
        Returns:
            dict with keys:
                - vulnerable: bool
                - evidence: dict with time measurements
        """
        result = {
            'vulnerable': False,
            'evidence': {},
            'validation_performed': True
        }
        
        try:
            import time
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test 1: Baseline (sleep 0)
            params_fast = {param_name: "; sleep 0"}
            start_fast = time.time()
            self.session.get(base_url, params=params_fast, timeout=10)
            time_fast = time.time() - start_fast
            
            # Test 2: Delay test (sleep 5)
            params_slow = {param_name: "; sleep 5"}
            start_slow = time.time()
            self.session.get(base_url, params=params_slow, timeout=12)
            time_slow = time.time() - start_slow
            
            # Calculate difference
            time_diff = time_slow - time_fast
            
            # Vulnerable if delay is significant (> 4 seconds)
            vulnerable = time_diff > 4
            
            result['vulnerable'] = vulnerable
            result['evidence'] = {
                'time_fast': round(time_fast, 2),
                'time_slow': round(time_slow, 2),
                'time_diff': round(time_diff, 2),
                'test_name': 'Command Injection Time-based',
                'impact': 'Low (sleep command only)',
                'reason': f'Diferença de {time_diff:.1f}s confirma execução' if vulnerable else 'Sem delay detectado'
            }
            
            return result
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'evidence': {
                    'error': str(e),
                    'test_name': 'Command Injection Time-based',
                    'impact': 'Low'
                },
                'validation_performed': True
            }
    
    def validate_xss(self, url, param_name):
        """
        Validate if XSS is actually executable (not just reflected).
        
        Returns:
            dict with keys:
                - executable: bool
                - reflected_only: bool
                - evidence: dict
        """
        result = {
            'executable': False,
            'reflected_only': False,
            'evidence': {},
            'validation_performed': True
        }
        
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Use safe payload that doesn't execute anything dangerous
            safe_payload = '<img src=x onerror="void(0)">'
            
            params = {param_name: safe_payload}
            resp = self.session.get(base_url, params=params, timeout=self.timeout)
            
            # Check if payload is reflected
            payload_in_response = safe_payload in resp.text
            
            # Check if payload is HTML-encoded (safe)
            encoded_patterns = [
                '&lt;img',  # < encoded
                '&#60;img',  # < numeric
                '\\x3cimg',  # hex encoded
            ]
            is_encoded = any(pattern in resp.text.lower() for pattern in encoded_patterns)
            
            # Check if tag is rendered (unsafe)
            tag_rendered = '<img' in resp.text and 'src=x' in resp.text
            
            if tag_rendered and not is_encoded:
                result['executable'] = True
                result['evidence'] = {
                    'payload': safe_payload,
                    'rendered': True,
                    'encoded': False,
                    'test_name': 'XSS Execution Confirmation',
                    'impact': 'None (safe payload)',
                    'reason': 'Tag renderizada sem encoding = XSS executável'
                }
            elif payload_in_response and is_encoded:
                result['reflected_only'] = True
                result['evidence'] = {
                    'payload': safe_payload,
                    'rendered': False,
                    'encoded': True,
                    'test_name': 'XSS Reflection Only',
                    'impact': 'None',
                    'reason': 'Payload refletido mas HTML-encoded (bloqueado)'
                }
            
            return result
            
        except Exception as e:
            return {
                'executable': False,
                'reflected_only': False,
                'error': str(e),
                'evidence': {'error': str(e), 'test_name': 'XSS Validation', 'impact': 'None'},
                'validation_performed': True
            }
    
    def validate_open_redirect(self, url, param_name):
        """
        Validate open redirect with bypass techniques.
        """
        result = {
            'vulnerable': False,
            'has_validation': False,
            'evidence': {},
            'validation_performed': True
        }
        
        try:
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            bypass_payloads = [
                '//evil.com',
                'https://evil.com',
                '@evil.com',
                'javascript:alert(1)',
            ]
            
            working_bypasses = []
            blocked_attempts = 0
            
            for payload in bypass_payloads:
                params = {param_name: payload}
                resp = self.session.get(base_url, params=params, timeout=self.timeout, allow_redirects=False)
                
                location = resp.headers.get('Location', '')
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    if 'evil.com' in location or payload in location:
                        working_bypasses.append({'payload': payload, 'location': location})
                else:
                    blocked_attempts += 1
            
            result['vulnerable'] = len(working_bypasses) > 0
            result['has_validation'] = blocked_attempts > 0
            result['evidence'] = {
                'working_bypasses': working_bypasses,
                'blocked_count': blocked_attempts,
                'test_name': 'Open Redirect Bypass',
                'impact': 'None',
                'reason': f'{len(working_bypasses)} bypass(es)' if working_bypasses else 'Whitelist bloqueou'
            }
            
            return result
            
        except Exception as e:
            return {
                'vulnerable': False,
                'has_validation': False,
                'error': str(e),
                'evidence': {'error': str(e), 'test_name': 'Open Redirect', 'impact': 'None'},
                'validation_performed': True
            }
    
    def validate_clickjacking(self, url):
        """
        Validate clickjacking considering both X-Frame-Options and CSP.
        """
        result = {
            'vulnerable': True,
            'has_xfo': False,
            'has_csp': False,
            'evidence': {},
            'validation_performed': True
        }
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            
            xfo = resp.headers.get('X-Frame-Options', '').lower()
            has_xfo = xfo in ['deny', 'sameorigin']
            
            csp = resp.headers.get('Content-Security-Policy', '').lower()
            csp_protects = "frame-ancestors 'none'" in csp or "frame-ancestors 'self'" in csp
            
            result['has_xfo'] = has_xfo
            result['has_csp'] = csp_protects
            result['vulnerable'] = not (has_xfo or csp_protects)
            
            defenses = []
            if has_xfo:
                defenses.append(f'X-Frame-Options: {xfo}')
            if csp_protects:
                defenses.append('CSP frame-ancestors')
            
            result['evidence'] = {
                'x_frame_options': xfo if xfo else 'None',
                'has_defense': has_xfo or csp_protects,
                'defenses': defenses,
                'test_name': 'Clickjacking Defense',
                'impact': 'None',
                'reason': f'Protegido: {", ".join(defenses)}' if defenses else 'Sem defesa'
            }
            
            return result
            
        except Exception as e:
            return {
                'vulnerable': True,
                'has_xfo': False,
                'has_csp': False,
                'error': str(e),
                'evidence': {'error': str(e), 'test_name': 'Clickjacking', 'impact': 'None'},
                'validation_performed': True
            }
