    def check_api_security(self):
        """
        API Security Scanner - OWASP API Top 10
        Tests for API-specific vulnerabilities
        """
        try:
            # Check if target is an API
            if self.api_scanner.is_api_endpoint(self.target_url):
                api_findings = self.api_scanner.scan_endpoint(self.target_url)
                
                for finding in api_findings:
                    self._add_result(
                        finding['vulnerability'],
                        finding['status'],
                        finding['details'],
                        finding['severity'],
                        finding['methodology'],
                        finding['manual_test'],
                        finding['risk'],
                        finding['category']
                    )
            
            # Also test discovered API endpoints
            if self.discovered_params:
                tested_urls = set()
                for url, params in self.discovered_params:
                    if url in tested_urls:
                        continue
                    tested_urls.add(url)
                    
                    if self.api_scanner.is_api_endpoint(url):
                        api_findings = self.api_scanner.scan_endpoint(url)
                        
                        for finding in api_findings:
                            self._add_result(
                                finding['vulnerability'],
                                finding['status'],
                                finding['details'],
                                finding['severity'],
                                finding['methodology'],
                                finding['manual_test'],
                                finding['risk'],
                                finding['category']
                            )
        except Exception as e:
            pass
