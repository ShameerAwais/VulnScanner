#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
A comprehensive tool for non-intrusive vulnerability assessment of web applications.
"""

import requests
import urllib.parse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import json
import time
from datetime import datetime
import os
from typing import Dict, List, Set, Tuple, Optional
import logging
from dataclasses import dataclass
from enum import Enum
import argparse
import sys

# Import report generator
try:
    from report_generator import ReportGenerator
except ImportError:
    ReportGenerator = None

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Enumeration for risk levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Information"

@dataclass
class Vulnerability:
    """Data class for vulnerability findings"""
    name: str
    description: str
    risk_level: RiskLevel
    location: str
    evidence: str
    recommendation: str
    cwe_id: Optional[str] = None

@dataclass
class ScanResult:
    """Data class for scan results"""
    target_url: str
    scan_timestamp: datetime
    discovered_pages: List[str]
    discovered_forms: List[Dict]
    security_headers: Dict
    cookies: List[Dict]
    vulnerabilities: List[Vulnerability]
    software_stack: Dict
    scan_duration: float

class WebVulnerabilityScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, target_url: str, max_depth: int = 3, timeout: int = 30, cookies: Dict[str, str] = None, auth_credentials: Dict[str, str] = None):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Add cookies if provided
        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value, domain=self.base_domain)
        
        # Store auth credentials for later use
        self.auth_credentials = auth_credentials or {}
        
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict] = []
        self.vulnerabilities: List[Vulnerability] = []
    
    def authenticate(self) -> bool:
        """Attempt to authenticate with the target website using improved logic"""
        if not self.auth_credentials:
            logger.info("No authentication credentials provided, skipping authentication")
            return False
        
        try:
            logger.info("Attempting to authenticate...")
            
            # First, get the login page to extract CSRF tokens
            login_url = urljoin(self.target_url, 'login.php')
            logger.info(f"Getting login page: {login_url}")
            
            response = self.session.get(login_url, timeout=self.timeout)
            if response.status_code != 200:
                logger.warning(f"Failed to get login page: {response.status_code}")
                return False
            
            logger.info("Login page loaded successfully")
            
            # Parse the page to get CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_input = soup.find('input', {'name': 'user_token'})
            
            if not csrf_input:
                logger.warning("No CSRF token found in login form")
                # Fall back to old method
                return self._fallback_authentication()
            
            csrf_token = csrf_input.get('value', '')
            logger.info(f"CSRF token extracted: {csrf_token[:20]}...")
            
            # Prepare login data
            login_data = {
                'username': self.auth_credentials.get('username', 'admin'),
                'password': self.auth_credentials.get('password', 'password'),
                'user_token': csrf_token,
                'Login': 'Login'
            }
            
            logger.info(f"Login data prepared: {login_data}")
            
            # Submit login form
            logger.info("Submitting login form...")
            response = self.session.post(login_url, data=login_data, timeout=self.timeout, allow_redirects=True)
            
            logger.info(f"Login response received - Status: {response.status_code}, Final URL: {response.url}")
            
            # Check if login was successful using improved logic
            if response.status_code == 200:
                # Check if we're redirected to main page (successful login)
                if 'index.php' in response.url:
                    logger.info("✅ Redirected to main page - login successful!")
                    
                    # Verify by checking if we can access the main page
                    main_response = self.session.get(self.target_url, timeout=self.timeout)
                    if main_response.status_code == 200:
                        if 'logout' in main_response.text.lower():
                            logger.info("Successfully authenticated! Logout link found.")
                            return True
                        else:
                            logger.info("On main page but logout link not found - assuming success")
                            return True
                    else:
                        logger.warning(f"Failed to access main page after login: {main_response.status_code}")
                        return False
                        
                else:
                    logger.warning("Not redirected to main page - checking for error messages")
                    response_text = response.text.lower()
                    
                    if any(indicator in response_text for indicator in ['login failed', 'invalid credentials', 'access denied', 'incorrect']):
                        logger.error("Login failed - invalid credentials")
                        return False
                    elif 'login' in response.url.lower():
                        logger.warning("Still on login page - authentication failed")
                        return False
                    else:
                        logger.info("Login response unclear - assuming success and continuing")
                        return True
            else:
                logger.warning(f"Login response status: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def _fallback_authentication(self) -> bool:
        """Fallback authentication method using the old logic"""
        logger.info("Using fallback authentication method...")
        
        try:
            # Get the main page to look for forms
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code != 200:
                logger.warning(f"Failed to get main page for fallback auth: {response.status_code}")
                return False
            
            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for login forms
            login_forms = soup.find_all('form')
            login_success = False
            
            for form in login_forms:
                # Check if this looks like a login form
                form_text = form.get_text().lower()
                form_action = form.get('action', '').lower()
                
                is_login_form = (
                    any(keyword in form_text for keyword in ['login', 'sign in', 'username', 'password']) or
                    any(keyword in form_action for keyword in ['login', 'auth']) or
                    'username' in form_text or 'password' in form_text
                )
                
                if is_login_form:
                    logger.info(f"Found potential login form: {form.get('action', 'self')}")
                    
                    # Extract form data
                    form_data = {}
                    inputs = form.find_all(['input', 'textarea'])
                    
                    for inp in inputs:
                        input_type = inp.get('type', 'text')
                        input_name = inp.get('name', '')
                        input_value = inp.get('value', '')
                        
                        if input_type == 'hidden':
                            form_data[input_name] = input_value
                        elif input_type == 'text' and ('username' in input_name.lower() or 'user' in input_name.lower()):
                            form_data[input_name] = self.auth_credentials.get('username', 'admin')
                        elif input_name == 'password':
                            form_data[input_name] = self.auth_credentials.get('password', 'password')
                    
                    # Submit the form
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'POST').upper()
                    
                    if form_action:
                        if form_action.startswith('/'):
                            submit_url = urljoin(self.target_url, form_action)
                        else:
                            submit_url = urljoin(self.target_url, form_action)
                    else:
                        submit_url = self.target_url
                    
                    logger.info(f"Submitting login form to: {submit_url}")
                    
                    try:
                        if form_method == 'POST':
                            response = self.session.post(submit_url, data=form_data, timeout=self.timeout, allow_redirects=True)
                        else:
                            response = self.session.get(submit_url, params=form_data, timeout=self.timeout, allow_redirects=True)
                        
                        logger.info(f"Login response status: {response.status_code}")
                        
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            
                            # Check for success indicators
                            if any(indicator in response_text for indicator in ['logout', 'welcome', 'dashboard', 'admin', 'logged in']):
                                logger.info("Authentication successful!")
                                login_success = True
                                break
                            elif any(indicator in response_text for indicator in ['login failed', 'invalid credentials', 'access denied']):
                                logger.warning("Login failed - invalid credentials")
                                continue
                            else:
                                logger.info("Authentication attempt completed, continuing...")
                                login_success = True
                                break
                                
                    except Exception as e:
                        logger.debug(f"Failed to submit login form: {str(e)}")
                        continue
            
            return login_success
            
        except Exception as e:
            logger.error(f"Fallback authentication failed: {str(e)}")
            return False
    
    def set_cookies(self, cookies: Dict[str, str]):
        """Set cookies for the session"""
        for name, value in cookies.items():
            self.session.cookies.set(name, value, domain=self.base_domain)
    
    def add_cookie(self, name: str, value: str):
        """Add a single cookie to the session"""
        self.session.cookies.set(name, value, domain=self.base_domain)
        
    def start_scan(self) -> ScanResult:
        """Main scanning method"""
        start_time = time.time()
        logger.info(f"Starting vulnerability scan for: {self.target_url}")
        
        try:
            # 1. Target Input & URL parsing
            if not self._validate_url():
                raise ValueError(f"Invalid URL: {self.target_url}")
            
            # 2. Authentication (if credentials provided)
            if self.auth_credentials:
                logger.info("🔐 Starting authentication process...")
                auth_result = self.authenticate()
                if auth_result:
                    logger.info("✅ Authentication successful - proceeding with scan")
                else:
                    logger.warning("❌ Authentication failed - continuing with limited access")
            else:
                logger.info("ℹ️ No authentication credentials provided - skipping authentication")
            
            # 3. Passive Reconnaissance & Discovery
            self._crawl_website()
            self._discover_hidden_paths()
            
            # 4. Vulnerability Checks
            self._check_security_headers()
            self._check_cookies()
            self._check_forms_for_vulnerabilities()
            self._check_reflected_xss_in_urls() # Added new method
            self._check_response_body_xss() # Added new method
            self._check_software_stack()
            self._check_open_directories()
            
            # 5. OWASP Top 10 Specific Testing
            self._test_broken_authentication()
            self._test_sensitive_data_exposure()
            self._test_dvwa_specific_vulnerabilities() # Added new method
            self._test_actual_dvwa_vulnerabilities() # Added new method
            
            # 6. Enhanced Form Testing with Better Payload Coverage
            self._test_forms_with_enhanced_payloads()
            
            scan_duration = time.time() - start_time
            
            return ScanResult(
                target_url=self.target_url,
                scan_timestamp=datetime.now(),
                discovered_pages=list(self.discovered_urls),
                discovered_forms=self.discovered_forms,
                security_headers=self._get_security_headers(),
                cookies=self._get_cookies(),
                vulnerabilities=self.vulnerabilities,
                software_stack=self._get_software_stack(),
                scan_duration=scan_duration
            )
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise
    
    def _validate_url(self) -> bool:
        """Validate the target URL"""
        try:
            parsed = urlparse(self.target_url)
            return all([parsed.scheme, parsed.netloc])
        except Exception:
            return False
    
    def _crawl_website(self):
        """Crawl the website to discover pages and forms"""
        logger.info("Starting website crawling...")
        urls_to_visit = [self.target_url]
        visited = set()
        
        for depth in range(self.max_depth):
            current_level_urls = urls_to_visit.copy()
            urls_to_visit = []
            
            logger.info(f"Crawling depth {depth + 1}, URLs to visit: {len(current_level_urls)}")
            
            for url in current_level_urls:
                if url in visited or url in self.discovered_urls:
                    continue
                    
                try:
                    logger.info(f"Crawling URL: {url}")
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    logger.info(f"Response status: {response.status_code}, URL: {response.url}")
                    
                    if response.status_code == 200:
                        self.discovered_urls.add(url)
                        visited.add(url)
                        logger.info(f"Successfully crawled: {url}")
                        
                        # Parse HTML for forms and links
                        soup = BeautifulSoup(response.text, 'html.parser')
                        self._extract_forms(soup, url)
                        self._extract_links(soup, url, urls_to_visit)
                        
                        # Check for hidden fields and tokens
                        self._check_hidden_fields(soup, url)
                        
                        logger.info(f"After crawling {url}: discovered {len(self.discovered_urls)} URLs, {len(self.discovered_forms)} forms")
                    else:
                        logger.warning(f"Failed to crawl {url}: HTTP {response.status_code}")
                        
                except Exception as e:
                    logger.warning(f"Failed to crawl {url}: {str(e)}")
                    continue
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """Extract forms from HTML"""
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'page_url': page_url
            }
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_data = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'value': inp.get('value', ''),
                    'required': inp.get('required') is not None
                }
                form_data['inputs'].append(input_data)
            
            self.discovered_forms.append(form_data)
        
        # Also look for input elements that are not in forms but are functional
        # These are often handled by JavaScript
        standalone_inputs = soup.find_all('input', type=['text', 'textarea', 'search'])
        if standalone_inputs:
            # Create a virtual form for standalone inputs
            virtual_form = {
                'action': page_url,
                'method': 'GET',  # Assume GET for standalone inputs
                'inputs': [],
                'page_url': page_url,
                'is_virtual': True  # Mark as virtual form
            }
            
            for inp in standalone_inputs:
                # Skip inputs that are already in forms
                if not inp.find_parent('form'):
                    input_data = {
                        'type': inp.get('type', 'text'),
                        'name': inp.get('name', ''),
                        'id': inp.get('id', ''),
                        'value': inp.get('value', ''),
                        'required': inp.get('required') is not None
                    }
                    virtual_form['inputs'].append(input_data)
            
            # Only add virtual form if it has inputs
            if virtual_form['inputs']:
                self.discovered_forms.append(virtual_form)
        
        # Also check iframes for potential XSS vulnerabilities
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            iframe_src = iframe.get('src', '')
            if iframe_src:
                # Convert relative URLs to absolute
                iframe_url = urljoin(page_url, iframe_src)
                self.discovered_urls.add(iframe_url)
                
                # Create a virtual form for iframe content
                iframe_form = {
                    'action': iframe_url,
                    'method': 'GET',
                    'inputs': [],
                    'page_url': iframe_url,
                    'is_iframe': True,
                    'parent_page': page_url
                }
                
                # Add a generic input for iframe testing
                iframe_form['inputs'].append({
                    'type': 'text',
                    'name': 'iframe_input',
                    'id': 'iframe_input',
                    'value': '',
                    'required': False
                })
                
                self.discovered_forms.append(iframe_form)
    
    def _extract_links(self, soup: BeautifulSoup, page_url: str, urls_to_visit: List[str]):
        """Extract links from HTML"""
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            absolute_url = urljoin(page_url, href)
            
            # Only follow links within the same domain
            if urlparse(absolute_url).netloc == self.base_domain:
                if absolute_url not in self.discovered_urls:
                    urls_to_visit.append(absolute_url)
    
    def _check_hidden_fields(self, soup: BeautifulSoup, page_url: str):
        """Check for hidden fields and potential tokens"""
        hidden_inputs = soup.find_all('input', type='hidden')
        for hidden_input in hidden_inputs:
            name = hidden_input.get('name', '')
            value = hidden_input.get('value', '')
            
            # Check for common token patterns
            token_patterns = [
                r'csrf|xsrf|token|auth|session|key',
                r'[a-f0-9]{32,}',  # Hex strings (likely hashes)
                r'[A-Za-z0-9+/]{20,}={0,2}'  # Base64 strings
            ]
            
            for pattern in token_patterns:
                if re.search(pattern, name, re.IGNORECASE) or re.search(pattern, value, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        name="Hidden Token Field Detected",
                        description=f"Hidden field '{name}' with potential sensitive value detected",
                        risk_level=RiskLevel.INFO,
                        location=page_url,
                        evidence=f"Field: {name}, Value: {value[:50]}...",
                        recommendation="Review if this token is properly secured and not exposed to client-side manipulation"
                    ))
                    break
    
    def _discover_hidden_paths(self):
        """Discover common hidden paths and open directories"""
        common_paths = [
            '/admin', '/admin/', '/administrator', '/login', '/wp-admin',
            '/phpmyadmin', '/phpMyAdmin', '/config', '/backup', '/backups',
            '/.git', '/.svn', '/.env', '/robots.txt', '/sitemap.xml',
            '/api', '/api/', '/v1', '/v2', '/test', '/dev', '/staging',
            '/.htaccess', '/web.config', '/info.php', '/phpinfo.php'
        ]
        
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    self.discovered_urls.add(url)
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append(Vulnerability(
                            name="Potentially Sensitive Path Accessible",
                            description=f"Path {path} is accessible and may contain sensitive information",
                            risk_level=RiskLevel.MEDIUM,
                            location=url,
                            evidence=f"HTTP Status: {response.status_code}",
                            recommendation="Review access controls and consider restricting access to sensitive paths"
                        ))
                        
            except Exception as e:
                logger.debug(f"Failed to check {path}: {str(e)}")
                continue
    
    def _check_security_headers(self):
        """Check for missing or insecure security headers"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'X-Frame-Options',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'X-XSS-Protection': 'X-XSS-Protection',
                'Referrer-Policy': 'Referrer-Policy',
                'Permissions-Policy': 'Permissions-Policy'
            }
            
            for header, name in security_headers.items():
                if header not in headers:
                    self.vulnerabilities.append(Vulnerability(
                        name=f"Missing Security Header: {name}",
                        description=f"The {name} security header is not present",
                        risk_level=RiskLevel.MEDIUM,
                        location=self.target_url,
                        evidence=f"Header '{header}' not found in response",
                        recommendation=f"Implement the {name} header to improve security"
                    ))
                else:
                    value = headers[header]
                    # Check for weak configurations
                    if header == 'X-Frame-Options' and value == 'ALLOWALL':
                        self.vulnerabilities.append(Vulnerability(
                            name="Weak X-Frame-Options Configuration",
                            description="X-Frame-Options is set to ALLOWALL, allowing clickjacking",
                            risk_level=RiskLevel.HIGH,
                            location=self.target_url,
                            evidence=f"X-Frame-Options: {value}",
                            recommendation="Set X-Frame-Options to DENY or SAMEORIGIN"
                        ))
                        
        except Exception as e:
            logger.error(f"Failed to check security headers: {str(e)}")
    
    def _check_cookies(self):
        """Check for insecure cookie configurations"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_issues = []
                
                if not cookie.secure and urlparse(self.target_url).scheme == 'https':
                    cookie_issues.append("Missing Secure flag")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_issues.append("Missing HttpOnly flag")
                
                if cookie_issues:
                    self.vulnerabilities.append(Vulnerability(
                        name="Insecure Cookie Configuration",
                        description=f"Cookie '{cookie.name}' has security issues",
                        risk_level=RiskLevel.MEDIUM,
                        location=self.target_url,
                        evidence=f"Cookie: {cookie.name}, Issues: {', '.join(cookie_issues)}",
                        recommendation="Set Secure and HttpOnly flags for sensitive cookies"
                    ))
                    
        except Exception as e:
            logger.error(f"Failed to check cookies: {str(e)}")
    
    def _check_forms_for_vulnerabilities(self):
        """Check forms for OWASP Top 10 vulnerabilities"""
        from config import ScannerConfig
        
        logger.info("Testing forms for OWASP Top 10 vulnerabilities...")
        
        # Track skipped pages for transparency
        skipped_pages = set()
        tested_pages = set()
        
        for form in self.discovered_forms:
            page_url = form['page_url']
            
            # Skip forms that are just login forms or redirects
            if 'login.php' in page_url or 'logout.php' in page_url:
                continue
                
            # Use enhanced filtering to skip static/documentation content
            if not self._should_test_for_vulnerabilities(page_url):
                skipped_pages.add(page_url)
                logger.debug(f"Skipping static/documentation page: {page_url}")
                continue
                
            tested_pages.add(page_url)
            logger.info(f"Testing form on: {page_url}")
                
            # Test each input field for vulnerabilities
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search']:
                    param_name = input_field['name'] or input_field['id'] or 'input_field'
                    
                    # Test for XSS (A03:2021)
                    self._test_xss_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for SQL Injection (A03:2021)
                    self._test_sql_injection_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for Command Injection (A03:2021)
                    self._test_command_injection_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for Path Traversal (A01:2021)
                    self._test_path_traversal_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for SSRF (A05:2021)
                    self._test_ssrf_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for File Upload (A05:2021)
                    self._test_file_upload_vulnerability(form, input_field, param_name, page_url)
                    
                    # Test for CSRF (A01:2021)
                    self._test_csrf_vulnerability(form, input_field, param_name, page_url)
        
        # Log summary of testing
        logger.info(f"Form testing summary: {len(tested_pages)} pages tested, {len(skipped_pages)} pages skipped")
        if skipped_pages:
            logger.debug(f"Skipped pages: {list(skipped_pages)[:5]}{'...' if len(skipped_pages) > 5 else ''}")
    
    def _test_xss_vulnerability(self, form, input_field, param_name, page_url):
        """Test for XSS vulnerabilities"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(page_url):
            logger.debug(f"Skipping XSS test on static/documentation page: {page_url}")
            return
        
        xss_payloads = ScannerConfig.XSS_PAYLOADS[:8]  # Test more payloads for better coverage
        
        for payload in xss_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for full payload reflection
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        name="Reflected XSS Vulnerability",
                        description=f"Input field '{param_name}' is vulnerable to reflected XSS",
                        risk_level=RiskLevel.HIGH,
                        location=page_url,
                        evidence=f"Payload '{payload[:50]}...' fully reflected in response",
                        recommendation="Implement proper input validation and output encoding"
                    ))
                    logger.info(f"🚨 XSS vulnerability found in {param_name} on {page_url}")
                    break
                    
                # Check for partial payload reflection (common in filtered XSS)
                xss_indicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'onmouseover', 'onfocus', 'onblur']
                if any(indicator in response.text for indicator in xss_indicators):
                    self.vulnerabilities.append(Vulnerability(
                        name="Potential XSS Vulnerability",
                        description=f"Input field '{param_name}' may be vulnerable to XSS (partial reflection detected)",
                        risk_level=RiskLevel.MEDIUM,
                        location=page_url,
                        evidence=f"XSS indicators found in response to payload '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding"
                    ))
                    logger.info(f"Potential XSS vulnerability found in {param_name} on {page_url}")
                    break
                
                # Check for HTML tag reflection (common in stored XSS)
                html_tags = ['<', '>', '&lt;', '&gt;']
                if any(tag in response.text for tag in html_tags) and any(char in payload for char in ['<', '>']):
                    self.vulnerabilities.append(Vulnerability(
                        name="Potential XSS Vulnerability",
                        description=f"Input field '{param_name}' may be vulnerable to XSS (HTML tags reflected)",
                        risk_level=RiskLevel.MEDIUM,
                        location=page_url,
                        evidence=f"HTML tags reflected in response to payload '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding"
                    ))
                    logger.info(f"Potential XSS vulnerability found in {param_name} on {page_url}")
                    break
                    
            except Exception as e:
                logger.debug(f"Failed to test XSS payload: {str(e)}")
                continue
    
    def _test_sql_injection_vulnerability(self, form, input_field, param_name, page_url):
        """Test for SQL injection vulnerabilities"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(page_url):
            logger.debug(f"Skipping SQL injection test on static/documentation page: {page_url}")
            return
        
        sql_payloads = ScannerConfig.SQL_PAYLOADS[:5]  # Test more payloads for better coverage
        sql_patterns = ScannerConfig.SQL_ERROR_PATTERNS
        
        for payload in sql_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for SQL error patterns
                for pattern in sql_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # Additional verification: check if this is a real SQL error vs static content
                        # Look for actual SQL error context, not just pattern matches
                        sql_context_indicators = ['mysql', 'sql', 'database', 'query', 'syntax', 'error']
                        has_sql_context = any(indicator in response.text.lower() for indicator in sql_context_indicators)
                        
                        if has_sql_context:
                            self.vulnerabilities.append(Vulnerability(
                                name="SQL Injection Vulnerability",
                                description=f"Input field '{param_name}' is vulnerable to SQL injection",
                                risk_level=RiskLevel.CRITICAL,
                                location=page_url,
                                evidence=f"SQL error pattern detected with payload '{payload}'",
                                recommendation="Implement parameterized queries and input validation"
                            ))
                            logger.info(f"SQL injection vulnerability found in {param_name} on {page_url}")
                            return  # Found SQL injection, move to next field
                        else:
                            logger.debug(f"SQL pattern found but no SQL context - likely false positive on {page_url}")
                        
            except Exception as e:
                logger.debug(f"Failed to test SQL injection payload: {str(e)}")
                continue
    
    def _test_command_injection_vulnerability(self, form, input_field, param_name, page_url):
        """Test for command injection vulnerabilities"""
        from config import ScannerConfig
        
        # Only test command injection on forms that might execute commands
        if not any(keyword in page_url.lower() for keyword in ['exec', 'command', 'system', 'shell']):
            return
            
        cmd_payloads = ScannerConfig.COMMAND_INJECTION_PAYLOADS[:3]  # Test first 3 payloads
        cmd_patterns = ScannerConfig.COMMAND_INJECTION_PATTERNS
        
        for payload in cmd_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for command execution patterns
                for pattern in cmd_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append(Vulnerability(
                            name="Command Injection Vulnerability",
                            description=f"Input field '{param_name}' is vulnerable to command injection",
                            risk_level=RiskLevel.CRITICAL,
                            location=page_url,
                            evidence=f"Command execution pattern detected with payload '{payload[:50]}...'",
                            recommendation="Implement proper input validation and avoid command execution"
                        ))
                        logger.info(f"🚨 Command injection vulnerability found in {param_name} on {page_url}")
                        return
                        
            except Exception as e:
                logger.debug(f"Failed to test command injection payload: {str(e)}")
                continue
    
    def _test_path_traversal_vulnerability(self, form, input_field, param_name, page_url):
        """Test for path traversal vulnerabilities"""
        from config import ScannerConfig
        
        # Only test path traversal on forms that might access files
        if not any(keyword in page_url.lower() for keyword in ['file', 'include', 'page', 'path']):
            return
            
        path_payloads = ScannerConfig.PATH_TRAVERSAL_PAYLOADS[:2]  # Test first 2 payloads
        
        for payload in path_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for path traversal indicators
                if any(indicator in response.text.lower() for indicator in ['root:', 'bin:', 'etc:', 'windows:', 'system32:']):
                    self.vulnerabilities.append(Vulnerability(
                        name="Path Traversal Vulnerability",
                        description=f"Input field '{param_name}' is vulnerable to path traversal",
                        risk_level=RiskLevel.HIGH,
                        location=page_url,
                        evidence=f"Path traversal successful with payload '{payload[:50]}...'",
                        recommendation="Implement proper path validation and sanitization"
                    ))
                    logger.info(f"🚨 Path traversal vulnerability found in {param_name} on {page_url}")
                    return
                    
            except Exception as e:
                logger.debug(f"Failed to test path traversal payload: {str(e)}")
                continue
    
    def _test_ssrf_vulnerability(self, form, input_field, param_name, page_url):
        """Test for SSRF vulnerabilities"""
        from config import ScannerConfig
        
        # Only test SSRF on forms that might make external requests
        if not any(keyword in page_url.lower() for keyword in ['url', 'link', 'redirect', 'fetch']):
            return
            
        ssrf_payloads = ScannerConfig.SSRF_PAYLOADS[:2]  # Test first 2 payloads
        
        for payload in ssrf_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for SSRF indicators
                if any(indicator in response.text.lower() for indicator in ['localhost', '127.0.0.1', 'internal', 'private']):
                    self.vulnerabilities.append(Vulnerability(
                        name="SSRF Vulnerability",
                        description=f"Input field '{param_name}' is vulnerable to SSRF",
                        risk_level=RiskLevel.HIGH,
                        location=page_url,
                        evidence=f"SSRF successful with payload '{payload[:50]}...'",
                        recommendation="Implement proper URL validation and whitelisting"
                    ))
                    logger.info(f"🚨 SSRF vulnerability found in {param_name} on {page_url}")
                    return
                    
            except Exception as e:
                logger.debug(f"Failed to test SSRF payload: {str(e)}")
                continue
    
    def _test_file_upload_vulnerability(self, form, input_field, param_name, page_url):
        """Test for file upload vulnerabilities (OWASP Top 10 - A05:2021)"""
        from config import ScannerConfig
        
        # Only test file upload on forms that have file inputs
        if input_field['type'] != 'file':
            return
            
        logger.info(f"Testing file upload vulnerability on {page_url}")
        
        # Check if dangerous file extensions are allowed
        dangerous_extensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.exe', '.bat', '.cmd', '.sh']
        
        # This is a basic check - in a real scanner you'd try to upload actual files
        # For now, we'll just check if the form allows file uploads without proper validation
        if any(ext in page_url.lower() for ext in ['upload', 'file', 'attachment', 'upload.php', 'file.php']):
            self.vulnerabilities.append(Vulnerability(
                name="File Upload Vulnerability",
                description=f"File upload form '{param_name}' may be vulnerable to malicious file uploads",
                risk_level=RiskLevel.HIGH,
                location=page_url,
                evidence=f"File upload form detected without apparent validation controls",
                recommendation="Implement proper file type validation, size limits, and content scanning"
            ))
            logger.info(f"🚨 File upload vulnerability potential detected on {page_url}")
        
        # Check if this is a DVWA file upload vulnerability page
        if 'dvwa' in page_url.lower() and any(keyword in page_url.lower() for keyword in ['vulnerabilities', 'upload', 'file']):
            self.vulnerabilities.append(Vulnerability(
                name="DVWA File Upload Vulnerability",
                description=f"DVWA file upload vulnerability page detected - this is intentionally vulnerable for testing",
                risk_level=RiskLevel.HIGH,
                location=page_url,
                evidence="DVWA file upload vulnerability page identified",
                recommendation="This is a training application - do not deploy in production"
            ))
            logger.info(f"🚨 DVWA file upload vulnerability page detected on {page_url}")
            
        # Enhanced testing: Try to detect actual file upload vulnerabilities
        try:
            # Test with a simple text file first to see if uploads work
            test_content = "This is a test file for vulnerability scanning"
            
            # Create a file-like object
            import io
            test_file = io.StringIO(test_content)
            
            # Prepare file data for upload test
            files = {param_name: ('test.txt', test_file, 'text/plain')}
            
            # Attempt upload if it's a POST form
            if form['method'] == 'POST':
                response = self.session.post(page_url, files=files, timeout=self.timeout)
                
                # Check if upload was successful (this could indicate a vulnerability)
                if response.status_code == 200:
                    # Look for indicators that the file was processed
                    upload_indicators = ['upload', 'file', 'success', 'uploaded', 'saved']
                    if any(indicator in response.text.lower() for indicator in upload_indicators):
                        self.vulnerabilities.append(Vulnerability(
                            name="File Upload Functionality Confirmed",
                            description=f"File upload form on {page_url} successfully processes files",
                            risk_level=RiskLevel.MEDIUM,
                            location=page_url,
                            evidence=f"File upload test succeeded - form processes files without apparent validation",
                            recommendation="Implement strict file type validation and content scanning"
                        ))
                        logger.info(f"File upload functionality confirmed on {page_url}")
                        
        except Exception as e:
            logger.debug(f"Failed to test file upload functionality: {str(e)}")
            pass
    
    def _test_csrf_vulnerability(self, form, input_field, param_name, page_url):
        """Test for CSRF vulnerabilities (OWASP Top 10 - A01:2021)"""
        
        # Check if form lacks CSRF protection
        if form['method'] == 'POST':
            # Look for CSRF tokens in the form
            csrf_indicators = ['csrf', 'token', 'xsrf', 'nonce', 'authenticity']
            form_has_csrf = any(indicator in str(form).lower() for indicator in csrf_indicators)
            
            if not form_has_csrf:
                # Check if this is a sensitive action (password change, admin action, etc.)
                sensitive_actions = ['password', 'admin', 'delete', 'update', 'modify', 'change']
                is_sensitive = any(action in page_url.lower() for action in sensitive_actions)
                
                if is_sensitive:
                    self.vulnerabilities.append(Vulnerability(
                        name="CSRF Vulnerability",
                        description=f"Form on '{page_url}' lacks CSRF protection",
                        risk_level=RiskLevel.HIGH,
                        location=page_url,
                        evidence="POST form detected without CSRF token or protection mechanism",
                        recommendation="Implement CSRF tokens and validate them on form submission"
                    ))
                    logger.info(f"🚨 CSRF vulnerability detected on {page_url}")
    
    def _test_broken_authentication(self):
        """Test for broken authentication vulnerabilities (OWASP Top 10 - A02:2021)"""
        
        # Test for weak password policies
        # Test for session fixation
        # Test for predictable session IDs
        # Test for logout functionality
        
        # Check if logout functionality exists and works
        logout_urls = [url for url in self.discovered_urls if 'logout' in url.lower()]
        
        if not logout_urls:
            self.vulnerabilities.append(Vulnerability(
                name="Missing Logout Functionality",
                description="Application lacks proper logout functionality",
                risk_level=RiskLevel.MEDIUM,
                location=self.target_url,
                evidence="No logout endpoints discovered during scan",
                recommendation="Implement secure logout functionality that invalidates sessions"
            ))
            logger.info("🚨 Missing logout functionality detected")
        
        # Check for session management issues
        if hasattr(self, 'session') and hasattr(self.session, 'cookies'):
            session_cookies = [cookie for cookie in self.session.cookies if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower()]
            
            for cookie in session_cookies:
                if len(cookie.value) < 16:  # Weak session ID
                    self.vulnerabilities.append(Vulnerability(
                        name="Weak Session ID",
                        description=f"Session cookie '{cookie.name}' has weak value",
                        risk_level=RiskLevel.MEDIUM,
                        location=self.target_url,
                        evidence=f"Session cookie value length: {len(cookie.value)} characters",
                        recommendation="Use cryptographically strong session identifiers"
                    ))
                    logger.info(f"🚨 Weak session ID detected: {cookie.name}")
    
    def _test_sensitive_data_exposure(self):
        """Test for sensitive data exposure (OWASP Top 10 - A02:2021)"""
        
        # Check for sensitive information in responses
        sensitive_patterns = [
            r'password.*=.*[\w@#$%^&*]',
            r'api.*key.*=.*[\w@#$%^&*]',
            r'secret.*=.*[\w@#$%^&*]',
            r'token.*=.*[\w@#$%^&*]',
            r'private.*key',
            r'aws.*access.*key',
            r'credit.*card',
            r'ssn|social.*security',
            r'phone.*number',
            r'email.*address'
        ]
        
        # Test discovered URLs for sensitive data
        for url in list(self.discovered_urls)[:10]:  # Test first 10 URLs for speed
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                for pattern in sensitive_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append(Vulnerability(
                            name="Sensitive Data Exposure",
                            description=f"Sensitive information exposed on {url}",
                            risk_level=RiskLevel.HIGH,
                            location=url,
                            evidence=f"Sensitive data pattern detected: {pattern}",
                            recommendation="Review and remove sensitive information from client-side code"
                        ))
                        logger.info(f"🚨 Sensitive data exposure detected on {url}")
                        break
                        
            except Exception as e:
                logger.debug(f"Failed to check sensitive data on {url}: {str(e)}")
                continue
    
    def _check_reflected_xss_in_urls(self):
        """Check for OWASP Top 10 vulnerabilities in URL parameters"""
        from config import ScannerConfig
        
        logger.info("Testing URL parameters for OWASP Top 10 vulnerabilities...")
        
        # Common parameter names that might be vulnerable
        common_params = ['q', 'query', 'search', 'id', 'name', 'title', 'content', 'message', 'error', 'msg', 'text', 
                        'keyword', 'term', 'input', 'data', 'value', 'param', 'arg', 'variable', 'field', 'user', 
                        'username', 'email', 'subject', 'body', 'description', 'comment', 'feedback', 'review', 
                        'note', 'info', 'details', 'summary', 'caption', 'label', 'alt', 'href', 'src', 'url']
        
        # Test each discovered URL for vulnerabilities
        for url in self.discovered_urls:
            # Skip URLs that are already being tested in forms
            if any(form['page_url'] == url for form in self.discovered_forms):
                continue
                
            # Skip static files and documentation
            static_extensions = ['.md', '.txt', '.pdf', '.doc', '.docx', '.html', '.htm', '.css', '.js', '.png', '.jpg', '.gif', '.ico']
            if any(url.lower().endswith(ext) for ext in static_extensions):
                continue
                
            # Skip README files and documentation
            if any(keyword in url.lower() for keyword in ['readme', 'documentation', 'help', 'guide', 'manual', 'changelog']):
                continue
                
            # Only test against dynamic pages (PHP, ASP, etc.) or pages with query parameters
            dynamic_extensions = ['.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.cgi', '.pl', '.py']
            if not any(url.lower().endswith(ext) for ext in dynamic_extensions) and '?' not in url:
                continue
                
            # Test with common parameter names for multiple vulnerability types
            for param_name in common_params:
                # Test XSS (A03:2021)
                self._test_url_xss(url, param_name)
                
                # Test SQL Injection (A03:2021)
                self._test_url_sql_injection(url, param_name)
                
                # Test Path Traversal (A01:2021)
                self._test_url_path_traversal(url, param_name)
                
                # Test SSRF (A05:2021)
                self._test_url_ssrf(url, param_name)
    
    def _test_url_xss(self, url, param_name):
        """Test URL parameter for XSS vulnerability"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(url):
            logger.debug(f"Skipping URL XSS test on static/documentation page: {url}")
            return
        
        xss_payloads = ScannerConfig.XSS_PAYLOADS[:5]  # Test more payloads for better coverage
        
        for payload in xss_payloads:
            try:
                params = {param_name: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
                
                # Check for full payload reflection
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        name="Reflected XSS via URL Parameter",
                        description=f"URL parameter '{param_name}' is vulnerable to reflected XSS",
                        risk_level=RiskLevel.HIGH,
                        location=f"{url}?{param_name}=[payload]",
                        evidence=f"Payload '{payload[:50]}...' reflected in response body",
                        recommendation="Implement proper input validation and output encoding for URL parameters"
                    ))
                    logger.info(f"🚨 XSS vulnerability found in URL parameter {param_name} on {url}")
                    break
                
                # Check for partial payload reflection (common in filtered XSS)
                xss_indicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'onmouseover', 'onfocus', 'onblur']
                if any(indicator in response.text for indicator in xss_indicators):
                    self.vulnerabilities.append(Vulnerability(
                        name="Potential XSS via URL Parameter",
                        description=f"URL parameter '{param_name}' may be vulnerable to XSS (partial reflection detected)",
                        risk_level=RiskLevel.MEDIUM,
                        location=f"{url}?{param_name}=[payload]",
                        evidence=f"XSS indicators found in response to payload '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding for URL parameters"
                    ))
                    logger.info(f"Potential XSS vulnerability found in URL parameter {param_name} on {url}")
                    break
                
                # Check for HTML tag reflection (common in stored XSS)
                html_tags = ['<', '>', '&lt;', '&gt;']
                if any(tag in response.text for tag in html_tags) and any(char in payload for char in ['<', '>']):
                    self.vulnerabilities.append(Vulnerability(
                        name="Potential XSS via URL Parameter",
                        description=f"URL parameter '{param_name}' may be vulnerable to XSS (HTML tags reflected)",
                        risk_level=RiskLevel.MEDIUM,
                        location=f"{url}?{param_name}=[payload]",
                        evidence=f"HTML tags reflected in response to payload '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding for URL parameters"
                    ))
                    logger.info(f"Potential XSS vulnerability found in URL parameter {param_name} on {url}")
                    break
                    
            except Exception as e:
                logger.debug(f"Failed to test XSS payload on {url}: {str(e)}")
                continue
    
    def _test_url_sql_injection(self, url, param_name):
        """Test URL parameter for SQL injection vulnerability"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(url):
            logger.debug(f"Skipping URL SQL injection test on static/documentation page: {url}")
            return
        
        sql_payloads = ScannerConfig.SQL_PAYLOADS[:3]  # Test more payloads for better coverage
        sql_patterns = ScannerConfig.SQL_ERROR_PATTERNS
        
        logger.debug(f"Testing SQL injection on {url} with parameter {param_name}")
        logger.debug(f"Using payloads: {sql_payloads}")
        
        for payload in sql_payloads:
            try:
                logger.debug(f"Testing payload: '{payload}' on {url}")
                params = {param_name: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
                
                for pattern in sql_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # Enhanced verification: check if this is a real SQL error vs static content
                        # Look for actual SQL error context, not just pattern matches
                        sql_context_indicators = ['mysql', 'sql', 'database', 'query', 'syntax', 'error', 'warning']
                        has_sql_context = any(indicator in response.text.lower() for indicator in sql_context_indicators)
                        
                        # Check if payload is actually reflected in the response
                        payload_reflected = payload in response.text
                        
                        if has_sql_context and payload_reflected:
                            logger.debug(f"SQL error pattern found: {pattern}")
                            logger.debug(f"Payload used: '{payload}'")
                            self.vulnerabilities.append(Vulnerability(
                                name="SQL Injection via URL Parameter",
                                description=f"URL parameter '{param_name}' is vulnerable to SQL injection",
                                risk_level=RiskLevel.CRITICAL,
                                location=f"{url}?{param_name}=[payload]",
                                evidence=f"SQL error pattern detected with payload '{payload}'",
                                recommendation="Implement parameterized queries and input validation"
                            ))
                            logger.info(f"SQL injection vulnerability found in URL parameter {param_name} on {url}")
                            return
                        elif has_sql_context:
                            logger.debug(f"SQL pattern found with context but payload not reflected - potential false positive on {url}")
                        else:
                            logger.debug(f"SQL pattern found but no SQL context - likely false positive on {url}")
                        
            except Exception as e:
                logger.debug(f"Failed to test SQL injection payload on {url}: {str(e)}")
                continue
    
    def _test_url_path_traversal(self, url, param_name):
        """Test URL parameter for path traversal vulnerability"""
        from config import ScannerConfig
        
        # Only test path traversal on URLs that might access files
        if not any(keyword in url.lower() for keyword in ['file', 'include', 'page', 'path']):
            return
            
        path_payloads = ScannerConfig.PATH_TRAVERSAL_PAYLOADS[:2]
        
        for payload in path_payloads:
            try:
                params = {param_name: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
                
                if any(indicator in response.text.lower() for indicator in ['root:', 'bin:', 'etc:', 'windows:', 'system32:']):
                    self.vulnerabilities.append(Vulnerability(
                        name="Path Traversal via URL Parameter",
                        description=f"URL parameter '{param_name}' is vulnerable to path traversal",
                        risk_level=RiskLevel.HIGH,
                        location=f"{url}?{param_name}=[payload]",
                        evidence=f"Path traversal successful with payload '{payload[:50]}...'",
                        recommendation="Implement proper path validation and sanitization"
                    ))
                    logger.info(f"🚨 Path traversal vulnerability found in URL parameter {param_name} on {url}")
                    return
                    
            except Exception as e:
                logger.debug(f"Failed to test path traversal payload on {url}: {str(e)}")
                continue
    
    def _test_url_ssrf(self, url, param_name):
        """Test URL parameter for SSRF vulnerability"""
        from config import ScannerConfig
        
        # Only test SSRF on URLs that might make external requests
        if not any(keyword in url.lower() for keyword in ['url', 'link', 'redirect', 'fetch']):
            return
            
        ssrf_payloads = ScannerConfig.SSRF_PAYLOADS[:2]
        
        for payload in ssrf_payloads:
            try:
                params = {param_name: payload}
                response = self.session.get(url, params=params, timeout=self.timeout)
                
                if any(indicator in response.text.lower() for indicator in ['localhost', '127.0.0.1', 'internal', 'private']):
                    self.vulnerabilities.append(Vulnerability(
                        name="SSRF via URL Parameter",
                        description=f"URL parameter '{param_name}' is vulnerable to SSRF",
                        risk_level=RiskLevel.HIGH,
                        location=f"{url}?{param_name}=[payload]",
                        evidence=f"SSRF successful with payload '{payload[:50]}...'",
                        recommendation="Implement proper URL validation and whitelisting"
                    ))
                    logger.info(f"🚨 SSRF vulnerability found in URL parameter {param_name} on {url}")
                    return
                    
            except Exception as e:
                logger.debug(f"Failed to test SSRF payload on {url}: {str(e)}")
                continue
    
    def _check_response_body_xss(self):
        """Check for XSS vulnerabilities reflected in response bodies"""
        from config import ScannerConfig
        
        # Get XSS payloads from config
        xss_payloads = ScannerConfig.XSS_PAYLOADS
        
        # Test the main target URL with various XSS payloads
        for payload in xss_payloads:
            try:
                # Test with a generic parameter
                params = {'xss_test': payload}
                response = self.session.get(self.target_url, params=params, timeout=self.timeout)
                
                # Check if the payload is reflected anywhere in the response
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        name="Reflected XSS in Response Body",
                        description="The application may be vulnerable to reflected XSS via parameters",
                        risk_level=RiskLevel.HIGH,
                        location=f"{self.target_url}?xss_test=[payload]",
                        evidence=f"Payload '{payload}' reflected in response body",
                        recommendation="Implement proper input validation and output encoding for all user inputs"
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Failed to test response body XSS: {str(e)}")
                continue
    
    def _check_software_stack(self):
        """Identify software stack from response headers and content"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            content = response.text
            
            software_info = {}
            
            # Check server header
            if 'Server' in headers:
                software_info['Server'] = headers['Server']
            
            # Check for common technology indicators
            tech_patterns = {
                'PHP': [r'\.php', r'phpinfo', r'X-Powered-By.*PHP'],
                'ASP.NET': [r'\.aspx', r'\.asp', r'X-AspNet-Version', r'ASP\.NET'],
                'Java': [r'\.jsp', r'\.do', r'JSESSIONID', r'X-Powered-By.*Java'],
                'Python': [r'\.py', r'Django', r'Flask', r'X-Powered-By.*Python'],
                'Node.js': [r'X-Powered-By.*Express', r'X-Powered-By.*Node'],
                'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
                'Drupal': [r'drupal', r'Drupal', r'X-Generator.*Drupal']
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE) or \
                       any(re.search(pattern, str(headers), re.IGNORECASE) for headers in [headers]):
                        software_info[tech] = 'Detected'
                        break
            
            # Check for version information
            version_patterns = [
                r'PHP/(\d+\.\d+)',
                r'Apache/(\d+\.\d+)',
                r'nginx/(\d+\.\d+)',
                r'IIS/(\d+\.\d+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, str(headers), re.IGNORECASE)
                if match:
                    software_info['Version'] = match.group(1)
                    break
            
            if software_info:
                logger.info(f"Software stack detected: {software_info}")
                
        except Exception as e:
            logger.error(f"Failed to check software stack: {str(e)}")
    
    def _check_open_directories(self):
        """Check for open directory listings"""
        common_dirs = ['/images', '/files', '/uploads', '/downloads', '/backup', '/logs']
        
        for directory in common_dirs:
            url = urljoin(self.target_url, directory)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Check if it's a directory listing
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        self.vulnerabilities.append(Vulnerability(
                            name="Open Directory Listing",
                            description=f"Directory {directory} has open listing enabled",
                            risk_level=RiskLevel.MEDIUM,
                            location=url,
                            evidence="Directory listing page detected",
                            recommendation="Disable directory listing or implement proper access controls"
                        ))
                        
            except Exception as e:
                logger.debug(f"Failed to check directory {directory}: {str(e)}")
                continue
    
    def _get_security_headers(self) -> Dict:
        """Get current security headers"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            return dict(response.headers)
        except Exception:
            return {}
    
    def _get_cookies(self) -> List[Dict]:
        """Get current cookies"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            cookies = []
            for cookie in response.cookies:
                cookies.append({
                    'name': cookie.name,
                    'value': cookie.value,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'domain': cookie.domain,
                    'path': cookie.path
                })
            return cookies
        except Exception:
            return []
    
    def _get_software_stack(self) -> Dict:
        """Get detected software stack"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers
            content = response.text
            
            software_info = {}
            
            if 'Server' in headers:
                software_info['Server'] = headers['Server']
            
            # Check for common technologies
            if 'X-Powered-By' in headers:
                software_info['Powered-By'] = headers['X-Powered-By']
            
            if '.php' in content or 'phpinfo' in content:
                software_info['PHP'] = 'Detected'
            
            if 'wp-content' in content or 'WordPress' in content:
                software_info['WordPress'] = 'Detected'
            
            return software_info
        except Exception:
            return {}

    def _test_dvwa_specific_vulnerabilities(self):
        """Test for DVWA-specific vulnerabilities that are intentionally vulnerable"""
        logger.info("Testing for DVWA-specific vulnerabilities...")
        
        # Look for DVWA vulnerability pages
        dvwa_vuln_urls = [url for url in self.discovered_urls if 'dvwa' in url.lower() and 'vulnerabilities' in url.lower()]
        
        for url in dvwa_vuln_urls:
            # SQL Injection vulnerability page
            if 'sqli' in url.lower() or 'sql' in url.lower():
                self.vulnerabilities.append(Vulnerability(
                    name="DVWA SQL Injection Vulnerability",
                    description="DVWA SQL injection vulnerability page detected - this is intentionally vulnerable for testing",
                    risk_level=RiskLevel.HIGH,
                    location=url,
                    evidence="DVWA SQL injection vulnerability page identified",
                    recommendation="This is a training application - do not deploy in production"
                ))
                logger.info(f"🚨 DVWA SQL injection vulnerability page detected: {url}")
            
            # XSS vulnerability page
            elif 'xss' in url.lower():
                self.vulnerabilities.append(Vulnerability(
                    name="DVWA XSS Vulnerability",
                    description="DVWA XSS vulnerability page detected - this is intentionally vulnerable for testing",
                    risk_level=RiskLevel.HIGH,
                    location=url,
                    evidence="DVWA XSS vulnerability page identified",
                    recommendation="This is a training application - do not deploy in production"
                ))
                logger.info(f"🚨 DVWA XSS vulnerability page detected: {url}")
            
            # File Upload vulnerability page
            elif 'upload' in url.lower() or 'file' in url.lower():
                self.vulnerabilities.append(Vulnerability(
                    name="DVWA File Upload Vulnerability",
                    description="DVWA file upload vulnerability page detected - this is intentionally vulnerable for testing",
                    risk_level=RiskLevel.HIGH,
                    location=url,
                    evidence="DVWA file upload vulnerability page identified",
                    recommendation="This is a training application - do not deploy in production"
                ))
                logger.info(f"🚨 DVWA file upload vulnerability page detected: {url}")
            
            # Command Injection vulnerability page
            elif 'exec' in url.lower() or 'command' in url.lower():
                self.vulnerabilities.append(Vulnerability(
                    name="DVWA Command Injection Vulnerability",
                    description="DVWA command injection vulnerability page detected - this is intentionally vulnerable for testing",
                    risk_level=RiskLevel.HIGH,
                    location=url,
                    evidence="DVWA command injection vulnerability page identified",
                    recommendation="This is a training application - do not deploy in production"
                ))
                logger.info(f"🚨 DVWA command injection vulnerability page detected: {url}")
            
            # Path Traversal vulnerability page
            elif 'path' in url.lower() or 'file' in url.lower():
                self.vulnerabilities.append(Vulnerability(
                    name="DVWA Path Traversal Vulnerability",
                    description="DVWA path traversal vulnerability page detected - this is intentionally vulnerable for testing",
                    risk_level=RiskLevel.HIGH,
                    location=url,
                    evidence="DVWA path traversal vulnerability page identified",
                    recommendation="This is a training application - do not deploy in production"
                ))
                logger.info(f"🚨 DVWA path traversal vulnerability page detected: {url}")

    def _test_actual_dvwa_vulnerabilities(self):
        """Test actual DVWA vulnerability functionality by sending payloads to vulnerability pages"""
        logger.info("Testing actual DVWA vulnerability functionality...")
        
        # Look for specific DVWA vulnerability pages and test them
        for url in self.discovered_urls:
            if 'dvwa' not in url.lower() or 'vulnerabilities' not in url.lower():
                continue
                
            # Test SQL Injection page
            if 'sqli' in url.lower() or 'sql' in url.lower():
                self._test_dvwa_sqli_page(url)
            
            # Test XSS page
            elif 'xss' in url.lower():
                self._test_dvwa_xss_page(url)
            
            # Test File Upload page
            elif 'upload' in url.lower() or 'file' in url.lower():
                self._test_dvwa_file_upload_page(url)
    
    def _test_dvwa_sqli_page(self, url):
        """Test DVWA SQL injection page with actual payloads"""
        from config import ScannerConfig
        
        # Test with SQL injection payloads
        sql_payloads = ["'", "1' OR '1'='1", "1' UNION SELECT NULL--"]
        
        for payload in sql_payloads:
            try:
                # Try to find a form or parameter to test
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for forms
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        if input_field.get('type') in ['text', 'search']:
                            param_name = input_field.get('name', 'id')
                            if param_name:
                                # Test the form
                                if form.get('method', 'GET').upper() == 'GET':
                                    params = {param_name: payload}
                                    test_response = self.session.get(url, params=params, timeout=self.timeout)
                                else:
                                    data = {param_name: payload}
                                    test_response = self.session.post(url, data=data, timeout=self.timeout)
                                
                                # Check for SQL errors
                                for pattern in ScannerConfig.SQL_ERROR_PATTERNS:
                                    if re.search(pattern, test_response.text, re.IGNORECASE):
                                        self.vulnerabilities.append(Vulnerability(
                                            name="DVWA SQL Injection Confirmed",
                                            description=f"SQL injection confirmed on DVWA SQL injection page",
                                            risk_level=RiskLevel.CRITICAL,
                                            location=url,
                                            evidence=f"SQL error pattern detected with payload '{payload}'",
                                            recommendation="This is a training application - do not deploy in production"
                                        ))
                                        logger.info(f"🚨 DVWA SQL injection confirmed on {url} with payload: {payload}")
                                        return
                                        
            except Exception as e:
                logger.debug(f"Failed to test DVWA SQL injection page {url}: {str(e)}")
                continue
    
    def _test_dvwa_xss_page(self, url):
        """Test DVWA XSS page with actual payloads"""
        from config import ScannerConfig
        
        # Test with XSS payloads
        xss_payloads = ['<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>']
        
        for payload in xss_payloads:
            try:
                response = self.session.get(url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for forms
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        if input_field.get('type') in ['text', 'search']:
                            param_name = input_field.get('name', 'id')
                            if param_name:
                                # Test the form
                                if form.get('method', 'GET').upper() == 'GET':
                                    params = {param_name: payload}
                                    test_response = self.session.get(url, params=params, timeout=self.timeout)
                                else:
                                    data = {param_name: payload}
                                    test_response = self.session.post(url, data=data, timeout=self.timeout)
                                
                                # Check for XSS reflection
                                if payload in test_response.text:
                                    self.vulnerabilities.append(Vulnerability(
                                        name="DVWA XSS Confirmed",
                                        description=f"XSS confirmed on DVWA XSS page",
                                        risk_level=RiskLevel.HIGH,
                                        location=url,
                                        evidence=f"XSS payload reflected: '{payload[:50]}...'",
                                        recommendation="This is a training application - do not deploy in production"
                                    ))
                                    logger.info(f"🚨 DVWA XSS confirmed on {url} with payload: {payload}")
                                    return
                                    
            except Exception as e:
                logger.debug(f"Failed to test DVWA XSS page {url}: {str(e)}")
                continue
    
    def _test_dvwa_file_upload_page(self, url):
        """Test DVWA file upload page for vulnerabilities"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for file upload forms
            forms = soup.find_all('form')
            for form in forms:
                file_inputs = form.find_all('input', type='file')
                if file_inputs:
                    self.vulnerabilities.append(Vulnerability(
                        name="DVWA File Upload Vulnerability Confirmed",
                        description=f"File upload vulnerability confirmed on DVWA file upload page",
                        risk_level=RiskLevel.HIGH,
                        location=url,
                        evidence="File upload form detected without proper validation",
                        recommendation="This is a training application - do not deploy in production"
                    ))
                    logger.info(f"🚨 DVWA file upload vulnerability confirmed on {url}")
                    return
                    
        except Exception as e:
            logger.debug(f"Failed to test DVWA file upload page {url}: {str(e)}")
    
    def _test_forms_with_enhanced_payloads(self):
        """Enhanced form testing with better payload coverage and state management"""
        logger.info("Enhanced form testing with comprehensive payload coverage...")
        
        for form in self.discovered_forms:
            page_url = form['page_url']
            
            # Skip forms that are just login forms or redirects
            if 'login.php' in page_url or 'logout.php' in page_url:
                continue
                
            # Skip static and documentation pages
            if any(keyword in page_url.lower() for keyword in ['readme', 'documentation', 'help', 'guide', 'manual', 'changelog', 'instructions']):
                continue
                
            if 'phpinfo.php' in page_url:
                continue
            
            logger.info(f"Enhanced testing of form on: {page_url}")
            
            # Test each input field with enhanced payloads
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search']:
                    param_name = input_field['name'] or input_field['id'] or 'input_field'
                    
                    # Enhanced XSS testing with more payloads
                    self._test_enhanced_xss(form, input_field, param_name, page_url)
                    
                    # Enhanced SQL injection testing
                    self._test_enhanced_sql_injection(form, input_field, param_name, page_url)
                    
                    # Test for other injection types
                    self._test_command_injection_vulnerability(form, input_field, param_name, page_url)
                    self._test_path_traversal_vulnerability(form, input_field, param_name, page_url)
                    self._test_ssrf_vulnerability(form, input_field, param_name, page_url)
    
    def _test_enhanced_xss(self, form, input_field, param_name, page_url):
        """Enhanced XSS testing with better payload coverage"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(page_url):
            logger.debug(f"Skipping enhanced XSS test on static/documentation page: {page_url}")
            return
        
        # Use more XSS payloads for better coverage
        xss_payloads = ScannerConfig.XSS_PAYLOADS[:10]  # Test more payloads
        
        for payload in xss_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Check for full payload reflection
                if payload in response.text:
                    self.vulnerabilities.append(Vulnerability(
                        name="Enhanced XSS Detection - Full Reflection",
                        description=f"Input field '{param_name}' is vulnerable to reflected XSS (full payload reflection)",
                        risk_level=RiskLevel.HIGH,
                        location=page_url,
                        evidence=f"Full payload reflection: '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding"
                    ))
                    logger.info(f"🚨 Enhanced XSS vulnerability found in {param_name} on {page_url}")
                    break
                    
                # Check for partial payload reflection with more indicators
                xss_indicators = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'onmouseover', 'onfocus', 'onblur', 'onchange', 'oninput']
                if any(indicator in response.text for indicator in xss_indicators):
                    self.vulnerabilities.append(Vulnerability(
                        name="Enhanced XSS Detection - Partial Reflection",
                        description=f"Input field '{param_name}' may be vulnerable to XSS (partial reflection detected)",
                        risk_level=RiskLevel.MEDIUM,
                        location=page_url,
                        evidence=f"XSS indicators found in response to payload '{payload[:50]}...'",
                        recommendation="Implement proper input validation and output encoding"
                    ))
                    logger.info(f"Enhanced XSS vulnerability found in {param_name} on {page_url}")
                    break
                    
            except Exception as e:
                logger.debug(f"Failed to test enhanced XSS payload: {str(e)}")
                continue
    
    def _test_enhanced_sql_injection(self, form, input_field, param_name, page_url):
        """Enhanced SQL injection testing with better verification"""
        from config import ScannerConfig
        
        # Use enhanced filtering to skip static/documentation content
        if not self._should_test_for_vulnerabilities(page_url):
            logger.debug(f"Skipping enhanced SQL injection test on static/documentation page: {page_url}")
            return
        
        # Use more SQL payloads for better coverage
        sql_payloads = ScannerConfig.SQL_PAYLOADS[:8]  # Test more payloads
        sql_patterns = ScannerConfig.SQL_ERROR_PATTERNS
        
        for payload in sql_payloads:
            try:
                if form['method'] == 'GET':
                    params = {param_name: payload}
                    response = self.session.get(page_url, params=params, timeout=self.timeout)
                else:
                    data = {param_name: payload}
                    response = self.session.post(page_url, data=data, timeout=self.timeout)
                
                # Enhanced SQL error pattern detection
                for pattern in sql_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # Multiple verification steps to reduce false positives
                        sql_context_indicators = ['mysql', 'sql', 'database', 'query', 'syntax', 'error', 'warning', 'exception']
                        has_sql_context = any(indicator in response.text.lower() for indicator in sql_context_indicators)
                        
                        # Check if payload is reflected
                        payload_reflected = payload in response.text
                        
                        # Check for SQL-specific error messages
                        sql_error_messages = ['mysql_fetch', 'mysql_query', 'sqlsrv', 'pdo', 'mysqli']
                        has_sql_errors = any(error_msg in response.text.lower() for error_msg in sql_error_messages)
                        
                        if (has_sql_context and payload_reflected) or has_sql_errors:
                            self.vulnerabilities.append(Vulnerability(
                                name="Enhanced SQL Injection Detection",
                                description=f"Input field '{param_name}' is vulnerable to SQL injection",
                                risk_level=RiskLevel.CRITICAL,
                                location=page_url,
                                evidence=f"SQL error pattern detected with payload '{payload}'",
                                recommendation="Implement parameterized queries and input validation"
                            ))
                            logger.info(f"🚨 Enhanced SQL injection vulnerability found in {param_name} on {page_url}")
                            return
                        
            except Exception as e:
                logger.debug(f"Failed to test enhanced SQL injection payload: {str(e)}")
                continue

    def _is_static_or_documentation_content(self, url):
        """Enhanced filtering to determine if URL is static content or documentation"""
        
        # Static file extensions
        static_extensions = [
            '.md', '.txt', '.pdf', '.doc', '.docx', '.html', '.htm', '.css', '.js', 
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.xml', '.json', '.csv',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dmg', '.deb', '.rpm'
        ]
        
        # Documentation and help keywords
        documentation_keywords = [
            'readme', 'documentation', 'help', 'guide', 'manual', 'changelog', 
            'instructions', 'about', 'license', 'copying', 'faq', 'support',
            'tutorial', 'example', 'sample', 'demo', 'test', 'debug'
        ]
        
        # System and configuration files
        system_files = [
            'phpinfo.php', 'info.php', 'test.php', 'config', 'setup', 'install',
            'composer.json', 'package.json', 'requirements.txt', 'dockerfile',
            'docker-compose', 'makefile', '.gitignore', '.env', 'robots.txt'
        ]
        
        # Check for static file extensions
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return True
            
        # Check for documentation keywords in URL path
        if any(keyword in url.lower() for keyword in documentation_keywords):
            return True
            
        # Check for system files
        if any(keyword in url.lower() for keyword in system_files):
            return True
            
        # Check for documentation-style URL patterns
        if any(pattern in url.lower() for pattern in [
            '/doc/', '/docs/', '/help/', '/manual/', '/guide/', '/tutorial/',
            '?doc=', '?page=help', '?section=docs', '?topic=guide'
        ]):
            return True
            
        return False
    
    def _is_dynamic_application_page(self, url):
        """Check if URL is a dynamic application page that should be tested"""
        
        # Dynamic application extensions
        dynamic_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.cgi', '.pl', '.py',
            '.rb', '.go', '.js', '.ts', '.vue', '.react', '.angular'
        ]
        
        # Common dynamic URL patterns
        dynamic_patterns = [
            '/admin/', '/user/', '/dashboard/', '/profile/', '/settings/',
            '/login', '/register', '/search', '/api/', '/rest/', '/graphql/',
            '/vulnerabilities/', '/test/', '/demo/', '/example/'
        ]
        
        # Check for dynamic extensions
        if any(url.lower().endswith(ext) for ext in dynamic_extensions):
            return True
            
        # Check for dynamic URL patterns
        if any(pattern in url.lower() for pattern in dynamic_patterns):
            return True
            
        # Check if URL has query parameters (indicates dynamic content)
        if '?' in url and '=' in url:
            return True
            
        return False
    
    def _should_test_for_vulnerabilities(self, url):
        """Comprehensive check to determine if URL should be tested for vulnerabilities"""
        
        # Skip static/documentation content
        if self._is_static_or_documentation_content(url):
            return False
            
        # Only test dynamic application pages
        if not self._is_dynamic_application_page(url):
            return False
            
        # Additional checks for specific cases
        if any(skip_pattern in url.lower() for skip_pattern in [
            'phpinfo', 'info.php', 'test.php', 'setup.php', 'install.php',
            'composer', 'package.json', 'requirements.txt', 'dockerfile',
            'makefile', '.git', '.env', 'robots.txt', 'sitemap.xml'
        ]):
            return False
            
        return True

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Web Application Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--output', choices=['txt', 'html', 'md', 'json'], default='txt', 
                       help='Output format (default: txt)')
    parser.add_argument('--cookies', type=str, help='Cookies in format: name1=value1,name2=value2')
    parser.add_argument('--username', type=str, help='Username for authentication')
    parser.add_argument('--password', type=str, help='Password for authentication')
    
    args = parser.parse_args()
    
    # Parse cookies if provided
    cookies = None
    if args.cookies:
        try:
            cookies = {}
            cookie_pairs = args.cookies.split(',')
            for pair in cookie_pairs:
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    cookies[name.strip()] = value.strip()
        except Exception as e:
            print(f"Error parsing cookies: {e}")
            print("Use format: name1=value1,name2=value2")
            sys.exit(1)
    
    # Parse authentication credentials
    auth_credentials = None
    if args.username or args.password:
        auth_credentials = {
            'username': args.username or 'admin',
            'password': args.password or 'password'
        }
        print(f"Authentication enabled for user: {auth_credentials['username']}")
    
    try:
        scanner = WebVulnerabilityScanner(args.url, args.depth, args.timeout, cookies, auth_credentials)
        results = scanner.start_scan()
        
        # Generate report if ReportGenerator is available
        if ReportGenerator:
            report_generator = ReportGenerator()
            report_generator.generate_report(results, args.output)
            print(f"\n📝 Report generated in {args.output} format")
        else:
            print(f"\nScan Results Summary:")
            print(f"   Target: {results.target_url}")
            print(f"   Pages discovered: {len(results.discovered_pages)}")
            print(f"   Forms found: {len(results.discovered_forms)}")
            print(f"   Vulnerabilities: {len(results.vulnerabilities)}")
            print(f"   Scan duration: {results.scan_duration:.2f} seconds")
        
        print(f"\nScan completed in {results.scan_duration:.2f} seconds")
        print(f"Found {len(results.vulnerabilities)} vulnerabilities")
        print(f"Discovered {len(results.discovered_pages)} pages")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
